package internal

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-hover/pkg/hoverclient"
	"github.com/GoCodeAlone/workflow/interfaces"
	pb "github.com/GoCodeAlone/workflow/plugin/external/proto"
)

func TestHoverIaCServer_Name(t *testing.T) {
	srv := NewIaCServer()
	resp, err := srv.Name(context.Background(), &pb.NameRequest{})
	if err != nil {
		t.Fatalf("Name: %v", err)
	}
	if resp.GetName() != "hover" {
		t.Errorf("Name = %q want %q", resp.GetName(), "hover")
	}
}

func TestHoverIaCServer_Version(t *testing.T) {
	srv := NewIaCServer()
	resp, err := srv.Version(context.Background(), &pb.VersionRequest{})
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if resp.GetVersion() == "" {
		t.Error("Version returned empty string")
	}
}

func TestHoverIaCServer_Capabilities(t *testing.T) {
	srv := NewIaCServer()
	resp, err := srv.Capabilities(context.Background(), &pb.CapabilitiesRequest{})
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	if resp.GetComputePlanVersion() != "v2" {
		t.Errorf("ComputePlanVersion = %q want %q", resp.GetComputePlanVersion(), "v2")
	}
	caps := resp.GetCapabilities()
	if len(caps) != 2 {
		t.Fatalf("expected 2 capabilities, got %d", len(caps))
	}
	gotTypes := map[string]bool{}
	for _, c := range caps {
		gotTypes[c.GetResourceType()] = true
	}
	for _, want := range []string{"infra.dns", "infra.dns_delegation"} {
		if !gotTypes[want] {
			t.Errorf("capability %q missing", want)
		}
	}
}

func TestHoverIaCServer_FinalizeApply_NoOp(t *testing.T) {
	srv := NewIaCServer()
	resp, err := srv.FinalizeApply(context.Background(), &pb.FinalizeApplyRequest{})
	if err != nil {
		t.Fatalf("FinalizeApply: %v", err)
	}
	if len(resp.GetErrors()) != 0 {
		t.Errorf("expected no errors, got %v", resp.GetErrors())
	}
}

func TestHoverIaCServer_Initialize_MissingUsername(t *testing.T) {
	srv := NewIaCServer()
	_, err := srv.Initialize(context.Background(), &pb.InitializeRequest{
		ConfigJson: []byte(`{"password": "pw"}`),
	})
	if err == nil {
		t.Fatal("expected error for missing username")
	}
}

func TestHoverIaCServer_Initialize_MissingPassword(t *testing.T) {
	srv := NewIaCServer()
	_, err := srv.Initialize(context.Background(), &pb.InitializeRequest{
		ConfigJson: []byte(`{"username": "user"}`),
	})
	if err == nil {
		t.Fatal("expected error for missing password")
	}
}

func TestHoverIaCServer_Initialize_InvalidTOTPSecret(t *testing.T) {
	srv := NewIaCServer()
	_, err := srv.Initialize(context.Background(), &pb.InitializeRequest{
		ConfigJson: []byte(`{"username": "u", "password": "p", "totp_secret": "!not-valid-base32!"}`),
	})
	if err == nil {
		t.Fatal("expected error for invalid TOTP secret")
	}
}

func TestHoverIaCServer_Plan_EmptyDesired(t *testing.T) {
	// Plan with an empty desired list is valid — returns a plan with no actions.
	srv := NewIaCServer()
	resp, err := srv.Plan(context.Background(), &pb.PlanRequest{})
	if err != nil {
		t.Fatalf("Plan with empty desired: %v", err)
	}
	if resp.GetPlan() != nil && len(resp.GetPlan().GetActions()) != 0 {
		t.Errorf("expected no actions for empty desired, got %d", len(resp.GetPlan().GetActions()))
	}
}

func TestHoverIaCServer_ResourceDriverReadAndDiff(t *testing.T) {
	driver := &iacServerFakeDriver{
		readOut: &interfaces.ResourceOutput{
			Name:       "delegation",
			Type:       "infra.dns_delegation",
			ProviderID: "gocodealone.tech",
			Outputs:    map[string]any{"nameservers": []any{"ns1.digitalocean.com"}},
			Status:     "active",
		},
		diff: &interfaces.DiffResult{NeedsUpdate: false},
	}
	srv := &hoverIaCServer{
		provider: &HoverProvider{drivers: map[string]interfaces.ResourceDriver{
			"infra.dns_delegation": driver,
		}},
	}

	readResp, err := srv.Read(context.Background(), &pb.ResourceReadRequest{
		ResourceType: "infra.dns_delegation",
		Ref:          &pb.ResourceRef{Name: "delegation", Type: "infra.dns_delegation", ProviderId: "gocodealone.tech"},
	})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if readResp.GetOutput().GetProviderId() != "gocodealone.tech" {
		t.Fatalf("Read ProviderID = %q, want gocodealone.tech", readResp.GetOutput().GetProviderId())
	}
	if driver.readRef.ProviderID != "gocodealone.tech" {
		t.Fatalf("driver read ref = %+v, want provider id gocodealone.tech", driver.readRef)
	}

	diffResp, err := srv.Diff(context.Background(), &pb.ResourceDiffRequest{
		ResourceType: "infra.dns_delegation",
		Desired: &pb.ResourceSpec{
			Name:       "delegation",
			Type:       "infra.dns_delegation",
			ConfigJson: []byte(`{"domain":"gocodealone.tech"}`),
		},
		Current: readResp.GetOutput(),
	})
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if diffResp.GetResult().GetNeedsUpdate() {
		t.Fatal("Diff NeedsUpdate = true, want false")
	}
	if driver.diffDesired.Config["domain"] != "gocodealone.tech" {
		t.Fatalf("driver diff desired config = %+v", driver.diffDesired.Config)
	}
}

func TestHoverIaCServer_Import_ReturnsResourceState(t *testing.T) {
	driver := &iacServerFakeDriver{
		readOut: &interfaces.ResourceOutput{
			Name:       "example.com",
			Type:       "infra.dns",
			ProviderID: "example.com",
			Outputs: map[string]any{
				"domain": "example.com",
				"records": []any{
					map[string]any{"type": "MX", "name": "@", "content": "mail.protonmail.ch", "ttl": 300},
				},
			},
			Status: "active",
		},
	}
	srv := &hoverIaCServer{
		provider: &HoverProvider{drivers: map[string]interfaces.ResourceDriver{
			"infra.dns": driver,
		}},
	}

	resp, err := srv.Import(context.Background(), &pb.ImportRequest{ProviderId: "example.com"})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	state := resp.GetState()
	if state == nil {
		t.Fatal("Import state is nil")
	}
	if state.GetProvider() != "hover" {
		t.Fatalf("Provider = %q, want hover", state.GetProvider())
	}
	if state.GetType() != "infra.dns" {
		t.Fatalf("Type = %q, want infra.dns", state.GetType())
	}
	if state.GetProviderId() != "example.com" {
		t.Fatalf("ProviderId = %q, want example.com", state.GetProviderId())
	}
	if state.GetAppliedConfigSource() != "adoption" {
		t.Fatalf("AppliedConfigSource = %q, want adoption", state.GetAppliedConfigSource())
	}
	outputs, err := unmarshalJSONMap(state.GetOutputsJson())
	if err != nil {
		t.Fatalf("outputs JSON: %v", err)
	}
	if outputs["domain"] != "example.com" {
		t.Fatalf("outputs.domain = %v, want example.com", outputs["domain"])
	}
	if driver.readRef != (interfaces.ResourceRef{Name: "example.com", Type: "infra.dns", ProviderID: "example.com"}) {
		t.Fatalf("driver read ref = %+v, want provider-id import ref", driver.readRef)
	}
}

func TestHoverIaCServer_Destroy_EmptyRefs(t *testing.T) {
	srv := NewIaCServer()
	// Destroy with zero refs is a no-op regardless of initialization state.
	resp, err := srv.Destroy(context.Background(), &pb.DestroyRequest{})
	if err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if len(resp.GetResult().GetDestroyed()) != 0 {
		t.Errorf("expected no destroyed, got %v", resp.GetResult().GetDestroyed())
	}
}

type iacServerFakeDriver struct {
	readOut     *interfaces.ResourceOutput
	readRef     interfaces.ResourceRef
	diff        *interfaces.DiffResult
	diffDesired interfaces.ResourceSpec
	diffCurrent *interfaces.ResourceOutput
}

func (d *iacServerFakeDriver) Create(_ context.Context, spec interfaces.ResourceSpec) (*interfaces.ResourceOutput, error) {
	return &interfaces.ResourceOutput{Name: spec.Name, Type: spec.Type, ProviderID: spec.Name}, nil
}

func (d *iacServerFakeDriver) Read(_ context.Context, ref interfaces.ResourceRef) (*interfaces.ResourceOutput, error) {
	d.readRef = ref
	return d.readOut, nil
}

func (d *iacServerFakeDriver) Update(_ context.Context, ref interfaces.ResourceRef, spec interfaces.ResourceSpec) (*interfaces.ResourceOutput, error) {
	return &interfaces.ResourceOutput{Name: spec.Name, Type: spec.Type, ProviderID: ref.ProviderID}, nil
}

func (d *iacServerFakeDriver) Delete(_ context.Context, _ interfaces.ResourceRef) error { return nil }

func (d *iacServerFakeDriver) Diff(_ context.Context, desired interfaces.ResourceSpec, current *interfaces.ResourceOutput) (*interfaces.DiffResult, error) {
	d.diffDesired = desired
	d.diffCurrent = current
	return d.diff, nil
}

func (d *iacServerFakeDriver) HealthCheck(_ context.Context, _ interfaces.ResourceRef) (*interfaces.HealthResult, error) {
	return &interfaces.HealthResult{Healthy: true}, nil
}

func (d *iacServerFakeDriver) Scale(_ context.Context, ref interfaces.ResourceRef, _ int) (*interfaces.ResourceOutput, error) {
	return &interfaces.ResourceOutput{Name: ref.Name, Type: ref.Type, ProviderID: ref.ProviderID}, nil
}

func (d *iacServerFakeDriver) SensitiveKeys() []string { return nil }

// ── EnumerateAll gRPC coverage ─────────────────────────────────────────────

// TestHoverIaCServer_EnumerateAll_DNS exercises the typed gRPC surface
// (hoverIaCServer.EnumerateAll). The SDK auto-registers this service at
// plugin startup because hoverIaCServer embeds the Unimplemented*Enumerator
// stub and overrides EnumerateAll. This test confirms the proto<->Go
// marshalling round-trips zone + domain_id outputs.
func TestHoverIaCServer_EnumerateAll_DNS(t *testing.T) {
	srv := &hoverIaCServer{
		provider: &HoverProvider{
			domains: &fakeHoverClient{
				domains: []hoverclient.Domain{
					{ID: "dom-1", Name: "alpha.test"},
					{ID: "dom-2", Name: "beta.test"},
				},
			},
		},
	}
	resp, err := srv.EnumerateAll(context.Background(), &pb.EnumerateAllRequest{ResourceType: "infra.dns"})
	if err != nil {
		t.Fatalf("EnumerateAll: %v", err)
	}
	if len(resp.GetOutputs()) != 2 {
		t.Fatalf("want 2 outputs; got %d", len(resp.GetOutputs()))
	}
	first := resp.GetOutputs()[0]
	if first.GetProviderId() != "alpha.test" {
		t.Errorf("providerID = %q; want alpha.test", first.GetProviderId())
	}
	if first.GetType() != "infra.dns" {
		t.Errorf("type = %q; want infra.dns", first.GetType())
	}
	var outputs map[string]any
	if err := json.Unmarshal(first.GetOutputsJson(), &outputs); err != nil {
		t.Fatalf("unmarshal outputs: %v", err)
	}
	if outputs["zone"] != "alpha.test" || outputs["domain_id"] != "dom-1" {
		t.Errorf("outputs = %#v", outputs)
	}
}
