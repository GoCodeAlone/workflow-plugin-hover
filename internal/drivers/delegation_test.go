package drivers

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-hover/internal/hover"
	"github.com/GoCodeAlone/workflow/interfaces"
)

type fakeDelegationClient struct {
	getResult *hover.DomainDelegation
	getErr    error
	setErr    error
	lastSetNS []string
}

func (f *fakeDelegationClient) GetDomainDelegation(_ context.Context, _ string) (*hover.DomainDelegation, error) {
	return f.getResult, f.getErr
}

func (f *fakeDelegationClient) SetNameservers(_ context.Context, _ string, ns []string) error {
	f.lastSetNS = append([]string(nil), ns...)
	return f.setErr
}

func TestDelegationDriver_TypeAndProviderIDFormat(t *testing.T) {
	d := NewDelegationDriverWithClient(&fakeDelegationClient{})
	if got := d.Type(); got != "infra.dns_delegation" {
		t.Errorf("Type() = %q, want infra.dns_delegation", got)
	}
	if got := d.ProviderIDFormat(); got != interfaces.IDFormatDomainName {
		t.Errorf("ProviderIDFormat() = %v, want IDFormatDomainName", got)
	}
	if d.SensitiveKeys() != nil {
		t.Errorf("SensitiveKeys() = %v, want nil", d.SensitiveKeys())
	}
}

func TestDelegationDriver_Create_CallsSetNameservers(t *testing.T) {
	fc := &fakeDelegationClient{}
	d := NewDelegationDriverWithClient(fc)
	spec := interfaces.ResourceSpec{
		Name: "example.com",
		Type: "infra.dns_delegation",
		Config: map[string]any{
			"domain":      "example.com",
			"nameservers": []any{"ns1.do.com", "ns2.do.com", "ns3.do.com"},
		},
	}
	out, err := d.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if fc.lastSetNS == nil || len(fc.lastSetNS) != 3 {
		t.Errorf("client.SetNameservers not called with 3 NS; got %v", fc.lastSetNS)
	}
	if out.ProviderID != "example.com" {
		t.Errorf("ProviderID = %q", out.ProviderID)
	}
	// Outputs.nameservers MUST be []any, not []string (structpb-safe).
	nsRaw, ok := out.Outputs["nameservers"]
	if !ok {
		t.Fatal("Outputs.nameservers missing")
	}
	nsAny, ok := nsRaw.([]any)
	if !ok {
		t.Fatalf("Outputs.nameservers = %T, want []any", nsRaw)
	}
	if len(nsAny) != 3 {
		t.Errorf("Outputs.nameservers len = %d, want 3", len(nsAny))
	}
	// previous_nameservers NOT in Outputs for v0.2.0 (no state channel).
	if _, present := out.Outputs["previous_nameservers"]; present {
		t.Errorf("v0.2.0 Outputs should not contain previous_nameservers")
	}
}

func TestDelegationDriver_Create_MissingDomain_Rejected(t *testing.T) {
	d := NewDelegationDriverWithClient(&fakeDelegationClient{})
	spec := interfaces.ResourceSpec{
		Type: "infra.dns_delegation",
		Config: map[string]any{
			"nameservers": []any{"a.com", "b.com"},
		},
	}
	if _, err := d.Create(context.Background(), spec); err == nil {
		t.Fatal("expected error for missing domain")
	}
}

func TestDelegationDriver_Create_MissingNameservers_Rejected(t *testing.T) {
	d := NewDelegationDriverWithClient(&fakeDelegationClient{})
	spec := interfaces.ResourceSpec{
		Name:   "example.com",
		Type:   "infra.dns_delegation",
		Config: map[string]any{"domain": "example.com"},
	}
	if _, err := d.Create(context.Background(), spec); err == nil {
		t.Fatal("expected error for missing nameservers")
	}
}

func TestDelegationDriver_Create_DuplicateNameservers_Rejected(t *testing.T) {
	d := NewDelegationDriverWithClient(&fakeDelegationClient{})
	spec := interfaces.ResourceSpec{
		Name: "example.com",
		Type: "infra.dns_delegation",
		Config: map[string]any{
			"domain":      "example.com",
			"nameservers": []any{"a.com", "a.com"},
		},
	}
	if _, err := d.Create(context.Background(), spec); err == nil {
		t.Fatal("expected error for duplicate nameservers")
	}
}

func TestDelegationDriver_Read_HappyPath(t *testing.T) {
	fc := &fakeDelegationClient{
		getResult: &hover.DomainDelegation{
			ID:          "domain-example.com",
			Name:        "example.com",
			Nameservers: []string{"ns1.do.com", "ns2.do.com"},
		},
	}
	d := NewDelegationDriverWithClient(fc)
	out, err := d.Read(context.Background(), interfaces.ResourceRef{Name: "example.com", ProviderID: "example.com"})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if out.ProviderID != "example.com" {
		t.Errorf("ProviderID = %q", out.ProviderID)
	}
	ns, _ := out.Outputs["nameservers"].([]any)
	if len(ns) != 2 {
		t.Errorf("nameservers len = %d", len(ns))
	}
}

func TestDelegationDriver_Read_PropagatesError(t *testing.T) {
	fc := &fakeDelegationClient{getErr: errors.New("API down")}
	d := NewDelegationDriverWithClient(fc)
	_, err := d.Read(context.Background(), interfaces.ResourceRef{Name: "x.com", ProviderID: "x.com"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDelegationDriver_Update_HappyPath(t *testing.T) {
	fc := &fakeDelegationClient{
		getResult: &hover.DomainDelegation{
			ID: "domain-example.com", Name: "example.com",
			Nameservers: []string{"ns1.do.com", "ns2.do.com"},
		},
	}
	d := NewDelegationDriverWithClient(fc)
	ref := interfaces.ResourceRef{Name: "example.com", Type: "infra.dns_delegation", ProviderID: "example.com"}
	spec := interfaces.ResourceSpec{
		Name: "example.com", Type: "infra.dns_delegation",
		Config: map[string]any{
			"domain":      "example.com",
			"nameservers": []any{"ns3.do.com", "ns4.do.com"},
		},
	}
	out, err := d.Update(context.Background(), ref, spec)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if fc.lastSetNS[0] != "ns3.do.com" {
		t.Errorf("first NS = %q", fc.lastSetNS[0])
	}
	// Defend the structpb-safe invariant on the Update path too:
	// Outputs["nameservers"] MUST be []any, not []string (would
	// reject structpb.NewStruct at the gRPC boundary).
	nsRaw, ok := out.Outputs["nameservers"]
	if !ok {
		t.Fatal("Update Outputs.nameservers missing")
	}
	if _, ok := nsRaw.([]any); !ok {
		t.Fatalf("Update Outputs.nameservers = %T, want []any", nsRaw)
	}
}

func TestDelegationDriver_Update_DomainRenameRejected(t *testing.T) {
	d := NewDelegationDriverWithClient(&fakeDelegationClient{})
	ref := interfaces.ResourceRef{Name: "old.com", ProviderID: "old.com"}
	spec := interfaces.ResourceSpec{
		Name: "new.com", Type: "infra.dns_delegation",
		Config: map[string]any{
			"domain":      "new.com",
			"nameservers": []any{"a.com", "b.com"},
		},
	}
	if _, err := d.Update(context.Background(), ref, spec); err == nil {
		t.Fatal("expected error rejecting domain rename")
	}
}

func TestDelegationDriver_Delete_ResetsToHoverDefaults(t *testing.T) {
	// v0.2.0 ships fallback-only Delete: ResourceRef has no state
	// channel (verified: workflow/interfaces/iac_provider.go:183-187
	// defines ResourceRef as {Name, Type, ProviderID}). Restore from
	// stashed previous_nameservers is a v0.3.0 follow-up requiring
	// an interfaces change.
	fc := &fakeDelegationClient{}
	d := NewDelegationDriverWithClient(fc)
	ref := interfaces.ResourceRef{Name: "example.com", ProviderID: "example.com"}
	if err := d.Delete(context.Background(), ref); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(fc.lastSetNS) != 2 || fc.lastSetNS[0] != "ns1.hover.com" || fc.lastSetNS[1] != "ns2.hover.com" {
		t.Errorf("Delete set NS = %v, want [ns1.hover.com ns2.hover.com]", fc.lastSetNS)
	}
}

func TestDelegationDriver_Diff_NilCurrent(t *testing.T) {
	d := NewDelegationDriverWithClient(&fakeDelegationClient{})
	spec := interfaces.ResourceSpec{
		Name: "example.com", Type: "infra.dns_delegation",
		Config: map[string]any{
			"domain":      "example.com",
			"nameservers": []any{"a.com", "b.com"},
		},
	}
	res, err := d.Diff(context.Background(), spec, nil)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if !res.NeedsUpdate {
		t.Error("expected NeedsUpdate=true for nil current")
	}
}

func TestDelegationDriver_Diff_UpToDate_OrderIndependent(t *testing.T) {
	d := NewDelegationDriverWithClient(&fakeDelegationClient{})
	spec := interfaces.ResourceSpec{
		Name: "example.com", Type: "infra.dns_delegation",
		Config: map[string]any{
			"domain":      "example.com",
			"nameservers": []any{"a.com", "b.com", "c.com"},
		},
	}
	current := &interfaces.ResourceOutput{
		ProviderID: "example.com",
		Outputs: map[string]any{
			"domain":      "example.com",
			"nameservers": []any{"c.com", "a.com", "b.com"}, // reversed
		},
	}
	res, err := d.Diff(context.Background(), spec, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if res.NeedsUpdate {
		t.Error("expected NeedsUpdate=false for same multiset")
	}
}

func TestDelegationDriver_Diff_Changed(t *testing.T) {
	d := NewDelegationDriverWithClient(&fakeDelegationClient{})
	spec := interfaces.ResourceSpec{
		Name: "example.com", Type: "infra.dns_delegation",
		Config: map[string]any{
			"domain":      "example.com",
			"nameservers": []any{"new.com", "b.com"},
		},
	}
	current := &interfaces.ResourceOutput{
		ProviderID: "example.com",
		Outputs: map[string]any{
			"domain":      "example.com",
			"nameservers": []any{"a.com", "b.com"},
		},
	}
	res, err := d.Diff(context.Background(), spec, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if !res.NeedsUpdate {
		t.Error("expected NeedsUpdate=true")
	}
}

func TestDelegationDriver_Diff_DomainChange_NeedsReplace(t *testing.T) {
	d := NewDelegationDriverWithClient(&fakeDelegationClient{})
	spec := interfaces.ResourceSpec{
		Name: "new.com", Type: "infra.dns_delegation",
		Config: map[string]any{
			"domain":      "new.com",
			"nameservers": []any{"a.com", "b.com"},
		},
	}
	current := &interfaces.ResourceOutput{ProviderID: "old.com"}
	res, err := d.Diff(context.Background(), spec, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if !res.NeedsReplace {
		t.Error("expected NeedsReplace=true on domain change")
	}
	if len(res.Changes) != 1 || res.Changes[0].Path != "domain" || !res.Changes[0].ForceNew {
		t.Errorf("expected ForceNew domain change, got %+v", res.Changes)
	}
}

func TestDelegationDriver_HealthCheck_Healthy(t *testing.T) {
	fc := &fakeDelegationClient{
		getResult: &hover.DomainDelegation{
			ID: "domain-example.com", Name: "example.com",
			Nameservers: []string{"a.com", "b.com"},
		},
	}
	d := NewDelegationDriverWithClient(fc)
	res, err := d.HealthCheck(context.Background(), interfaces.ResourceRef{Name: "example.com", ProviderID: "example.com"})
	if err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}
	if !res.Healthy {
		t.Errorf("Healthy = false, want true")
	}
}

func TestDelegationDriver_HealthCheck_Unhealthy(t *testing.T) {
	fc := &fakeDelegationClient{getErr: errors.New("boom")}
	d := NewDelegationDriverWithClient(fc)
	res, err := d.HealthCheck(context.Background(), interfaces.ResourceRef{Name: "example.com", ProviderID: "example.com"})
	if err != nil {
		t.Fatalf("HealthCheck should not return err; got %v", err)
	}
	if res.Healthy {
		t.Error("Healthy = true, want false")
	}
}

func TestDelegationDriver_Scale_NotSupported(t *testing.T) {
	d := NewDelegationDriverWithClient(&fakeDelegationClient{})
	_, err := d.Scale(context.Background(), interfaces.ResourceRef{Name: "x"}, 3)
	if err == nil {
		t.Fatal("expected error from Scale")
	}
}

func TestDelegationDriver_CtxCanceled_AllMethods(t *testing.T) {
	d := NewDelegationDriverWithClient(&fakeDelegationClient{})
	ref := interfaces.ResourceRef{Name: "example.com", ProviderID: "example.com"}
	spec := interfaces.ResourceSpec{
		Name: "example.com", Type: "infra.dns_delegation",
		Config: map[string]any{
			"domain":      "example.com",
			"nameservers": []any{"a.com", "b.com"},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.Create(ctx, spec); err == nil {
		t.Error("Create: expected error for canceled ctx")
	}
	if _, err := d.Read(ctx, ref); err == nil {
		t.Error("Read: expected error for canceled ctx")
	}
	if _, err := d.Update(ctx, ref, spec); err == nil {
		t.Error("Update: expected error for canceled ctx")
	}
	if err := d.Delete(ctx, ref); err == nil {
		t.Error("Delete: expected error for canceled ctx")
	}
	// HealthCheck returns (result, nil) on cancellation rather than
	// surfacing err — the result's Healthy flag carries the signal.
	if res, err := d.HealthCheck(ctx, ref); err != nil {
		t.Errorf("HealthCheck: unexpected err for canceled ctx: %v", err)
	} else if res.Healthy {
		t.Error("HealthCheck: Healthy=true for canceled ctx; expected unhealthy")
	}
}

func TestDelegationDriver_Read_PropagatesErrEmptyNameservers(t *testing.T) {
	// Callers using errors.Is(driverErr, hover.ErrEmptyNameservers) to
	// distinguish "Hover surfaced 0 nameservers" from other failures need
	// the sentinel to survive the driver's error wrap. This test defends
	// that contract.
	fc := &fakeDelegationClient{
		getErr: fmt.Errorf("hover: GetDomainDelegation %q: %w", "example.com", hover.ErrEmptyNameservers),
	}
	d := NewDelegationDriverWithClient(fc)
	_, err := d.Read(context.Background(), interfaces.ResourceRef{Name: "example.com", ProviderID: "example.com"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, hover.ErrEmptyNameservers) {
		t.Errorf("errors.Is should match hover.ErrEmptyNameservers through driver wrap; got %v", err)
	}
}

func TestDelegationDriver_Create_CaseInsensitiveDuplicate_Rejected(t *testing.T) {
	// DNS hostnames are case-insensitive; ["NS1.example.com", "ns1.example.com"]
	// is a duplicate even though the strings differ. Matches the EqualFold
	// semantics used by Update + Diff.
	d := NewDelegationDriverWithClient(&fakeDelegationClient{})
	spec := interfaces.ResourceSpec{
		Name: "example.com", Type: "infra.dns_delegation",
		Config: map[string]any{
			"domain":      "example.com",
			"nameservers": []any{"NS1.example.com", "ns1.example.com"},
		},
	}
	if _, err := d.Create(context.Background(), spec); err == nil {
		t.Fatal("expected error for case-insensitive duplicate nameservers")
	}
}

func TestDelegationDriver_Diff_CaseInsensitiveMatch(t *testing.T) {
	// Same hostnames in different cases must match (DNS is
	// case-insensitive). Regresses a sort-vs-EqualFold sequencing
	// bug where mixed-case multisets could falsely diverge.
	d := NewDelegationDriverWithClient(&fakeDelegationClient{})
	spec := interfaces.ResourceSpec{
		Name: "example.com", Type: "infra.dns_delegation",
		Config: map[string]any{
			"domain":      "example.com",
			"nameservers": []any{"NS1.example.com", "ns2.example.com"},
		},
	}
	current := &interfaces.ResourceOutput{
		ProviderID: "example.com",
		Outputs: map[string]any{
			"domain":      "example.com",
			"nameservers": []any{"ns1.EXAMPLE.com", "NS2.example.com"},
		},
	}
	res, err := d.Diff(context.Background(), spec, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if res.NeedsUpdate {
		t.Error("expected NeedsUpdate=false; case-only diff is no-op")
	}
}
