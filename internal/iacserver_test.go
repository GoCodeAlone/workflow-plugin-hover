package internal

import (
	"context"
	"testing"

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
	if len(resp.GetCapabilities()) != 1 {
		t.Fatalf("expected 1 capability, got %d", len(resp.GetCapabilities()))
	}
	cap := resp.GetCapabilities()[0]
	if cap.GetResourceType() != "infra.dns" {
		t.Errorf("ResourceType = %q want %q", cap.GetResourceType(), "infra.dns")
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
