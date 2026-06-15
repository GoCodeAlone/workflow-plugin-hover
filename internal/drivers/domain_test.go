package drivers

import (
	"context"
	"testing"

	"github.com/GoCodeAlone/workflow/interfaces"
)

type fakeDomainClient struct {
	locked   bool
	getCalls int
	setCalls int
	setValue bool
	getErr   error
	setErr   error
}

func (f *fakeDomainClient) GetTransferLock(_ context.Context, _ string) (bool, error) {
	f.getCalls++
	if f.getErr != nil {
		return false, f.getErr
	}
	return f.locked, nil
}

func (f *fakeDomainClient) SetTransferLock(_ context.Context, _ string, locked bool) error {
	f.setCalls++
	f.setValue = locked
	if f.setErr != nil {
		return f.setErr
	}
	f.locked = locked
	return nil
}

func TestDomainDriver_UpdateSkipsWriteWhenTransferLockMatches(t *testing.T) {
	fc := &fakeDomainClient{locked: true}
	d := NewDomainDriverWithClient(fc)

	out, err := d.Update(context.Background(), interfaces.ResourceRef{
		Name:       "example.com",
		Type:       "infra.domain",
		ProviderID: "example.com",
	}, interfaces.ResourceSpec{
		Name: "example.com",
		Type: "infra.domain",
		Config: map[string]any{
			"domain":        "example.com",
			"transfer_lock": true,
		},
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if fc.getCalls != 1 {
		t.Fatalf("GetTransferLock calls = %d, want 1", fc.getCalls)
	}
	if fc.setCalls != 0 {
		t.Fatalf("SetTransferLock calls = %d, want 0", fc.setCalls)
	}
	if out.Outputs["transfer_lock"] != true {
		t.Fatalf("transfer_lock output = %v, want true", out.Outputs["transfer_lock"])
	}
}

func TestDomainDriver_UpdateWritesWhenTransferLockDiffers(t *testing.T) {
	fc := &fakeDomainClient{locked: true}
	d := NewDomainDriverWithClient(fc)

	out, err := d.Update(context.Background(), interfaces.ResourceRef{
		Name:       "example.com",
		Type:       "infra.domain",
		ProviderID: "example.com",
	}, interfaces.ResourceSpec{
		Name: "example.com",
		Type: "infra.domain",
		Config: map[string]any{
			"domain":        "example.com",
			"transfer_lock": false,
		},
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if fc.getCalls != 1 {
		t.Fatalf("GetTransferLock calls = %d, want 1", fc.getCalls)
	}
	if fc.setCalls != 1 {
		t.Fatalf("SetTransferLock calls = %d, want 1", fc.setCalls)
	}
	if fc.setValue {
		t.Fatal("SetTransferLock value = true, want false")
	}
	if out.Outputs["transfer_lock"] != false {
		t.Fatalf("transfer_lock output = %v, want false", out.Outputs["transfer_lock"])
	}
}

func TestDomainDriver_DiffTransferLock(t *testing.T) {
	d := NewDomainDriverWithClient(&fakeDomainClient{})
	spec := interfaces.ResourceSpec{
		Name: "example.com",
		Type: "infra.domain",
		Config: map[string]any{
			"domain":        "example.com",
			"transfer_lock": false,
		},
	}

	diff, err := d.Diff(context.Background(), spec, &interfaces.ResourceOutput{
		Name:       "example.com",
		Type:       "infra.domain",
		ProviderID: "example.com",
		Outputs: map[string]any{
			"domain":        "example.com",
			"transfer_lock": true,
		},
	})
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if diff == nil || !diff.NeedsUpdate {
		t.Fatalf("NeedsUpdate = false, want true")
	}
	if len(diff.Changes) != 1 || diff.Changes[0].Path != "transfer_lock" {
		t.Fatalf("changes = %#v, want transfer_lock", diff.Changes)
	}
}
