package internal

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/GoCodeAlone/workflow/interfaces"
)

func TestHoverProvider_Capabilities_IncludesDelegation(t *testing.T) {
	p := NewHoverProvider()
	caps := p.Capabilities()
	wantTypes := map[string]bool{
		"infra.dns":            false,
		"infra.dns_delegation": false,
	}
	for _, c := range caps {
		if _, ok := wantTypes[c.ResourceType]; ok {
			wantTypes[c.ResourceType] = true
		}
	}
	for rt, found := range wantTypes {
		if !found {
			t.Errorf("Capabilities missing %q", rt)
		}
	}
}

func TestHoverProvider_Initialize_DoesNotLogin(t *testing.T) {
	var hits atomic.Int32
	orig := http.DefaultTransport
	http.DefaultTransport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		hits.Add(1)
		return nil, errors.New("unexpected network call")
	})
	defer func() { http.DefaultTransport = orig }()

	p := NewHoverProvider()
	if err := p.Initialize(context.Background(), map[string]any{
		"username": "user@example.com",
		"password": "password",
	}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("Initialize made %d network calls; login should happen lazily on API operations", got)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestHoverProvider_Plan_FiltersDriverNoopCreates(t *testing.T) {
	p := &HoverProvider{
		drivers: map[string]interfaces.ResourceDriver{
			"infra.dns_delegation": &noopCreateDriver{},
		},
	}
	plan, err := p.Plan(context.Background(), []interfaces.ResourceSpec{{
		Name: "example.com",
		Type: "infra.dns_delegation",
		Config: map[string]any{
			"domain":      "example.com",
			"nameservers": []any{"ns1.example.com"},
		},
	}}, nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Actions) != 0 {
		t.Fatalf("expected no actions after driver no-op create filter, got %+v", plan.Actions)
	}
}

type noopCreateDriver struct{}

func (d *noopCreateDriver) Create(context.Context, interfaces.ResourceSpec) (*interfaces.ResourceOutput, error) {
	return nil, nil
}

func (d *noopCreateDriver) Read(context.Context, interfaces.ResourceRef) (*interfaces.ResourceOutput, error) {
	return nil, nil
}

func (d *noopCreateDriver) Update(context.Context, interfaces.ResourceRef, interfaces.ResourceSpec) (*interfaces.ResourceOutput, error) {
	return nil, nil
}

func (d *noopCreateDriver) Delete(context.Context, interfaces.ResourceRef) error {
	return nil
}

func (d *noopCreateDriver) Diff(context.Context, interfaces.ResourceSpec, *interfaces.ResourceOutput) (*interfaces.DiffResult, error) {
	return &interfaces.DiffResult{NeedsUpdate: false}, nil
}

func (d *noopCreateDriver) HealthCheck(context.Context, interfaces.ResourceRef) (*interfaces.HealthResult, error) {
	return nil, nil
}

func (d *noopCreateDriver) Scale(context.Context, interfaces.ResourceRef, int) (*interfaces.ResourceOutput, error) {
	return nil, nil
}

func (d *noopCreateDriver) SensitiveKeys() []string {
	return nil
}
