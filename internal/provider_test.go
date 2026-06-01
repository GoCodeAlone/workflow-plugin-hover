package internal

import (
	"context"
	"errors"
	"net/http"
	"os"
	"sync/atomic"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-hover/pkg/hoverclient"
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

// ── EnumerateAll(infra.dns) coverage ────────────────────────────────────────

// fakeHoverClient is a slice-backed hoverDomainLister used to drive
// EnumerateAll tests without touching the real hoverclient.Client (which
// requires a live login flow).
type fakeHoverClient struct {
	domains []hoverclient.Domain
	err     error
	calls   int
}

func (f *fakeHoverClient) ListDomains(_ context.Context) ([]hoverclient.Domain, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.domains, nil
}

func TestHoverProvider_EnumerateAll_DNS(t *testing.T) {
	stub := &fakeHoverClient{
		domains: []hoverclient.Domain{
			// hoverclient.Domain.Name is the Go field (json tag is "domain_name").
			{ID: "dom-1", Name: "alpha.test"},
			{ID: "dom-2", Name: "beta.test"},
		},
	}
	p := &HoverProvider{domains: stub}
	out, err := p.EnumerateAll(context.Background(), "infra.dns")
	if err != nil {
		t.Fatalf("EnumerateAll: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2; got %d", len(out))
	}
	if out[0].ProviderID != "alpha.test" {
		t.Errorf("providerID[0] = %q; want alpha.test", out[0].ProviderID)
	}
	if out[0].Type != "infra.dns" {
		t.Errorf("type[0] = %q; want infra.dns", out[0].Type)
	}
	if out[0].Outputs["zone"] != "alpha.test" {
		t.Errorf("zone[0] = %v", out[0].Outputs["zone"])
	}
	if out[0].Outputs["domain_id"] != "dom-1" {
		t.Errorf("domain_id[0] = %v", out[0].Outputs["domain_id"])
	}
	if stub.calls != 1 {
		t.Errorf("ListDomains called %d times; want 1", stub.calls)
	}
}

func TestHoverProvider_EnumerateAll_DNS_uninitialized(t *testing.T) {
	p := &HoverProvider{}
	_, err := p.EnumerateAll(context.Background(), "infra.dns")
	if err == nil {
		t.Fatalf("want uninitialized error; got nil")
	}
}

func TestHoverProvider_EnumerateAll_DNS_unsupportedType(t *testing.T) {
	p := &HoverProvider{domains: &fakeHoverClient{}}
	_, err := p.EnumerateAll(context.Background(), "infra.compute")
	if err == nil {
		t.Fatalf("want unsupported-type error; got nil")
	}
}

// TestHoverProvider_EnumerateAll_DNS_skipsBlankName ensures zones with empty
// Name strings are dropped rather than emitted with empty ProviderID.
func TestHoverProvider_EnumerateAll_DNS_skipsBlankName(t *testing.T) {
	stub := &fakeHoverClient{
		domains: []hoverclient.Domain{
			{ID: "dom-empty", Name: ""},
			{ID: "dom-real", Name: "real.test"},
		},
	}
	p := &HoverProvider{domains: stub}
	out, err := p.EnumerateAll(context.Background(), "infra.dns")
	if err != nil {
		t.Fatalf("EnumerateAll: %v", err)
	}
	if len(out) != 1 || out[0].ProviderID != "real.test" {
		t.Fatalf("want 1 entry with ProviderID=real.test; got %+v", out)
	}
}

// ── browser config tests ──────────────────────────────────────────────────────

// TestInitialize_ParsesBrowserConfig verifies that browser_path, browser_download,
// browser_headless, and browser_profile_dir config keys are parsed and passed
// to the client.
func TestInitialize_ParsesBrowserConfig(t *testing.T) {
	p := NewHoverProvider()
	if err := p.Initialize(context.Background(), map[string]any{
		"username":            "user@example.com",
		"password":            "password",
		"browser_path":        "/usr/bin/chromium",
		"browser_download":    false,
		"browser_headless":    false,
		"browser_profile_dir": "/tmp/test-profile",
	}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	opts := p.browserOpts
	if opts.Path != "/usr/bin/chromium" {
		t.Errorf("Path = %q, want /usr/bin/chromium", opts.Path)
	}
	if opts.Download != false {
		t.Errorf("Download = %v, want false", opts.Download)
	}
	if opts.Headless != false {
		t.Errorf("Headless = %v, want false", opts.Headless)
	}
	if opts.ProfileDir != "/tmp/test-profile" {
		t.Errorf("ProfileDir = %q, want /tmp/test-profile", opts.ProfileDir)
	}
}

// TestInitialize_EnvBrowserConfigAliases verifies that HOVER_BROWSER_* env
// vars are read as fallbacks when the config map omits browser_* keys.
func TestInitialize_EnvBrowserConfigAliases(t *testing.T) {
	t.Setenv("HOVER_BROWSER_PATH", "/env/chrome")
	t.Setenv("HOVER_BROWSER_HEADLESS", "false")
	t.Setenv("HOVER_BROWSER_DOWNLOAD", "false")
	t.Setenv("HOVER_BROWSER_PROFILE_DIR", "/env/profile")
	defer func() {
		os.Unsetenv("HOVER_BROWSER_PATH")
		os.Unsetenv("HOVER_BROWSER_HEADLESS")
		os.Unsetenv("HOVER_BROWSER_DOWNLOAD")
		os.Unsetenv("HOVER_BROWSER_PROFILE_DIR")
	}()

	p := NewHoverProvider()
	if err := p.Initialize(context.Background(), map[string]any{
		"username": "user@example.com",
		"password": "password",
		// no browser_* config keys — env vars should be used
	}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	opts := p.browserOpts
	if opts.Path != "/env/chrome" {
		t.Errorf("Path = %q, want /env/chrome", opts.Path)
	}
	if opts.Headless != false {
		t.Errorf("Headless = %v, want false", opts.Headless)
	}
	if opts.Download != false {
		t.Errorf("Download = %v, want false", opts.Download)
	}
	if opts.ProfileDir != "/env/profile" {
		t.Errorf("ProfileDir = %q, want /env/profile", opts.ProfileDir)
	}
}
