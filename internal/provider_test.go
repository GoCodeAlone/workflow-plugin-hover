package internal

import (
	"context"
	"errors"
	"net/http"
	"os"
	"sync/atomic"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-hover/internal/drivers"
	"github.com/GoCodeAlone/workflow-plugin-hover/pkg/hoverclient"
	"github.com/GoCodeAlone/workflow/interfaces"
)

func TestHoverProvider_Capabilities_IncludesDelegation(t *testing.T) {
	p := NewHoverProvider()
	caps := p.Capabilities()
	wantTypes := map[string]bool{
		"infra.dns":            false,
		"infra.dns_delegation": false,
		"infra.domain":         false,
		"infra.http_redirect":  false,
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

// ── EnumerateAll(infra.dns_delegation) coverage ─────────────────────────────

// TestEnumerateAll_DelegationListsDomains verifies that EnumerateAll for
// "infra.dns_delegation" returns one ResourceOutput per domain with
// ProviderID == domain.Name and Type == "infra.dns_delegation", and that
// an unknown resource type still returns the unsupported error.
func TestEnumerateAll_DelegationListsDomains(t *testing.T) {
	stub := &fakeHoverClient{
		domains: []hoverclient.Domain{
			{ID: "1", Name: "a.com"},
			{ID: "2", Name: "b.com"},
		},
	}
	p := &HoverProvider{domains: stub}

	out, err := p.EnumerateAll(context.Background(), "infra.dns_delegation")
	if err != nil {
		t.Fatalf("EnumerateAll(infra.dns_delegation): %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 outputs; got %d", len(out))
	}
	for i, want := range []string{"a.com", "b.com"} {
		if out[i].ProviderID != want {
			t.Errorf("out[%d].ProviderID = %q; want %q", i, out[i].ProviderID, want)
		}
		if out[i].Type != "infra.dns_delegation" {
			t.Errorf("out[%d].Type = %q; want infra.dns_delegation", i, out[i].Type)
		}
	}
	if stub.calls != 1 {
		t.Errorf("ListDomains called %d times; want 1", stub.calls)
	}

	// Unknown resource type must still return the unsupported error.
	stub2 := &fakeHoverClient{}
	p2 := &HoverProvider{domains: stub2}
	_, err2 := p2.EnumerateAll(context.Background(), "infra.compute")
	if err2 == nil {
		t.Fatal("want error for unsupported resource type; got nil")
	}
}

// ── Import delegation dual-fetch coverage ────────────────────────────────────

// fakeDelegationClientForImport satisfies HoverDelegationClient and
// hoverDomainLister so it can be injected into both the DelegationDriver
// and HoverProvider.domains field. It also satisfies hoverclient.HoverClient
// via a nil client stored in drivers so we need a separate provider-level stub.
type fakeDelegationClientForImport struct {
	registrarNS  []string
	registrarErr error
}

func (f *fakeDelegationClientForImport) GetDomainDelegation(_ context.Context, _ string) (*hoverclient.DomainDelegation, error) {
	if f.registrarErr != nil {
		return nil, f.registrarErr
	}
	return &hoverclient.DomainDelegation{
		ID:          "domain-x.com",
		Name:        "x.com",
		Nameservers: f.registrarNS,
	}, nil
}

func (f *fakeDelegationClientForImport) SetNameservers(_ context.Context, _ string, _ []string) error {
	return nil
}

// TestImport_DelegationUsesRegistrarNotLiveRead verifies that
// HoverProvider.Import for infra.dns_delegation calls ReadForImport (which
// fetches the registrar NS authoritatively) rather than falling through to
// the live-first DelegationDriver.Read path.
func TestImport_DelegationUsesRegistrarNotLiveRead(t *testing.T) {
	registrarNS := []string{"ns1.dnsimple.com"}
	liveNS := []string{"ns1.digitalocean.com"}

	fc := &fakeDelegationClientForImport{registrarNS: registrarNS}

	// Build a DelegationDriver with a resolver that returns different (live) NS.
	liveResolver := func(_ context.Context, _ string) ([]string, error) {
		return liveNS, nil
	}

	delegDriver := drivers.NewDelegationDriverWithClientAndResolver(fc, liveResolver)

	p := &HoverProvider{
		drivers: map[string]interfaces.ResourceDriver{
			"infra.dns_delegation": delegDriver,
			"infra.dns":            &noopCreateDriver{},
		},
	}

	state, err := p.Import(context.Background(), "x.com", "infra.dns_delegation")
	if err != nil {
		t.Fatalf("Import(infra.dns_delegation): %v", err)
	}
	if state == nil {
		t.Fatal("Import returned nil state")
	}

	// registrar_nameservers must be the REGISTRAR value (not live).
	regNS, ok := state.Outputs["registrar_nameservers"].([]any)
	if !ok || len(regNS) != 1 || regNS[0] != "ns1.dnsimple.com" {
		t.Errorf("registrar_nameservers = %v, want [ns1.dnsimple.com]", state.Outputs["registrar_nameservers"])
	}

	// live_nameservers must be the LIVE DNS value.
	liveNSOut, ok := state.Outputs["live_nameservers"].([]any)
	if !ok || len(liveNSOut) != 1 || liveNSOut[0] != "ns1.digitalocean.com" {
		t.Errorf("live_nameservers = %v, want [ns1.digitalocean.com]", state.Outputs["live_nameservers"])
	}

	// Primary nameservers must equal registrar (authoritative intent).
	ns, ok := state.Outputs["nameservers"].([]any)
	if !ok || len(ns) != 1 || ns[0] != "ns1.dnsimple.com" {
		t.Errorf("nameservers = %v, want [ns1.dnsimple.com]", state.Outputs["nameservers"])
	}

	// ResourceState structural invariants.
	if state.Provider != "hover" {
		t.Errorf("Provider = %q, want hover", state.Provider)
	}
	if state.Type != "infra.dns_delegation" {
		t.Errorf("Type = %q, want infra.dns_delegation", state.Type)
	}
	if state.AppliedConfigSource != "adoption" {
		t.Errorf("AppliedConfigSource = %q, want adoption", state.AppliedConfigSource)
	}
}

// TestImport_DNSUnchanged verifies that Import for infra.dns still goes
// through the generic d.Read path (not the delegation dual-fetch).
func TestImport_DNSUnchanged(t *testing.T) {
	// noopCreateDriver.Read returns nil — Import must not panic or break.
	p := &HoverProvider{
		drivers: map[string]interfaces.ResourceDriver{
			"infra.dns":            &noopCreateDriver{},
			"infra.dns_delegation": &noopCreateDriver{},
		},
	}
	// infra.dns with nil Read output → Import returns an error (nil output guard).
	_, err := p.Import(context.Background(), "x.com", "infra.dns")
	if err == nil {
		t.Fatal("expected error when driver.Read returns nil output for infra.dns")
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
