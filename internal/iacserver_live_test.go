//go:build live_dns

// Env-gated live integration coverage for the HoverProvider IaC surface
// (Initialize, EnumerateAll, Import, Status) exercising the browser backend.
//
// Run with:
//
//	HOVER_LIVE_TEST=1 \
//	HOVER_USERNAME=$USER \
//	HOVER_PASSWORD=$PASS \
//	  GOWORK=off go test -tags live_dns \
//	  -run TestHoverProvider_IaC_live ./internal/...
//
// Optional env vars:
//   - HOVER_TOTP_SECRET       — base32 TOTP seed (required when account has
//     authenticator 2FA)
//   - HOVER_BROWSER_PATH / ROD_BROWSER_PATH — absolute path to Chrome binary
//   - HOVER_BROWSER_DOWNLOAD  — allow go-rod to download Chromium (default true)
//   - HOVER_BROWSER_HEADLESS  — run Chrome headlessly (default true)
//   - HOVER_BROWSER_PROFILE_DIR — persistent browser profile directory
package internal

import (
	"context"
	"os"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-hover/pkg/hoverclient"
	pb "github.com/GoCodeAlone/workflow/plugin/external/proto"
)

// newLiveHoverProvider builds a HoverProvider wired to the production
// *hoverclient.Client using browser opts from HOVER_BROWSER_* env vars
// (matching the production Initialize path). The helper aborts the test
// (t.Fatal) when required credentials are missing.
func newLiveHoverProvider(t *testing.T) *HoverProvider {
	t.Helper()
	user := os.Getenv("HOVER_USERNAME")
	pass := os.Getenv("HOVER_PASSWORD")
	if user == "" || pass == "" {
		t.Fatal("HOVER_USERNAME + HOVER_PASSWORD must be set for live test")
	}
	var totpSecret hoverclient.TOTPSecret
	if totpRaw := os.Getenv("HOVER_TOTP_SECRET"); totpRaw != "" {
		ts, err := hoverclient.ParseBase32(totpRaw)
		if err != nil {
			t.Fatalf("invalid HOVER_TOTP_SECRET: %v", err)
		}
		totpSecret = ts
	}

	browserOpts, err := hoverclient.BrowserOptionsFromEnv()
	if err != nil {
		t.Fatalf("browser opts from env: %v", err)
	}

	creds := hoverclient.Credentials{
		Username:   user,
		Password:   pass,
		TOTPSecret: totpSecret,
	}
	c, err := hoverclient.NewClientWithOptions(creds, nil, hoverclient.ClientOptions{Browser: browserOpts})
	if err != nil {
		t.Fatalf("hoverclient.NewClientWithOptions: %v", err)
	}
	return &HoverProvider{client: c, domains: c}
}

// newLiveInitializedProvider builds a HoverProvider via the production
// provider.Initialize path (parseBrowserConfig + NewClientWithOptions),
// sourcing all config from env vars.
func newLiveInitializedProvider(t *testing.T) *HoverProvider {
	t.Helper()
	cfg := map[string]any{
		"username": os.Getenv("HOVER_USERNAME"),
		"password": os.Getenv("HOVER_PASSWORD"),
	}
	if s := os.Getenv("HOVER_TOTP_SECRET"); s != "" {
		cfg["totp_secret"] = s
	}
	if s := os.Getenv("HOVER_BROWSER_PATH"); s != "" {
		cfg["browser_path"] = s
	}
	if s := os.Getenv("HOVER_BROWSER_PROFILE_DIR"); s != "" {
		cfg["browser_profile_dir"] = s
	}
	if s := os.Getenv("HOVER_BROWSER_DOWNLOAD"); s != "" {
		cfg["browser_download"] = s
	}
	if s := os.Getenv("HOVER_BROWSER_HEADLESS"); s != "" {
		cfg["browser_headless"] = s
	}
	p := NewHoverProvider()
	if err := p.Initialize(context.Background(), cfg); err != nil {
		t.Fatalf("provider Initialize: %v", err)
	}
	return p
}

// TestHoverProvider_IaC_live exercises the full provider IaC path:
// EnumerateAll → Import → Status, using the browser-auth backend.
// Requires HOVER_LIVE_TEST=1 + HOVER_USERNAME + HOVER_PASSWORD.
func TestHoverProvider_IaC_live(t *testing.T) {
	if os.Getenv("HOVER_LIVE_TEST") != "1" {
		t.Skip("set HOVER_LIVE_TEST=1 + HOVER_USERNAME + HOVER_PASSWORD to run")
	}
	ctx := context.Background()

	// Build an initialized provider via the production Initialize path so that
	// parseBrowserConfig + NewClientWithOptions are exercised end-to-end.
	p := newLiveInitializedProvider(t)

	// EnumerateAll — list all domains in the account.
	enumOut, err := p.EnumerateAll(ctx, "infra.dns")
	if err != nil {
		t.Fatalf("live EnumerateAll: %v", err)
	}
	if len(enumOut) == 0 {
		t.Skip("account has zero domains; cannot validate Import/Status paths")
	}
	for _, o := range enumOut {
		if o.ProviderID == "" {
			t.Errorf("empty ProviderID for %+v", o.Outputs)
		}
		if o.Type != "infra.dns" {
			t.Errorf("wrong Type %q", o.Type)
		}
		if _, ok := o.Outputs["zone"]; !ok {
			t.Errorf("missing zone output: %+v", o.Outputs)
		}
	}
	t.Logf("enumerated %d hover domains", len(enumOut))

	// Import — adopt the first domain via the provider Import path.
	firstDomain := enumOut[0].ProviderID
	state, err := p.Import(ctx, firstDomain, "infra.dns")
	if err != nil {
		t.Fatalf("live Import %q: %v", firstDomain, err)
	}
	if state == nil {
		t.Fatal("Import returned nil state")
	}
	if state.Provider != "hover" {
		t.Errorf("state.Provider = %q, want hover", state.Provider)
	}
	if state.ProviderID != firstDomain {
		t.Errorf("state.ProviderID = %q, want %q", state.ProviderID, firstDomain)
	}
	if state.AppliedConfigSource != "adoption" {
		t.Errorf("state.AppliedConfigSource = %q, want adoption", state.AppliedConfigSource)
	}
	t.Logf("imported domain %q: %d outputs", firstDomain, len(state.Outputs))

	// Status — exercise the typed gRPC IaC server Status path.
	srv := &hoverIaCServer{provider: p}
	statusResp, err := srv.Status(ctx, &pb.StatusRequest{
		Refs: []*pb.ResourceRef{
			{Name: firstDomain, Type: "infra.dns", ProviderId: firstDomain},
		},
	})
	if err != nil {
		t.Fatalf("live Status %q: %v", firstDomain, err)
	}
	if len(statusResp.GetStatuses()) == 0 {
		t.Error("Status returned no statuses")
	}
	t.Logf("status for %q: %d statuses returned", firstDomain, len(statusResp.GetStatuses()))
}
