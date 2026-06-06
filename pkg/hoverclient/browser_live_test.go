package hoverclient

import (
	"context"
	"os"
	"sort"
	"strings"
	"testing"
)

func TestLiveBrowserLoginAndHTTPReuseProbe(t *testing.T) {
	if os.Getenv("HOVER_LIVE_TEST") != "1" {
		t.Skip("set HOVER_LIVE_TEST=1 to run live Hover browser auth probe")
	}
	creds := liveCredentialsFromEnv(t)
	opts := liveBrowserOptionsFromEnv(t)
	result, err := ProbeLiveBrowserAuth(context.Background(), creds, opts)
	if err != nil {
		t.Fatalf("live browser auth probe: %v", err)
	}
	if !result.LoginSucceeded {
		t.Fatalf("login did not complete")
	}
	if len(result.ClearanceCookies) == 0 {
		t.Fatalf("Imperva clearance cookies not observed")
	}
	t.Logf("go_http_reuse_viable=%t domains=%d clearance_cookies=%v", result.GoHTTPReuseViable, result.DomainCount, result.ClearanceCookieNames())
}

func TestLiveSetNameserversNoop(t *testing.T) {
	if os.Getenv("HOVER_LIVE_TEST") != "1" {
		t.Skip("set HOVER_LIVE_TEST=1 to run live Hover browser write probe")
	}
	domain := strings.TrimSpace(os.Getenv("HOVER_LIVE_NS_DOMAIN"))
	if domain == "" {
		t.Skip("set HOVER_LIVE_NS_DOMAIN to the disposable Hover domain to test")
	}
	wantNS := splitLiveNameservers(os.Getenv("HOVER_LIVE_NS_EXPECTED"))
	if len(wantNS) == 0 {
		t.Fatal("set HOVER_LIVE_NS_EXPECTED to the current nameservers, comma-separated")
	}

	ctx := context.Background()
	creds := liveCredentialsFromEnv(t)
	opts := liveBrowserOptionsFromEnv(t)
	c, err := NewClientWithOptions(creds, nil, ClientOptions{Browser: opts})
	if err != nil {
		t.Fatalf("NewClientWithOptions: %v", err)
	}

	domains, err := c.ListDomains(ctx)
	if err != nil {
		t.Fatalf("ListDomains before write: %v", err)
	}
	var found bool
	for _, d := range domains {
		if strings.EqualFold(d.Name, domain) {
			found = true
			assertNameserversMatch(t, "ListDomains nameservers", d.Nameservers, wantNS)
			break
		}
	}
	if !found {
		t.Fatalf("domain %q not found in Hover account", domain)
	}

	before, err := c.GetDomainDelegation(ctx, domain)
	if err != nil {
		t.Fatalf("GetDomainDelegation before write: %v", err)
	}
	assertNameserversMatch(t, "delegation before write", before.Nameservers, wantNS)

	if err := c.SetNameservers(ctx, domain, wantNS); err != nil {
		t.Fatalf("SetNameservers no-op write: %v", err)
	}

	after, err := c.GetDomainDelegation(ctx, domain)
	if err != nil {
		t.Fatalf("GetDomainDelegation after write: %v", err)
	}
	assertNameserversMatch(t, "delegation after write", after.Nameservers, wantNS)
	t.Logf("SetNameservers no-op write succeeded for %s with %s", domain, strings.Join(wantNS, ","))
}

func liveCredentialsFromEnv(t *testing.T) Credentials {
	t.Helper()
	var missing []string
	username := strings.TrimSpace(os.Getenv("HOVER_USERNAME"))
	password := strings.TrimRight(os.Getenv("HOVER_PASSWORD"), "\r\n")
	if username == "" {
		missing = append(missing, "HOVER_USERNAME")
	}
	if password == "" {
		missing = append(missing, "HOVER_PASSWORD")
	}
	if len(missing) > 0 {
		t.Fatalf("missing live Hover env: %s", strings.Join(missing, ", "))
	}
	var totp TOTPSecret
	if raw := strings.TrimSpace(os.Getenv("HOVER_TOTP_SECRET")); raw != "" {
		parsed, err := ParseBase32(raw)
		if err != nil {
			t.Fatalf("invalid HOVER_TOTP_SECRET: %v", err)
		}
		totp = parsed
	}
	return Credentials{Username: username, Password: password, TOTPSecret: totp}
}

func splitLiveNameservers(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		ns := strings.Trim(strings.TrimSpace(part), ".")
		if ns != "" {
			out = append(out, strings.ToLower(ns))
		}
	}
	return out
}

func assertNameserversMatch(t *testing.T, label string, got, want []string) {
	t.Helper()
	gotNorm := normalizeNameservers(got)
	wantNorm := normalizeNameservers(want)
	if len(gotNorm) != len(wantNorm) {
		t.Fatalf("%s = %v, want %v", label, gotNorm, wantNorm)
	}
	for i := range wantNorm {
		if gotNorm[i] != wantNorm[i] {
			t.Fatalf("%s = %v, want %v", label, gotNorm, wantNorm)
		}
	}
}

func normalizeNameservers(ns []string) []string {
	out := make([]string, 0, len(ns))
	for _, item := range ns {
		trimmed := strings.Trim(strings.TrimSpace(item), ".")
		if trimmed != "" {
			out = append(out, strings.ToLower(trimmed))
		}
	}
	sort.Strings(out)
	return out
}

func liveBrowserOptionsFromEnv(t *testing.T) BrowserOptions {
	t.Helper()
	opts, err := BrowserOptionsFromEnv()
	if err != nil {
		t.Fatalf("browser options from env: %v", err)
	}
	return opts
}
