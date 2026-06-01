package hoverclient

import (
	"context"
	"os"
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

func liveBrowserOptionsFromEnv(t *testing.T) BrowserOptions {
	t.Helper()
	opts, err := BrowserOptionsFromEnv()
	if err != nil {
		t.Fatalf("browser options from env: %v", err)
	}
	return opts
}
