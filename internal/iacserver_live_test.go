//go:build live_dns

// Env-gated live integration coverage for EnumerateAll("infra.dns").
//
// Run with:
//
//	INFRA_DNS_ENUMERATE_LIVE=1 \
//	HOVER_USERNAME=$USER \
//	HOVER_PASSWORD=$PASS \
//	  GOWORK=off go test -tags live_dns \
//	  -run TestHoverProvider_EnumerateAll_DNS_live ./internal/...
//
// HOVER_TOTP_SECRET is optional; supply it when the test account has MFA
// enabled. Per docs/plans/2026-05-26-dns-provider-contract.md PR 4 (Task 13).
package internal

import (
	"context"
	"os"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-hover/pkg/hoverclient"
)

// newLiveHoverProvider builds a HoverProvider whose `domains` field is
// wired to the production *hoverclient.Client. Credentials come from
// HOVER_USERNAME + HOVER_PASSWORD (+ optional HOVER_TOTP_SECRET); the
// helper aborts the test (t.Fatal) when required env is missing so the
// live-only run is loud rather than silent.
func newLiveHoverProvider(t *testing.T) *HoverProvider {
	t.Helper()
	user := os.Getenv("HOVER_USERNAME")
	pass := os.Getenv("HOVER_PASSWORD")
	if user == "" || pass == "" {
		t.Fatal("HOVER_USERNAME + HOVER_PASSWORD must be set for live EnumerateAll test")
	}
	var totpSecret hoverclient.TOTPSecret
	if totpRaw := os.Getenv("HOVER_TOTP_SECRET"); totpRaw != "" {
		ts, err := hoverclient.ParseBase32(totpRaw)
		if err != nil {
			t.Fatalf("invalid HOVER_TOTP_SECRET: %v", err)
		}
		totpSecret = ts
	}
	creds := hoverclient.Credentials{
		Username:   user,
		Password:   pass,
		TOTPSecret: totpSecret,
	}
	c, err := hoverclient.NewClient(creds, nil)
	if err != nil {
		t.Fatalf("hoverclient.NewClient: %v", err)
	}
	return &HoverProvider{client: c, domains: c}
}

func TestHoverProvider_EnumerateAll_DNS_live(t *testing.T) {
	if os.Getenv("INFRA_DNS_ENUMERATE_LIVE") != "1" {
		t.Skip("set INFRA_DNS_ENUMERATE_LIVE=1 + HOVER_USERNAME + HOVER_PASSWORD to run")
	}
	p := newLiveHoverProvider(t)
	out, err := p.EnumerateAll(context.Background(), "infra.dns")
	if err != nil {
		t.Fatalf("live EnumerateAll: %v", err)
	}
	if len(out) == 0 {
		t.Skip("account has zero domains; cannot validate")
	}
	for _, o := range out {
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
	t.Logf("enumerated %d hover domains", len(out))
}
