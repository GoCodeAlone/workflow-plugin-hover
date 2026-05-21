package internal

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
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
