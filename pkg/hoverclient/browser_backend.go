package hoverclient

import (
	"context"
	"errors"
)

// ErrBrowserBackendUnavailable is returned by browserBackend live operations
// before the full browser login implementation is wired (Task 3). Callers
// should treat this as a "not yet implemented via browser" signal.
var ErrBrowserBackendUnavailable = errors.New("hover: browser backend not yet available for this operation (Task 3)")

// browserBackend implements executionBackend using a Chrome instance driven
// via the GoCodeAlone/rod CDP library. Login mints Imperva clearance cookies
// and completes TOTP 2FA in-browser; subsequent read operations reuse those
// cookies via the Go http.Client (hybrid architecture).
//
// Live operations currently return ErrBrowserBackendUnavailable — the full
// browser login flow is implemented in Task 3.
type browserBackend struct {
	opts BrowserOptions
}

func newBrowserBackend(opts BrowserOptions) *browserBackend {
	return &browserBackend{opts: opts}
}

func (b *browserBackend) Login(_ context.Context, _ *Client) error {
	return ErrBrowserBackendUnavailable
}

func (b *browserBackend) ListDomains(_ context.Context, _ *Client) ([]Domain, error) {
	return nil, ErrBrowserBackendUnavailable
}

func (b *browserBackend) GetDomain(_ context.Context, _ *Client, _ string) (*Domain, error) {
	return nil, ErrBrowserBackendUnavailable
}

func (b *browserBackend) ListRecords(_ context.Context, _ *Client, _ string) ([]DNSRecord, error) {
	return nil, ErrBrowserBackendUnavailable
}

func (b *browserBackend) CreateRecord(_ context.Context, _ *Client, _ string, _ DNSRecord) (*DNSRecord, error) {
	return nil, ErrBrowserBackendUnavailable
}

func (b *browserBackend) UpdateRecord(_ context.Context, _ *Client, _ string, _ DNSRecord) error {
	return ErrBrowserBackendUnavailable
}

func (b *browserBackend) DeleteRecord(_ context.Context, _ *Client, _ string) error {
	return ErrBrowserBackendUnavailable
}

func (b *browserBackend) GetDomainDelegation(_ context.Context, _ *Client, _ string) (*DomainDelegation, error) {
	return nil, ErrBrowserBackendUnavailable
}

func (b *browserBackend) SetNameservers(_ context.Context, _ *Client, _ string, _ []string) error {
	return ErrBrowserBackendUnavailable
}

func (b *browserBackend) Close() error { return nil }
