package hoverclient

import "context"

// executionBackend is the internal seam that routes login and API calls to
// either the HTTP backend (testing, injected http.Client) or the browser
// backend (production, Chrome-driven Imperva clearance + login).
//
// All methods receive *Client so the backend can read credentials, the cookie
// jar, and internal fields without duplicating them.
type executionBackend interface {
	Login(ctx context.Context, c *Client) error
	ListDomains(ctx context.Context, c *Client) ([]Domain, error)
	GetDomain(ctx context.Context, c *Client, domain string) (*Domain, error)
	ListRecords(ctx context.Context, c *Client, domain string) ([]DNSRecord, error)
	CreateRecord(ctx context.Context, c *Client, domainID string, rec DNSRecord) (*DNSRecord, error)
	UpdateRecord(ctx context.Context, c *Client, recordID string, rec DNSRecord) error
	DeleteRecord(ctx context.Context, c *Client, recordID string) error
	GetDomainDelegation(ctx context.Context, c *Client, domainName string) (*DomainDelegation, error)
	SetNameservers(ctx context.Context, c *Client, domainName string, ns []string) error
	GetTransferLock(ctx context.Context, c *Client, domainName string) (bool, error)
	SetTransferLock(ctx context.Context, c *Client, domainName string, locked bool) error
	GetForward(ctx context.Context, c *Client, domainName string) (*DomainForward, error)
	SetForward(ctx context.Context, c *Client, domainName string, forward DomainForward) error
	Close() error
}

// httpBackend implements executionBackend by delegating to the *Client's
// existing HTTP methods. It is selected when an *http.Client is injected
// (tests and internal callers that manage their own HTTP client).
type httpBackend struct{}

func (h *httpBackend) Login(ctx context.Context, c *Client) error {
	return c.ensureLogin(ctx)
}

func (h *httpBackend) ListDomains(ctx context.Context, c *Client) ([]Domain, error) {
	return c.listDomainsHTTP(ctx)
}

func (h *httpBackend) GetDomain(ctx context.Context, c *Client, domain string) (*Domain, error) {
	return c.getDomainHTTP(ctx, domain)
}

func (h *httpBackend) ListRecords(ctx context.Context, c *Client, domain string) ([]DNSRecord, error) {
	return c.listRecordsHTTP(ctx, domain)
}

func (h *httpBackend) CreateRecord(ctx context.Context, c *Client, domainID string, rec DNSRecord) (*DNSRecord, error) {
	return c.createRecordHTTP(ctx, domainID, rec)
}

func (h *httpBackend) UpdateRecord(ctx context.Context, c *Client, recordID string, rec DNSRecord) error {
	return c.updateRecordHTTP(ctx, recordID, rec)
}

func (h *httpBackend) DeleteRecord(ctx context.Context, c *Client, recordID string) error {
	return c.deleteRecordHTTP(ctx, recordID)
}

func (h *httpBackend) GetDomainDelegation(ctx context.Context, c *Client, domainName string) (*DomainDelegation, error) {
	return c.getDomainDelegationHTTP(ctx, domainName)
}

func (h *httpBackend) SetNameservers(ctx context.Context, c *Client, domainName string, ns []string) error {
	return c.setNameserversHTTP(ctx, domainName, ns)
}

func (h *httpBackend) GetTransferLock(ctx context.Context, c *Client, domainName string) (bool, error) {
	return c.getTransferLockHTTP(ctx, domainName)
}

func (h *httpBackend) SetTransferLock(ctx context.Context, c *Client, domainName string, locked bool) error {
	return c.setTransferLockHTTP(ctx, domainName, locked)
}

func (h *httpBackend) GetForward(ctx context.Context, c *Client, domainName string) (*DomainForward, error) {
	return c.getForwardHTTP(ctx, domainName)
}

func (h *httpBackend) SetForward(ctx context.Context, c *Client, domainName string, forward DomainForward) error {
	return c.setForwardHTTP(ctx, domainName, forward)
}

func (h *httpBackend) Close() error { return nil }
