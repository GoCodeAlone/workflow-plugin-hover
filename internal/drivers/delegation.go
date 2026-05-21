// Package-doc additions in this file are scoped to the dns_delegation
// driver. See dns.go for the prior infra.dns driver.
package drivers

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/GoCodeAlone/workflow-plugin-hover/internal/hover"
	"github.com/GoCodeAlone/workflow/interfaces"
)

// HoverDelegationClient is the subset of *hover.Client that DelegationDriver
// depends on. Injectable for tests.
type HoverDelegationClient interface {
	GetDomainDelegation(ctx context.Context, domain string) (*hover.DomainDelegation, error)
	SetNameservers(ctx context.Context, domain string, ns []string) error
}

// DelegationDriver manages registrar-level nameserver delegation
// (infra.dns_delegation) for Hover-registered domains.
//
// ProviderID = apex domain name (e.g. "example.com"). One resource = one
// domain. Outputs contain only the desired nameservers as []any
// (structpb-safe). v0.2.0 ships Delete = reset to Hover defaults
// [ns1.hover.com, ns2.hover.com]; restore-from-stash is deferred to
// v0.3.0 because interfaces.ResourceRef has no state channel.
type DelegationDriver struct {
	client     HoverDelegationClient
	nsResolver func(context.Context, string) ([]string, error)
}

// NewDelegationDriver returns a DelegationDriver bound to a real *hover.Client.
func NewDelegationDriver(c *hover.Client) *DelegationDriver {
	return &DelegationDriver{client: c, nsResolver: lookupPublicNameservers}
}

// NewDelegationDriverWithClient returns a DelegationDriver bound to an
// injected client; used by tests.
func NewDelegationDriverWithClient(c HoverDelegationClient) *DelegationDriver {
	return &DelegationDriver{client: c}
}

// NewDelegationDriverWithClientAndResolver returns a DelegationDriver bound
// to an injected client and public-NS resolver; used by tests.
func NewDelegationDriverWithClientAndResolver(c HoverDelegationClient, resolver func(context.Context, string) ([]string, error)) *DelegationDriver {
	return &DelegationDriver{client: c, nsResolver: resolver}
}

func (d *DelegationDriver) Type() string { return "infra.dns_delegation" }

func (d *DelegationDriver) SensitiveKeys() []string { return nil }

func (d *DelegationDriver) ProviderIDFormat() interfaces.ProviderIDFormat {
	return interfaces.IDFormatDomainName
}

// dnsDelegationSpec is the parsed config view.
type dnsDelegationSpec struct {
	domain      string
	nameservers []string
}

// parseDelegationSpec validates config and produces a typed view.
func parseDelegationSpec(spec interfaces.ResourceSpec) (dnsDelegationSpec, error) {
	domain, _ := spec.Config["domain"].(string)
	if domain == "" {
		domain = spec.Name
	}
	if domain == "" {
		return dnsDelegationSpec{}, fmt.Errorf("dns_delegation: config missing required key 'domain' (or spec.Name)")
	}
	rawNS, present := spec.Config["nameservers"]
	if !present {
		return dnsDelegationSpec{}, fmt.Errorf("dns_delegation %q: config missing required key 'nameservers'", domain)
	}
	nsList, ok := rawNS.([]any)
	if !ok {
		return dnsDelegationSpec{}, fmt.Errorf("dns_delegation %q: config 'nameservers' must be an array, got %T", domain, rawNS)
	}
	if len(nsList) < 1 {
		return dnsDelegationSpec{}, fmt.Errorf("dns_delegation %q: config 'nameservers' must have ≥1 entry", domain)
	}
	seen := make(map[string]struct{}, len(nsList))
	parsed := make([]string, 0, len(nsList))
	for i, item := range nsList {
		s, ok := item.(string)
		if !ok {
			return dnsDelegationSpec{}, fmt.Errorf("dns_delegation %q: nameservers[%d] must be a string, got %T", domain, i, item)
		}
		s = strings.TrimSpace(s)
		if s == "" {
			return dnsDelegationSpec{}, fmt.Errorf("dns_delegation %q: nameservers[%d] must be non-empty", domain, i)
		}
		// DNS hostnames are case-insensitive; dedupe via lowercase key
		// to match the EqualFold semantics used by Update + Diff.
		key := strings.ToLower(s)
		if _, dup := seen[key]; dup {
			return dnsDelegationSpec{}, fmt.Errorf("dns_delegation %q: nameservers[%d] = %q is a duplicate (case-insensitive)", domain, i, s)
		}
		seen[key] = struct{}{}
		parsed = append(parsed, s)
	}
	return dnsDelegationSpec{domain: domain, nameservers: parsed}, nil
}

// nameserversToAny converts []string to []any. Required for Outputs values
// to round-trip through structpb (typed slices are rejected; see iacserver.go
// package doc and the workspace structpb-boundary feedback memory).
func nameserversToAny(ns []string) []any {
	out := make([]any, len(ns))
	for i, s := range ns {
		out[i] = normalizeNameserverHost(s)
	}
	return out
}

func normalizeNameserverHost(host string) string {
	return strings.TrimSuffix(strings.TrimSpace(host), ".")
}

// delegationOutput builds the ResourceOutput for a Create/Update result.
// v0.2.0 ships without previous_nameservers (no state channel in
// interfaces.ResourceRef; v0.3.0 follow-up).
func delegationOutput(name, domain string, ns []string) *interfaces.ResourceOutput {
	return &interfaces.ResourceOutput{
		Name:       name,
		Type:       "infra.dns_delegation",
		ProviderID: domain,
		Outputs: map[string]any{
			"domain":      domain,
			"nameservers": nameserversToAny(ns),
		},
		Status: "active",
	}
}

// Create PUTs the desired nameservers. Output built from the desired set
// (no read-after-write); SetNameservers is authoritative on success.
func (d *DelegationDriver) Create(ctx context.Context, spec interfaces.ResourceSpec) (*interfaces.ResourceOutput, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("dns_delegation create: %w", err)
	}
	s, err := parseDelegationSpec(spec)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("dns_delegation create %q: %w", s.domain, err)
	}
	if err := d.client.SetNameservers(ctx, s.domain, s.nameservers); err != nil {
		return nil, fmt.Errorf("dns_delegation create %q: %w", s.domain, err)
	}
	return delegationOutput(spec.Name, s.domain, s.nameservers), nil
}

// Read fetches the current registrar nameservers.
func (d *DelegationDriver) Read(ctx context.Context, ref interfaces.ResourceRef) (*interfaces.ResourceOutput, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("dns_delegation read %q: %w", ref.Name, err)
	}
	domain := ref.ProviderID
	if domain == "" {
		domain = ref.Name
	}
	if d.nsResolver != nil {
		if ns, err := d.nsResolver(ctx, domain); err == nil && len(ns) > 0 {
			return delegationOutput(ref.Name, domain, ns), nil
		}
	}
	dom, err := d.client.GetDomainDelegation(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("dns_delegation read %q: %w", ref.Name, err)
	}
	return delegationOutput(ref.Name, domain, dom.Nameservers), nil
}

func lookupPublicNameservers(ctx context.Context, domain string) ([]string, error) {
	resolver := net.DefaultResolver
	records, err := resolver.LookupNS(ctx, domain)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(records))
	for _, record := range records {
		host := normalizeNameserverHost(record.Host)
		if host != "" {
			out = append(out, host)
		}
	}
	return out, nil
}

// Update replaces the registrar nameservers. Rejects in-place domain
// renames (those must route through Diff → NeedsReplace → Delete-then-Create).
func (d *DelegationDriver) Update(ctx context.Context, ref interfaces.ResourceRef, spec interfaces.ResourceSpec) (*interfaces.ResourceOutput, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("dns_delegation update %q: %w", ref.Name, err)
	}
	s, err := parseDelegationSpec(spec)
	if err != nil {
		return nil, err
	}
	currentDomain := ref.ProviderID
	if currentDomain == "" {
		currentDomain = ref.Name
	}
	if !strings.EqualFold(s.domain, currentDomain) {
		return nil, fmt.Errorf("dns_delegation update %q: spec.domain %q does not match current %q — domain change requires resource replace, not update", ref.Name, s.domain, currentDomain)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("dns_delegation update %q: %w", ref.Name, err)
	}
	if err := d.client.SetNameservers(ctx, currentDomain, s.nameservers); err != nil {
		return nil, fmt.Errorf("dns_delegation update %q: %w", ref.Name, err)
	}
	return delegationOutput(ref.Name, currentDomain, s.nameservers), nil
}

// hoverDefaultNameservers is the Delete target for v0.2.0 (per A5).
// ResourceRef has no state channel for previous_nameservers restore;
// that enhancement is v0.3.0 follow-up territory.
var hoverDefaultNameservers = []string{"ns1.hover.com", "ns2.hover.com"}

// Delete resets the registrar nameservers to Hover's defaults.
// Operators whose domains had non-default originals must restore
// manually via the Hover UI if a Delete fires unintended.
func (d *DelegationDriver) Delete(ctx context.Context, ref interfaces.ResourceRef) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("dns_delegation delete %q: %w", ref.Name, err)
	}
	domain := ref.ProviderID
	if domain == "" {
		domain = ref.Name
	}
	if err := d.client.SetNameservers(ctx, domain, hoverDefaultNameservers); err != nil {
		return fmt.Errorf("dns_delegation delete %q: %w", ref.Name, err)
	}
	return nil
}

// Diff compares desired vs current. Multiset semantics on nameservers
// (order-independent — Hover accepts any order on PUT). Domain rename
// (desired vs current.ProviderID) forces Replace.
func (d *DelegationDriver) Diff(_ context.Context, desired interfaces.ResourceSpec, current *interfaces.ResourceOutput) (*interfaces.DiffResult, error) {
	s, err := parseDelegationSpec(desired)
	if err != nil {
		return nil, err
	}
	if current == nil {
		return &interfaces.DiffResult{NeedsUpdate: true}, nil
	}
	if current.ProviderID != "" && !strings.EqualFold(s.domain, current.ProviderID) {
		// Set BOTH NeedsUpdate + NeedsReplace per the DNSDriver
		// pattern (see dns.go). Some planner paths gate on
		// NeedsUpdate; leaving it false risks the replace being
		// skipped even though NeedsReplace says otherwise.
		return &interfaces.DiffResult{
			NeedsUpdate:  true,
			NeedsReplace: true,
			Changes: []interfaces.FieldChange{{
				Path:     "domain",
				Old:      current.ProviderID,
				New:      s.domain,
				ForceNew: true,
			}},
		}, nil
	}
	currentNS := nameserversFromOutputs(current.Outputs)
	if !sameNameserverSet(currentNS, s.nameservers) {
		return &interfaces.DiffResult{
			NeedsUpdate: true,
			Changes: []interfaces.FieldChange{{
				Path: "nameservers",
				Old:  nameserversToAny(currentNS),
				New:  nameserversToAny(s.nameservers),
			}},
		}, nil
	}
	return &interfaces.DiffResult{NeedsUpdate: false}, nil
}

// nameserversFromOutputs reconstructs []string from Outputs["nameservers"]
// (which is stored as []any).
func nameserversFromOutputs(outputs map[string]any) []string {
	raw, ok := outputs["nameservers"]
	if !ok {
		return nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// sameNameserverSet returns true iff a and b are multiset-equal.
func sameNameserverSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	// Normalize to lowercase before sorting so the pairwise sort
	// positions are consistent with the EqualFold comparison.
	// Without normalize-then-sort, ["NS.foo"] sorts before ["ns.bar"]
	// case-sensitively but the case-insensitive compare expects the
	// reverse — causing two case-equal multisets to falsely diverge.
	sa := make([]string, len(a))
	sb := make([]string, len(b))
	for i, s := range a {
		sa[i] = strings.ToLower(s)
	}
	for i, s := range b {
		sb[i] = strings.ToLower(s)
	}
	sort.Strings(sa)
	sort.Strings(sb)
	for i := range sa {
		if sa[i] != sb[i] {
			return false
		}
	}
	return true
}

// HealthCheck probes connectivity to the domain by fetching its delegation.
func (d *DelegationDriver) HealthCheck(ctx context.Context, ref interfaces.ResourceRef) (*interfaces.HealthResult, error) {
	if err := ctx.Err(); err != nil {
		return &interfaces.HealthResult{Healthy: false, Message: err.Error()}, nil
	}
	domain := ref.ProviderID
	if domain == "" {
		domain = ref.Name
	}
	if _, err := d.client.GetDomainDelegation(ctx, domain); err != nil {
		return &interfaces.HealthResult{Healthy: false, Message: err.Error()}, nil
	}
	return &interfaces.HealthResult{Healthy: true, Message: "ok"}, nil
}

// Scale is not supported for DNS delegation (no replica concept).
func (d *DelegationDriver) Scale(_ context.Context, _ interfaces.ResourceRef, _ int) (*interfaces.ResourceOutput, error) {
	return nil, fmt.Errorf("dns_delegation: scale is not supported")
}
