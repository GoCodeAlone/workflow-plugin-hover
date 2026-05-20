// Package drivers provides IaC ResourceDriver implementations for the Hover
// DNS provider.
//
// Hover exposes NO official API. All endpoints below are derived from
// https://github.com/pjslauta/hover-dyn-dns and browser traffic inspection.
// Endpoint inventory (all relative to https://www.hover.com):
//
//	GET  /api/domains/<domain>/dns       — list records for a zone
//	POST /api/dns                         — create a record (form: domain_id, name, type, content, ttl)
//	PUT  /api/dns/<id>                    — update a record (form: content, ttl)
//	DELETE /api/dns/<id>                  — delete a record
//
// These are undocumented; the Hover site uses them directly from the control
// panel SPA. They may change without notice.
package drivers

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/GoCodeAlone/workflow-plugin-hover/internal/hover"
	"github.com/GoCodeAlone/workflow/interfaces"
)

// HoverDNSClient is the subset of hover.Client used by DNSDriver (injectable for tests).
type HoverDNSClient interface {
	GetDomain(ctx context.Context, domain string) (*hover.Domain, error)
	ListRecords(ctx context.Context, domain string) ([]hover.DNSRecord, error)
	CreateRecord(ctx context.Context, domainID string, rec hover.DNSRecord) (*hover.DNSRecord, error)
	UpdateRecord(ctx context.Context, recordID string, rec hover.DNSRecord) error
	DeleteRecord(ctx context.Context, recordID string) error
}

// DNSDriver manages Hover DNS zones and records (infra.dns).
// ProviderID is the apex domain name (e.g. "example.com").
type DNSDriver struct {
	client HoverDNSClient
}

// NewDNSDriver creates a DNSDriver backed by a real hover.Client.
func NewDNSDriver(c *hover.Client) *DNSDriver {
	return &DNSDriver{client: c}
}

// NewDNSDriverWithClient creates a driver with an injected client (for tests).
func NewDNSDriverWithClient(c HoverDNSClient) *DNSDriver {
	return &DNSDriver{client: c}
}

// Create idempotently reconciles a DNS zone on Hover. It creates missing
// records and updates existing ones that differ. Hover does not support
// creating zones via API — the domain must already be registered and in the
// account.
//
// Config keys:
//
//	domain   string      — apex zone name (e.g. "example.com"). Falls back to spec.Name.
//	records  []any       — each element: {type, name, content, ttl?}
func (d *DNSDriver) Create(ctx context.Context, spec interfaces.ResourceSpec) (*interfaces.ResourceOutput, error) {
	domain, err := domainFromSpec(spec)
	if err != nil {
		return nil, err
	}
	desired, err := declaredRecords(spec.Config)
	if err != nil {
		return nil, err
	}
	if err := d.upsertRecords(ctx, domain, desired); err != nil {
		return nil, err
	}
	return d.readOutput(ctx, domain, spec.Name)
}

func (d *DNSDriver) Read(ctx context.Context, ref interfaces.ResourceRef) (*interfaces.ResourceOutput, error) {
	return d.readOutput(ctx, ref.ProviderID, ref.Name)
}

func (d *DNSDriver) Update(ctx context.Context, ref interfaces.ResourceRef, spec interfaces.ResourceSpec) (*interfaces.ResourceOutput, error) {
	domain, err := domainFromSpec(spec)
	if err != nil {
		return nil, err
	}
	if ref.ProviderID != "" && !strings.EqualFold(domain, ref.ProviderID) {
		return nil, fmt.Errorf("hover dns: cannot rename zone from %q to %q — delete and re-create", ref.ProviderID, domain)
	}
	desired, err := declaredRecords(spec.Config)
	if err != nil {
		return nil, err
	}
	if err := d.upsertRecords(ctx, domain, desired); err != nil {
		return nil, err
	}
	return d.readOutput(ctx, domain, spec.Name)
}

func (d *DNSDriver) Delete(_ context.Context, _ interfaces.ResourceRef) error {
	// Hover does not expose a "delete zone" API.
	// Deleting individual records is possible but not done here because the
	// zone itself (the domain registration) must be managed outside the IaC
	// surface. Destroying infra.dns is therefore a no-op; operators must
	// manually remove records they no longer need.
	return nil
}

func (d *DNSDriver) Diff(_ context.Context, desired interfaces.ResourceSpec, current *interfaces.ResourceOutput) (*interfaces.DiffResult, error) {
	// Validate the desired spec up front so config errors surface at
	// Plan time, even for brand-new resources (current == nil) where
	// the engine would otherwise just see NeedsUpdate=true and let
	// Apply discover the same problem one stage later. declaredRecords
	// also covers the "config.records is required" check.
	desiredRecs, err := declaredRecords(desired.Config)
	if err != nil {
		return nil, err
	}

	if current == nil {
		return &interfaces.DiffResult{NeedsUpdate: true}, nil
	}

	desiredDomain, hasDomain, err := domainFromConfigIfPresent(desired.Config)
	if err != nil {
		return nil, err
	}
	if hasDomain && !strings.EqualFold(desiredDomain, current.ProviderID) {
		return &interfaces.DiffResult{
			NeedsUpdate:  true,
			NeedsReplace: true,
			Changes: []interfaces.FieldChange{
				{Path: "domain", Old: current.ProviderID, New: desiredDomain, ForceNew: true},
			},
		}, nil
	}

	currentRecs, err := dnsRecordsFromOutput(current)
	if err != nil {
		return nil, err
	}

	// Empty desired record set with no current records → in sync.
	// Empty desired with leftover current records → drift (everything
	// extra needs deletion); upsertRecords prunes them during apply.
	if len(desiredRecs) == 0 {
		if len(currentRecs) == 0 {
			return &interfaces.DiffResult{NeedsUpdate: false}, nil
		}
		return &interfaces.DiffResult{NeedsUpdate: true}, nil
	}

	// Index current records by (type, name) for O(1) lookup. Multiple
	// records sharing the same (type, name) — e.g., several A or
	// AAAA records on the apex — are accumulated in the candidate
	// slice and matched against desired records by exact Content
	// (and TTL when specified) rather than by slice position. Each
	// match consumes one candidate to preserve multiset semantics.
	currentByKey := make(map[string][]hover.DNSRecord)
	for _, r := range currentRecs {
		key := recordKey(r.Type, r.Name)
		currentByKey[key] = append(currentByKey[key], r)
	}

	for _, dr := range desiredRecs {
		key := recordKey(dr.Type, dr.Name)
		candidates := currentByKey[key]
		idx := -1
		for i, cur := range candidates {
			if cur.Content != dr.Content {
				continue
			}
			// TTL is part of the record's effective state. Only consider
			// it when the desired record specifies one (TTL == 0 means
			// "leave the existing TTL alone" per upsertRecords).
			if dr.TTL != 0 && cur.TTL != dr.TTL {
				continue
			}
			idx = i
			break
		}
		if idx < 0 {
			return &interfaces.DiffResult{NeedsUpdate: true}, nil
		}
		// Remove the matched candidate so subsequent desired records
		// can't re-match it.
		currentByKey[key] = append(candidates[:idx], candidates[idx+1:]...)
	}
	// Any remaining candidates are records that exist upstream but
	// are not in the desired set. Treat that as drift so Plan
	// surfaces the change to the operator; upsertRecords prunes
	// them during apply.
	for _, leftover := range currentByKey {
		if len(leftover) > 0 {
			return &interfaces.DiffResult{NeedsUpdate: true}, nil
		}
	}
	return &interfaces.DiffResult{NeedsUpdate: false}, nil
}

func (d *DNSDriver) HealthCheck(ctx context.Context, ref interfaces.ResourceRef) (*interfaces.HealthResult, error) {
	_, err := d.client.ListRecords(ctx, ref.ProviderID)
	if err != nil {
		return &interfaces.HealthResult{Healthy: false, Message: err.Error()}, nil
	}
	return &interfaces.HealthResult{Healthy: true}, nil
}

func (d *DNSDriver) Scale(_ context.Context, _ interfaces.ResourceRef, _ int) (*interfaces.ResourceOutput, error) {
	return nil, fmt.Errorf("hover dns: scale is not supported")
}

func (d *DNSDriver) SensitiveKeys() []string { return nil }

func (d *DNSDriver) ProviderIDFormat() interfaces.ProviderIDFormat {
	return interfaces.IDFormatDomainName
}

// ── helpers ──────────────────────────────────────────────────────────────────

func (d *DNSDriver) readOutput(ctx context.Context, domain, name string) (*interfaces.ResourceOutput, error) {
	recs, err := d.client.ListRecords(ctx, domain)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, fmt.Errorf("%w: hover dns zone %q", interfaces.ErrResourceNotFound, domain)
		}
		return nil, fmt.Errorf("hover dns read %q: %w", domain, err)
	}
	return dnsOutput(domain, name, recs), nil
}

func (d *DNSDriver) upsertRecords(ctx context.Context, domain string, desired []hover.DNSRecord) error {
	// An empty desired set means "drop everything" — fall through into
	// the prune step rather than short-circuiting. Without this, an
	// explicit `records: []` would still leave upstream records intact.

	// Hover's POST /api/dns endpoint requires `domain_id` (hover-assigned
	// numeric ID), NOT the apex name. Resolve the domain up front via
	// GetDomain, which returns both the ID and the current record set;
	// reuse the embedded record set to avoid a second ListRecords round trip.
	dom, err := d.client.GetDomain(ctx, domain)
	if err != nil {
		return fmt.Errorf("hover dns resolve domain %q: %w", domain, err)
	}

	existingByKey := make(map[string][]hover.DNSRecord)
	for _, r := range dom.Records {
		key := recordKey(r.Type, r.Name)
		existingByKey[key] = append(existingByKey[key], r)
	}

	// Two-pass match. First pass: skip any desired record that ALREADY
	// has an exact-content (and TTL when specified) match upstream —
	// no work needed. Consume those candidates so they can't be
	// re-used by the update pass. Second pass: every remaining
	// desired record either updates a leftover same-key candidate
	// (Content/TTL change on an existing record) or creates a new one.
	//
	// Without this two-pass split the previous code matched
	// candidates[0] every time and could update one record's content
	// to a value that another already-fine record holds — producing
	// a transient state with two identical records. Diff would still
	// converge eventually, but apply would do unnecessary writes and
	// could fail under multi-record configs.
	deferredUpdates := make([]hover.DNSRecord, 0, len(desired))
	for _, dr := range desired {
		key := recordKey(dr.Type, dr.Name)
		candidates := existingByKey[key]
		matched := -1
		for i, c := range candidates {
			if c.Content != dr.Content {
				continue
			}
			if dr.TTL != 0 && c.TTL != dr.TTL {
				continue
			}
			matched = i
			break
		}
		if matched >= 0 {
			existingByKey[key] = append(candidates[:matched], candidates[matched+1:]...)
			continue
		}
		deferredUpdates = append(deferredUpdates, dr)
	}

	for _, dr := range deferredUpdates {
		key := recordKey(dr.Type, dr.Name)
		candidates := existingByKey[key]
		if len(candidates) > 0 {
			ex := candidates[0]
			existingByKey[key] = candidates[1:]
			if err := d.client.UpdateRecord(ctx, ex.ID, dr); err != nil {
				return fmt.Errorf("hover dns update %s/%s %q: %w", dr.Type, dr.Name, domain, err)
			}
		} else {
			if _, err := d.client.CreateRecord(ctx, dom.ID, dr); err != nil {
				return fmt.Errorf("hover dns create %s/%s %q: %w", dr.Type, dr.Name, domain, err)
			}
			// Do NOT add the created record back into existingByKey.
			// existingByKey is the upstream set we're reconciling
			// against; the create is a NEW record, not a leftover.
			// Adding it would trip the prune sweep below and delete
			// the record we just created.
		}
	}

	// Prune: any candidates still in existingByKey after both passes
	// are upstream records that no longer appear in the desired config.
	// Delete them so the upstream zone converges to the declared set.
	// (Hover has no whole-zone replace API; this per-record delete is
	// the only path to convergence.)
	for _, leftovers := range existingByKey {
		for _, orphan := range leftovers {
			if err := d.client.DeleteRecord(ctx, orphan.ID); err != nil {
				return fmt.Errorf("hover dns prune %s/%s %q (id=%s): %w", orphan.Type, orphan.Name, domain, orphan.ID, err)
			}
		}
	}
	return nil
}

func domainFromSpec(spec interfaces.ResourceSpec) (string, error) {
	domain, ok, err := domainFromConfigIfPresent(spec.Config)
	if err != nil {
		return "", err
	}
	if !ok {
		domain = spec.Name
	}
	if domain == "" {
		return "", fmt.Errorf("hover dns: domain is required (set config.domain or resource name)")
	}
	return domain, nil
}

func domainFromConfigIfPresent(config map[string]any) (string, bool, error) {
	v, ok := config["domain"]
	if !ok {
		return "", false, nil
	}
	s, ok := v.(string)
	if !ok {
		return "", true, fmt.Errorf("hover dns: config.domain must be a string")
	}
	if s == "" {
		return "", true, fmt.Errorf("hover dns: config.domain must not be empty")
	}
	return s, true, nil
}

// declaredRecords parses config["records"] into a []hover.DNSRecord slice.
//
// `records` is REQUIRED. A missing key errors out — silently coercing
// to an empty slice would let upsertRecords prune every upstream
// record, which is rarely what an operator intends when they forgot
// to set the key. An explicitly empty `records: []` IS allowed (and
// does deliberately prune everything); only the missing-key /
// wrong-type cases are rejected.
func declaredRecords(config map[string]any) ([]hover.DNSRecord, error) {
	raw, present := config["records"]
	if !present {
		return nil, fmt.Errorf("hover dns: config.records is required (use an explicit 'records: []' to drop every record)")
	}
	items, err := toSliceOfMaps(raw)
	if err != nil {
		return nil, fmt.Errorf("hover dns: config.records: %w", err)
	}
	out := make([]hover.DNSRecord, 0, len(items))
	for i, m := range items {
		rec, err := recordFromMap(i, m)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, nil
}

func toSliceOfMaps(v any) ([]map[string]any, error) {
	switch typed := v.(type) {
	case []map[string]any:
		return typed, nil
	case []any:
		out := make([]map[string]any, 0, len(typed))
		for i, item := range typed {
			m, ok := item.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("records[%d] must be an object", i)
			}
			out = append(out, m)
		}
		return out, nil
	default:
		return nil, errors.New("must be a list")
	}
}

func recordFromMap(index int, m map[string]any) (hover.DNSRecord, error) {
	typ, err := requiredString(m, "type", index)
	if err != nil {
		return hover.DNSRecord{}, err
	}
	name, err := requiredString(m, "name", index)
	if err != nil {
		return hover.DNSRecord{}, err
	}
	content, err := requiredString(m, "content", index)
	if err != nil {
		return hover.DNSRecord{}, err
	}
	ttl, err := optionalNonNegativeInt(m, "ttl", index)
	if err != nil {
		return hover.DNSRecord{}, err
	}
	return hover.DNSRecord{
		Type:    strings.ToUpper(typ),
		Name:    name,
		Content: content,
		TTL:     ttl,
	}, nil
}

func requiredString(m map[string]any, key string, index int) (string, error) {
	v, ok := m[key]
	if !ok {
		return "", fmt.Errorf("hover dns: records[%d].%s is required", index, key)
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("hover dns: records[%d].%s must be a non-empty string", index, key)
	}
	return s, nil
}

func optionalInt(m map[string]any, key string) (int, bool) {
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	}
	return 0, false
}

// optionalNonNegativeInt is like optionalInt but rejects values that
// are present but the wrong type or negative, returning a typed error
// instead of silently coercing to 0. Used for record TTL where a
// silent 0 would skip the field in upsertRecords AND mask user typos.
func optionalNonNegativeInt(m map[string]any, key string, index int) (int, error) {
	v, ok := m[key]
	if !ok {
		return 0, nil
	}
	var n int
	switch t := v.(type) {
	case int:
		n = t
	case int64:
		n = int(t)
	case float64:
		// Reject non-integral floats (e.g. 1800.5) — Hover's TTL is
		// integer seconds.
		if t != float64(int64(t)) {
			return 0, fmt.Errorf("hover dns: records[%d].%s = %v must be a non-negative integer", index, key, t)
		}
		n = int(t)
	default:
		return 0, fmt.Errorf("hover dns: records[%d].%s = %v (%T) must be a non-negative integer", index, key, v, v)
	}
	if n < 0 {
		return 0, fmt.Errorf("hover dns: records[%d].%s = %d must be a non-negative integer", index, key, n)
	}
	return n, nil
}

func recordKey(typ, name string) string {
	return strings.ToUpper(typ) + "\x00" + strings.ToLower(name)
}

// dnsRecordsFromOutput deserialises the "records" key from a ResourceOutput
// Outputs map back into []hover.DNSRecord for diffing.
func dnsRecordsFromOutput(out *interfaces.ResourceOutput) ([]hover.DNSRecord, error) {
	if out == nil || out.Outputs == nil {
		return nil, nil
	}
	raw, ok := out.Outputs["records"]
	if !ok || raw == nil {
		return nil, nil
	}
	items, err := toSliceOfMaps(raw)
	if err != nil {
		return nil, fmt.Errorf("hover dns: outputs.records: %w", err)
	}
	recs := make([]hover.DNSRecord, 0, len(items))
	for _, m := range items {
		typ, _ := m["type"].(string)
		name, _ := m["name"].(string)
		content, _ := m["content"].(string)
		ttl, _ := optionalInt(m, "ttl")
		id, _ := m["id"].(string)
		if typ == "" || name == "" {
			continue
		}
		recs = append(recs, hover.DNSRecord{
			ID:      id,
			Type:    typ,
			Name:    name,
			Content: content,
			TTL:     ttl,
		})
	}
	return recs, nil
}

// dnsOutput builds the structpb-safe ResourceOutput for a Hover DNS zone.
// All Outputs values are primitive leaves (string/int/bool) — no typed slices.
// Records are encoded as []map[string]any per the structpb-boundary invariant.
func dnsOutput(domain, name string, records []hover.DNSRecord) *interfaces.ResourceOutput {
	outputs := map[string]any{
		"domain": domain,
	}
	if records != nil {
		recs := make([]any, 0, len(records))
		for _, r := range records {
			entry := map[string]any{
				"id":      r.ID,
				"type":    r.Type,
				"name":    r.Name,
				"content": r.Content,
				"ttl":     r.TTL,
			}
			recs = append(recs, entry)
		}
		outputs["records"] = recs
	}
	return &interfaces.ResourceOutput{
		Name:       name,
		Type:       "infra.dns",
		ProviderID: domain,
		Outputs:    outputs,
		Status:     "active",
	}
}
