package drivers

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-hover/internal/hover"
	"github.com/GoCodeAlone/workflow/interfaces"
)

// fakeClient is a test double for HoverDNSClient.
type fakeClient struct {
	domainID  string // hover-assigned domain ID returned by GetDomain
	records   []hover.DNSRecord
	createErr error
	updateErr error
	deleteErr error
	listErr   error
	nextID    int

	lastCreateDomainID string // captured for assertions
}

func (f *fakeClient) GetDomain(_ context.Context, domain string) (*hover.Domain, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	id := f.domainID
	if id == "" {
		id = "dom1"
	}
	recs := make([]hover.DNSRecord, len(f.records))
	copy(recs, f.records)
	return &hover.Domain{ID: id, Name: domain, Records: recs}, nil
}

func (f *fakeClient) ListRecords(_ context.Context, _ string) ([]hover.DNSRecord, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]hover.DNSRecord, len(f.records))
	copy(out, f.records)
	return out, nil
}

func (f *fakeClient) CreateRecord(_ context.Context, domainID string, rec hover.DNSRecord) (*hover.DNSRecord, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	f.lastCreateDomainID = domainID
	f.nextID++
	rec.ID = fmt.Sprintf("dns%d", f.nextID)
	f.records = append(f.records, rec)
	cp := rec
	return &cp, nil
}

func (f *fakeClient) UpdateRecord(_ context.Context, id string, rec hover.DNSRecord) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	for i, r := range f.records {
		if r.ID == id {
			f.records[i].Content = rec.Content
			if rec.TTL > 0 {
				f.records[i].TTL = rec.TTL
			}
			return nil
		}
	}
	return fmt.Errorf("record %q not found", id)
}

func (f *fakeClient) DeleteRecord(_ context.Context, id string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	for i, r := range f.records {
		if r.ID == id {
			f.records = append(f.records[:i], f.records[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("record %q not found", id)
}

func newDriver(records ...hover.DNSRecord) (*DNSDriver, *fakeClient) {
	fc := &fakeClient{records: records}
	return NewDNSDriverWithClient(fc), fc
}

func TestDNSDriver_Create_Empty(t *testing.T) {
	// Explicitly-empty records list is the supported way to declare
	// "no DNS records on this zone". A missing records key is now an
	// error (would otherwise silently prune everything upstream).
	d, _ := newDriver()
	spec := interfaces.ResourceSpec{Name: "example.com", Type: "infra.dns", Config: map[string]any{"records": []any{}}}
	out, err := d.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if out.ProviderID != "example.com" {
		t.Errorf("ProviderID = %q want %q", out.ProviderID, "example.com")
	}
}

func TestDNSDriver_Create_MissingRecordsKey_Rejected(t *testing.T) {
	d, _ := newDriver()
	spec := interfaces.ResourceSpec{Name: "example.com", Type: "infra.dns", Config: map[string]any{}}
	if _, err := d.Create(context.Background(), spec); err == nil {
		t.Fatal("expected error for missing config.records key")
	}
}

func TestDNSDriver_Create_WithRecords(t *testing.T) {
	d, fc := newDriver()
	spec := interfaces.ResourceSpec{
		Name: "example.com", Type: "infra.dns",
		Config: map[string]any{
			"records": []any{
				map[string]any{"type": "A", "name": "@", "content": "1.2.3.4", "ttl": 300},
			},
		},
	}
	out, err := d.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(fc.records) != 1 {
		t.Errorf("client.records len = %d want 1", len(fc.records))
	}
	recs, ok := out.Outputs["records"].([]any)
	if !ok || len(recs) != 1 {
		t.Errorf("outputs.records: %v", out.Outputs["records"])
	}
}

func TestDNSDriver_Create_UpdatesExistingRecord(t *testing.T) {
	existing := hover.DNSRecord{ID: "r1", Type: "A", Name: "@", Content: "1.1.1.1", TTL: 300}
	d, fc := newDriver(existing)

	spec := interfaces.ResourceSpec{
		Name: "example.com", Type: "infra.dns",
		Config: map[string]any{
			"records": []any{
				map[string]any{"type": "A", "name": "@", "content": "2.2.2.2"},
			},
		},
	}
	_, err := d.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if fc.records[0].Content != "2.2.2.2" {
		t.Errorf("record not updated: content=%q", fc.records[0].Content)
	}
}

func TestDNSDriver_Diff_NilCurrent(t *testing.T) {
	// Diff now validates config.records up front so config errors
	// surface at Plan time even for new resources. Use an explicit
	// empty records list to exercise the nil-current early-return path.
	d, _ := newDriver()
	spec := interfaces.ResourceSpec{Name: "example.com", Type: "infra.dns", Config: map[string]any{"records": []any{}}}
	diff, err := d.Diff(context.Background(), spec, nil)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if !diff.NeedsUpdate {
		t.Error("expected NeedsUpdate=true for nil current")
	}
}

func TestDNSDriver_Diff_MissingRecordsKey_ErrorsAtPlanTime(t *testing.T) {
	d, _ := newDriver()
	spec := interfaces.ResourceSpec{Name: "example.com", Type: "infra.dns", Config: map[string]any{}}
	if _, err := d.Diff(context.Background(), spec, nil); err == nil {
		t.Fatal("expected error for missing config.records at Plan time")
	}
}

func TestDNSDriver_Diff_UpToDate(t *testing.T) {
	d, _ := newDriver()
	spec := interfaces.ResourceSpec{
		Name: "example.com", Type: "infra.dns",
		Config: map[string]any{
			"records": []any{
				map[string]any{"type": "A", "name": "@", "content": "1.2.3.4"},
			},
		},
	}
	current := &interfaces.ResourceOutput{
		ProviderID: "example.com",
		Outputs: map[string]any{
			"records": []any{
				map[string]any{"id": "r1", "type": "A", "name": "@", "content": "1.2.3.4", "ttl": 300},
			},
		},
	}
	diff, err := d.Diff(context.Background(), spec, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if diff.NeedsUpdate {
		t.Error("expected NeedsUpdate=false for up-to-date state")
	}
}

func TestDNSDriver_Diff_RecordChanged(t *testing.T) {
	d, _ := newDriver()
	spec := interfaces.ResourceSpec{
		Name: "example.com", Type: "infra.dns",
		Config: map[string]any{
			"records": []any{
				map[string]any{"type": "A", "name": "@", "content": "9.9.9.9"},
			},
		},
	}
	current := &interfaces.ResourceOutput{
		ProviderID: "example.com",
		Outputs: map[string]any{
			"records": []any{
				map[string]any{"id": "r1", "type": "A", "name": "@", "content": "1.1.1.1", "ttl": 300},
			},
		},
	}
	diff, err := d.Diff(context.Background(), spec, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if !diff.NeedsUpdate {
		t.Error("expected NeedsUpdate=true for changed record")
	}
}

func TestDNSDriver_Diff_DomainChange_ForceReplace(t *testing.T) {
	d, _ := newDriver()
	spec := interfaces.ResourceSpec{
		Name:   "new.com",
		Type:   "infra.dns",
		Config: map[string]any{"domain": "new.com", "records": []any{}},
	}
	current := &interfaces.ResourceOutput{ProviderID: "old.com"}
	diff, err := d.Diff(context.Background(), spec, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if !diff.NeedsReplace {
		t.Error("expected NeedsReplace=true for domain change")
	}
}

func TestDNSDriver_Read_NotFound(t *testing.T) {
	d, fc := newDriver()
	fc.listErr = errors.New("not found: no such domain")
	_, err := d.Read(context.Background(), interfaces.ResourceRef{Name: "gone.com", ProviderID: "gone.com"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, interfaces.ErrResourceNotFound) {
		t.Errorf("want ErrResourceNotFound wrapping, got: %v", err)
	}
}

func TestDNSDriver_Update_DomainRenameRejected(t *testing.T) {
	d, _ := newDriver()
	spec := interfaces.ResourceSpec{
		Name: "new.com", Type: "infra.dns",
		Config: map[string]any{"domain": "new.com", "records": []any{}},
	}
	ref := interfaces.ResourceRef{Name: "old.com", ProviderID: "old.com"}
	_, err := d.Update(context.Background(), ref, spec)
	if err == nil {
		t.Fatal("expected error for domain rename")
	}
}

func TestDNSDriver_Delete_NoOp(t *testing.T) {
	d, _ := newDriver(hover.DNSRecord{ID: "r1", Type: "A", Name: "@", Content: "1.1.1.1"})
	err := d.Delete(context.Background(), interfaces.ResourceRef{Name: "example.com", ProviderID: "example.com"})
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestDNSDriver_HealthCheck_Healthy(t *testing.T) {
	d, _ := newDriver()
	h, err := d.HealthCheck(context.Background(), interfaces.ResourceRef{ProviderID: "example.com"})
	if err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}
	if !h.Healthy {
		t.Error("expected healthy")
	}
}

func TestDNSDriver_HealthCheck_Unhealthy(t *testing.T) {
	d, fc := newDriver()
	fc.listErr = errors.New("API down")
	h, err := d.HealthCheck(context.Background(), interfaces.ResourceRef{ProviderID: "example.com"})
	if err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}
	if h.Healthy {
		t.Error("expected unhealthy")
	}
}

func TestDNSDriver_Scale_Unsupported(t *testing.T) {
	d, _ := newDriver()
	_, err := d.Scale(context.Background(), interfaces.ResourceRef{}, 2)
	if err == nil {
		t.Fatal("expected error from Scale")
	}
}

func TestDNSDriver_SensitiveKeys(t *testing.T) {
	d, _ := newDriver()
	if keys := d.SensitiveKeys(); keys != nil {
		t.Errorf("SensitiveKeys = %v; want nil", keys)
	}
}

func TestDeclaredRecords_BadType(t *testing.T) {
	_, err := declaredRecords(map[string]any{"records": "not-a-list"})
	if err == nil {
		t.Fatal("expected error for non-list records")
	}
}

func TestDeclaredRecords_MissingType(t *testing.T) {
	_, err := declaredRecords(map[string]any{
		"records": []any{
			map[string]any{"name": "@", "content": "1.1.1.1"},
		},
	})
	if err == nil {
		t.Fatal("expected error for missing type")
	}
}

func TestDNSOutput_Structpb(t *testing.T) {
	records := []hover.DNSRecord{
		{ID: "r1", Type: "A", Name: "@", Content: "1.2.3.4", TTL: 300},
	}
	out := dnsOutput("example.com", "my-zone", records)
	// outputs["records"] must be []any, not []hover.DNSRecord,
	// to be structpb-safe.
	recs, ok := out.Outputs["records"].([]any)
	if !ok {
		t.Fatalf("outputs.records must be []any for structpb safety; got %T", out.Outputs["records"])
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	entry, ok := recs[0].(map[string]any)
	if !ok {
		t.Fatalf("record entry must be map[string]any; got %T", recs[0])
	}
	if entry["type"] != "A" || entry["name"] != "@" || entry["content"] != "1.2.3.4" {
		t.Errorf("unexpected record entry: %v", entry)
	}
}

// TestUpsertRecords_UsesDomainIDNotName regresses a bug where Create
// was passing the apex domain name into the Hover POST /api/dns
// `domain_id` form field, which Hover rejects (it requires the
// numeric hover-assigned ID). After the fix, upsertRecords resolves
// the domain ID via GetDomain and passes it to CreateRecord.
func TestUpsertRecords_UsesDomainIDNotName(t *testing.T) {
	fc := &fakeClient{
		domainID: "1234567",
		records:  nil, // empty → upsertRecords will Create
	}
	d := NewDNSDriverWithClient(fc)
	spec := interfaces.ResourceSpec{
		Name: "example.com",
		Type: "infra.dns",
		Config: map[string]any{
			"domain": "example.com",
			"records": []any{
				map[string]any{"type": "A", "name": "@", "content": "1.2.3.4", "ttl": 1800},
			},
		},
	}
	if _, err := d.Create(context.Background(), spec); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if fc.lastCreateDomainID != "1234567" {
		t.Fatalf("CreateRecord called with domain_id=%q, want %q (hover-assigned numeric ID)",
			fc.lastCreateDomainID, "1234567")
	}
}

// TestDiff_TTLChange_DetectedAsUpdate regresses a bug where Diff
// compared only Content, missing TTL changes — Update would never
// fire even though upsertRecords would have applied a new TTL.
func TestDiff_TTLChange_DetectedAsUpdate(t *testing.T) {
	current := &interfaces.ResourceOutput{
		ProviderID: "example.com",
		Outputs: map[string]any{
			"records": []any{
				map[string]any{"type": "A", "name": "@", "content": "1.2.3.4", "ttl": float64(1800), "id": "dns1"},
			},
		},
	}
	spec := interfaces.ResourceSpec{
		Name: "example.com",
		Type: "infra.dns",
		Config: map[string]any{
			"domain": "example.com",
			"records": []any{
				map[string]any{"type": "A", "name": "@", "content": "1.2.3.4", "ttl": 3600},
			},
		},
	}
	d := NewDNSDriverWithClient(&fakeClient{})
	res, err := d.Diff(context.Background(), spec, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if !res.NeedsUpdate {
		t.Fatal("expected NeedsUpdate=true for TTL change")
	}
}

// TestDiff_MultipleARecords_OrderingDoesNotMatter regresses a bug where
// Diff matched candidates[0] only and could falsely report NeedsUpdate
// when multiple records share the same (type, name) but appear in a
// different order between current and desired.
func TestDiff_MultipleARecords_OrderingDoesNotMatter(t *testing.T) {
	d, _ := newDriver()
	spec := interfaces.ResourceSpec{
		Name: "example.com", Type: "infra.dns",
		Config: map[string]any{
			"records": []any{
				map[string]any{"type": "A", "name": "@", "content": "1.1.1.1"},
				map[string]any{"type": "A", "name": "@", "content": "2.2.2.2"},
			},
		},
	}
	// Current returns the same set but in reverse order.
	current := &interfaces.ResourceOutput{
		ProviderID: "example.com",
		Outputs: map[string]any{
			"records": []any{
				map[string]any{"id": "r2", "type": "A", "name": "@", "content": "2.2.2.2"},
				map[string]any{"id": "r1", "type": "A", "name": "@", "content": "1.1.1.1"},
			},
		},
	}
	diff, err := d.Diff(context.Background(), spec, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if diff.NeedsUpdate {
		t.Error("expected NeedsUpdate=false for same multiset of records (order-independent)")
	}
}

func TestRecordFromMap_InvalidTTL_Rejected(t *testing.T) {
	// Negative TTL must surface as a typed error rather than coerce to 0.
	_, err := recordFromMap(0, map[string]any{
		"type":    "A",
		"name":    "@",
		"content": "1.2.3.4",
		"ttl":     -1,
	})
	if err == nil {
		t.Fatal("expected error for negative TTL")
	}
}

func TestRecordFromMap_NonIntegralTTL_Rejected(t *testing.T) {
	// Floats that aren't whole numbers (e.g., 300.5) must error.
	_, err := recordFromMap(0, map[string]any{
		"type":    "A",
		"name":    "@",
		"content": "1.2.3.4",
		"ttl":     300.5,
	})
	if err == nil {
		t.Fatal("expected error for non-integral float TTL")
	}
}

func TestRecordFromMap_StringTTL_Rejected(t *testing.T) {
	_, err := recordFromMap(0, map[string]any{
		"type":    "A",
		"name":    "@",
		"content": "1.2.3.4",
		"ttl":     "300",
	})
	if err == nil {
		t.Fatal("expected error for string TTL")
	}
}

// TestDiff_ExtraCurrentRecord_DetectedAsUpdate regresses a bug where
// Diff only checked desired ⊆ current, missing records that exist
// upstream but were removed from desired. Removing a record from
// config must show up in Plan even though upsertRecords doesn't
// currently prune them (separate follow-up).
func TestDiff_ExtraCurrentRecord_DetectedAsUpdate(t *testing.T) {
	d, _ := newDriver()
	spec := interfaces.ResourceSpec{
		Name: "example.com", Type: "infra.dns",
		Config: map[string]any{
			"records": []any{
				map[string]any{"type": "A", "name": "@", "content": "1.1.1.1"},
			},
		},
	}
	current := &interfaces.ResourceOutput{
		ProviderID: "example.com",
		Outputs: map[string]any{
			"records": []any{
				map[string]any{"id": "r1", "type": "A", "name": "@", "content": "1.1.1.1"},
				map[string]any{"id": "r2", "type": "A", "name": "www", "content": "1.1.1.1"},
			},
		},
	}
	diff, err := d.Diff(context.Background(), spec, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if !diff.NeedsUpdate {
		t.Error("expected NeedsUpdate=true when current has an extra record")
	}
}

func TestDiff_EmptyDesired_WithCurrentRecords_NeedsUpdate(t *testing.T) {
	d, _ := newDriver()
	spec := interfaces.ResourceSpec{
		Name: "example.com", Type: "infra.dns",
		Config: map[string]any{"records": []any{}},
	}
	current := &interfaces.ResourceOutput{
		ProviderID: "example.com",
		Outputs: map[string]any{
			"records": []any{
				map[string]any{"id": "r1", "type": "A", "name": "@", "content": "1.1.1.1"},
			},
		},
	}
	diff, err := d.Diff(context.Background(), spec, current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if !diff.NeedsUpdate {
		t.Error("expected NeedsUpdate=true when desired is empty but current has records")
	}
}

// TestUpsertRecords_PrunesExtraRecords verifies that records in the
// upstream zone that don't appear in the desired config are deleted
// during apply. Regresses the "no prune on apply" gap that left
// removed records as orphans upstream.
func TestUpsertRecords_PrunesExtraRecords(t *testing.T) {
	fc := &fakeClient{
		records: []hover.DNSRecord{
			{ID: "r1", Type: "A", Name: "@", Content: "1.1.1.1"},
			{ID: "r2", Type: "A", Name: "www", Content: "1.1.1.1"}, // orphan
		},
	}
	d := NewDNSDriverWithClient(fc)
	spec := interfaces.ResourceSpec{
		Name: "example.com", Type: "infra.dns",
		Config: map[string]any{
			"records": []any{
				map[string]any{"type": "A", "name": "@", "content": "1.1.1.1"},
			},
		},
	}
	if _, err := d.Update(context.Background(), interfaces.ResourceRef{Name: "example.com", ProviderID: "example.com"}, spec); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if len(fc.records) != 1 {
		t.Fatalf("expected upstream to converge to 1 record after prune; got %d: %+v", len(fc.records), fc.records)
	}
	if fc.records[0].Name != "@" {
		t.Errorf("expected the apex record to remain; got %+v", fc.records[0])
	}
}

func TestUpsertRecords_EmptyDesiredDeletesAll(t *testing.T) {
	fc := &fakeClient{
		records: []hover.DNSRecord{
			{ID: "r1", Type: "A", Name: "@", Content: "1.1.1.1"},
			{ID: "r2", Type: "A", Name: "www", Content: "1.1.1.1"},
		},
	}
	d := NewDNSDriverWithClient(fc)
	spec := interfaces.ResourceSpec{
		Name: "example.com", Type: "infra.dns",
		Config: map[string]any{"records": []any{}},
	}
	if _, err := d.Update(context.Background(), interfaces.ResourceRef{Name: "example.com", ProviderID: "example.com"}, spec); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if len(fc.records) != 0 {
		t.Errorf("expected all upstream records pruned; got %d: %+v", len(fc.records), fc.records)
	}
}

func TestDNSDriver_Diff_MissingDomain_ErrorsAtPlanTime(t *testing.T) {
	// No name + no config.domain → domainFromSpec returns error.
	// Diff must surface that before short-circuiting on nil current.
	d, _ := newDriver()
	spec := interfaces.ResourceSpec{
		Type:   "infra.dns",
		Config: map[string]any{"records": []any{}},
	}
	if _, err := d.Diff(context.Background(), spec, nil); err == nil {
		t.Fatal("expected error for missing domain at Plan time")
	}
}
