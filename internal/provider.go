// Package internal implements the Hover IaC provider. Hover has no official
// API; this plugin uses the browser-side session flow (see
// internal/hover/client.go).
package internal

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/GoCodeAlone/workflow-plugin-hover/internal/drivers"
	"github.com/GoCodeAlone/workflow-plugin-hover/pkg/hoverclient"
	"github.com/GoCodeAlone/workflow/interfaces"
	"github.com/GoCodeAlone/workflow/platform"
)

// Version is set at build time via -ldflags.
var Version = "0.0.0"

// hoverDomainLister is the minimal account-level surface EnumerateAll needs.
// *hoverclient.Client satisfies this interface via the ListDomains method
// added in pkg/hoverclient; the test fake (fakeHoverClient) satisfies it
// the same way without spinning up the real login flow.
type hoverDomainLister interface {
	ListDomains(ctx context.Context) ([]hoverclient.Domain, error)
}

// HoverProvider implements interfaces.IaCProvider for Hover.
// Supports two resource types:
//   - infra.dns           — DNS records within Hover's nameservers.
//   - infra.dns_delegation — registrar-level nameserver delegation.
type HoverProvider struct {
	client  *hoverclient.Client
	drivers map[string]interfaces.ResourceDriver
	// domains is the injected account-level domain lister used by EnumerateAll.
	// Defaults to client (which now satisfies hoverDomainLister); tests
	// override with a fakeHoverClient.
	domains hoverDomainLister
	// browserOpts holds the resolved browser configuration for the client.
	// Populated by Initialize; exposed for test assertions.
	browserOpts hoverclient.BrowserOptions
}

var _ interfaces.IaCProvider = (*HoverProvider)(nil)

// NewHoverProvider creates an uninitialised HoverProvider.
func NewHoverProvider() *HoverProvider { return &HoverProvider{} }

func (p *HoverProvider) Name() string    { return "hover" }
func (p *HoverProvider) Version() string { return Version }

// Initialize parses provider config and constructs a lazy Hover client.
// Required keys:
//
//	username     — Hover account username / email
//	password     — Hover account password
//
// Optional keys:
//
//	totp_secret        — Base32-encoded TOTP seed (required if the account has
//	                     MFA enabled; safe to omit when MFA is off)
//	browser_path       — Absolute path to the Chrome/Chromium binary.
//	                     Falls back to HOVER_BROWSER_PATH env var, then auto-discovery.
//	browser_download   — Boolean; allow rod to download Chromium if none found.
//	                     Falls back to HOVER_BROWSER_DOWNLOAD env var (default true).
//	browser_headless   — Boolean; run Chrome in headless mode.
//	                     Falls back to HOVER_BROWSER_HEADLESS env var (default true).
//	browser_profile_dir — Directory for the persistent Chrome profile (Imperva
//	                     clearance cookies). Falls back to HOVER_BROWSER_PROFILE_DIR
//	                     env var, then ${XDG_STATE_HOME:-$HOME/.local/state}/wfctl/plugins/hover/browser-profile.
func (p *HoverProvider) Initialize(ctx context.Context, config map[string]any) error {
	username, _ := config["username"].(string)
	password, _ := config["password"].(string)
	totpRaw, _ := config["totp_secret"].(string)

	if username == "" {
		return fmt.Errorf("hover: missing required config key 'username'")
	}
	if password == "" {
		return fmt.Errorf("hover: missing required config key 'password'")
	}

	var totpSecret hoverclient.TOTPSecret
	if totpRaw != "" {
		ts, err := hoverclient.ParseBase32(totpRaw)
		if err != nil {
			return fmt.Errorf("hover: invalid totp_secret: %w", err)
		}
		totpSecret = ts
	}

	browserOpts, err := parseBrowserConfig(config)
	if err != nil {
		return fmt.Errorf("hover: browser config: %w", err)
	}

	creds := hoverclient.Credentials{
		Username:   username,
		Password:   password,
		TOTPSecret: totpSecret,
	}
	c, err := hoverclient.NewClientWithOptions(creds, nil, hoverclient.ClientOptions{Browser: browserOpts})
	if err != nil {
		return fmt.Errorf("hover: client init: %w", err)
	}

	p.client = c
	p.domains = c
	p.browserOpts = browserOpts
	p.drivers = map[string]interfaces.ResourceDriver{
		"infra.dns":            drivers.NewDNSDriver(c),
		"infra.dns_delegation": drivers.NewDelegationDriver(c),
	}
	return nil
}

// Capabilities returns the resource types Hover supports.
func (p *HoverProvider) Capabilities() []interfaces.IaCCapabilityDeclaration {
	return []interfaces.IaCCapabilityDeclaration{
		{
			ResourceType: "infra.dns",
			Tier:         1,
			Operations:   []string{"create", "read", "update", "delete"},
		},
		{
			ResourceType: "infra.dns_delegation",
			Tier:         1,
			Operations:   []string{"create", "read", "update", "delete"},
		},
	}
}

// ResourceDriver returns the driver for the given resource type.
func (p *HoverProvider) ResourceDriver(resourceType string) (interfaces.ResourceDriver, error) {
	d, ok := p.drivers[resourceType]
	if !ok {
		return nil, fmt.Errorf("hover: unsupported resource type %q", resourceType)
	}
	return d, nil
}

// Plan delegates to platform.ComputePlan which dispatches driver.Diff per-resource.
func (p *HoverProvider) Plan(ctx context.Context, desired []interfaces.ResourceSpec, current []interfaces.ResourceState) (*interfaces.IaCPlan, error) {
	plan, err := platform.ComputePlan(ctx, p, desired, current)
	if err != nil {
		return nil, err
	}
	filtered := plan.Actions[:0]
	for _, action := range plan.Actions {
		if action.Action == "create" {
			driver, err := p.ResourceDriver(action.Resource.Type)
			if err != nil {
				return nil, err
			}
			diff, err := driver.Diff(ctx, action.Resource, nil)
			if err != nil {
				return nil, fmt.Errorf("hover: create preflight diff %q/%q: %w", action.Resource.Type, action.Resource.Name, err)
			}
			if diff == nil || !diff.NeedsUpdate {
				continue
			}
		}
		filtered = append(filtered, action)
	}
	plan.Actions = filtered
	return &plan, nil
}

// Destroy invokes the per-resource driver Delete for each ref.
// For infra.dns this is a no-op: Hover exposes no API to delete a
// DNS zone (only individual records). The resource is marked
// "destroyed" in IaC state because workflow has nothing further to
// reconcile, but the upstream records remain in Hover. Operators
// who want to drop all records must do so manually via the Hover
// control panel.
func (p *HoverProvider) Destroy(ctx context.Context, resources []interfaces.ResourceRef) (*interfaces.DestroyResult, error) {
	result := &interfaces.DestroyResult{}
	for _, ref := range resources {
		d, err := p.ResourceDriver(ref.Type)
		if err != nil {
			result.Errors = append(result.Errors, interfaces.ActionError{
				Resource: ref.Name, Action: "delete", Error: err.Error(),
			})
			continue
		}
		if err := d.Delete(ctx, ref); err != nil {
			result.Errors = append(result.Errors, interfaces.ActionError{
				Resource: ref.Name, Action: "delete", Error: err.Error(),
			})
			continue
		}
		result.Destroyed = append(result.Destroyed, ref.Name)
	}
	return result, nil
}

// Status returns the live status of the given refs.
func (p *HoverProvider) Status(ctx context.Context, resources []interfaces.ResourceRef) ([]interfaces.ResourceStatus, error) {
	var statuses []interfaces.ResourceStatus
	for _, ref := range resources {
		d, err := p.ResourceDriver(ref.Type)
		if err != nil {
			statuses = append(statuses, interfaces.ResourceStatus{
				Name: ref.Name, Type: ref.Type, ProviderID: ref.ProviderID, Status: "unknown",
			})
			continue
		}
		out, err := d.Read(ctx, ref)
		if err != nil {
			statuses = append(statuses, interfaces.ResourceStatus{
				Name: ref.Name, Type: ref.Type, ProviderID: ref.ProviderID, Status: "unknown",
			})
			continue
		}
		statuses = append(statuses, interfaces.ResourceStatus{
			Name: out.Name, Type: out.Type, ProviderID: out.ProviderID,
			Status: out.Status, Outputs: out.Outputs,
		})
	}
	return statuses, nil
}

// DetectDrift checks for ghost resources (state has entry, cloud says 404).
func (p *HoverProvider) DetectDrift(ctx context.Context, resources []interfaces.ResourceRef) ([]interfaces.DriftResult, error) {
	var results []interfaces.DriftResult
	for _, ref := range resources {
		d, err := p.ResourceDriver(ref.Type)
		if err != nil {
			results = append(results, interfaces.DriftResult{
				Name: ref.Name, Type: ref.Type, Drifted: true,
				Class:  interfaces.DriftClassUnknown,
				Fields: []string{"provider: " + err.Error()},
			})
			continue
		}
		_, err = d.Read(ctx, ref)
		if err != nil {
			if isNotFound(err) {
				results = append(results, interfaces.DriftResult{
					Name: ref.Name, Type: ref.Type, Drifted: true,
					Class: interfaces.DriftClassGhost,
				})
				continue
			}
			return nil, fmt.Errorf("hover DetectDrift %q: %w", ref.Name, err)
		}
		results = append(results, interfaces.DriftResult{
			Name: ref.Name, Type: ref.Type, Drifted: false,
			Class: interfaces.DriftClassInSync,
		})
	}
	return results, nil
}

// Import reads an existing Hover-managed resource and returns IaC adoption
// state. cloudID is the domain name for both infra.dns and infra.dns_delegation.
func (p *HoverProvider) Import(ctx context.Context, cloudID string, resourceType string) (*interfaces.ResourceState, error) {
	if cloudID == "" {
		return nil, fmt.Errorf("hover import: provider_id is required")
	}
	if resourceType == "" {
		resourceType = "infra.dns"
	}
	d, err := p.ResourceDriver(resourceType)
	if err != nil {
		return nil, err
	}
	out, err := d.Read(ctx, interfaces.ResourceRef{Name: cloudID, Type: resourceType, ProviderID: cloudID})
	if err != nil {
		return nil, fmt.Errorf("hover import %q: %w", cloudID, err)
	}
	if out == nil {
		return nil, fmt.Errorf("hover import %q: driver returned nil output", cloudID)
	}
	now := time.Now()
	id := out.ProviderID
	if id == "" {
		id = cloudID
	}
	return &interfaces.ResourceState{
		ID:                  id,
		Name:                out.Name,
		Type:                out.Type,
		Provider:            "hover",
		ProviderID:          id,
		AppliedConfigSource: "adoption",
		Outputs:             out.Outputs,
		CreatedAt:           now,
		UpdatedAt:           now,
	}, nil
}

// ResolveSizing is a stub: Hover has no compute sizing.
func (p *HoverProvider) ResolveSizing(_ string, _ interfaces.Size, _ *interfaces.ResourceHints) (*interfaces.ProviderSizing, error) {
	return nil, fmt.Errorf("hover: ResolveSizing is not supported")
}

// BootstrapStateBackend is a stub: Hover does not manage state backends.
func (p *HoverProvider) BootstrapStateBackend(_ context.Context, _ map[string]any) (*interfaces.BootstrapResult, error) {
	return nil, nil
}

// SupportedCanonicalKeys returns the full canonical key set; Hover maps only
// the dns-relevant subset but there's no harm reporting all to the validator.
func (p *HoverProvider) SupportedCanonicalKeys() []string {
	return interfaces.CanonicalKeys()
}

// Close is a no-op; the HTTP client has no persistent connections to tear down.
func (p *HoverProvider) Close() error { return nil }

// EnumerateAll implements interfaces.EnumeratorAll for resource type
// "infra.dns". Walks the account's zones via the injected hoverDomainLister
// (production wraps *hoverclient.Client.ListDomains — added in pkg/hoverclient
// for the cross-repo cascade). Each *ResourceOutput carries the zone name +
// hover-assigned domain_id so the downstream IaCProvider.Import path can
// adopt the zone without re-querying the account list.
//
// Domains with empty Name are dropped rather than emitted with empty
// ProviderID — guards against bogus state-store entries if the Hover
// account-page ever returns a malformed row.
func (p *HoverProvider) EnumerateAll(ctx context.Context, resourceType string) ([]*interfaces.ResourceOutput, error) {
	if p.domains == nil {
		return nil, fmt.Errorf("hover: EnumerateAll called on provider that is not initialized — call Initialize first")
	}
	if resourceType != "infra.dns" {
		return nil, fmt.Errorf("hover: EnumerateAll: resource type %q not supported", resourceType)
	}
	domains, err := p.domains.ListDomains(ctx)
	if err != nil {
		return nil, fmt.Errorf("hover: EnumerateAll infra.dns: %w", err)
	}
	out := make([]*interfaces.ResourceOutput, 0, len(domains))
	for _, d := range domains {
		if d.Name == "" {
			continue
		}
		out = append(out, &interfaces.ResourceOutput{
			ProviderID: d.Name,
			Type:       "infra.dns",
			Outputs: map[string]any{
				"zone":      d.Name,
				"domain_id": d.ID,
			},
		})
	}
	return out, nil
}

// isNotFound recognises a "resource doesn't exist upstream" error.
// The driver wraps these with interfaces.ErrResourceNotFound, so
// prefer the sentinel check via errors.Is. The string fallback
// remains for any non-driver code path (raw Client errors that
// haven't been wrapped) that still reports 404 via message text.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, interfaces.ErrResourceNotFound) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "not found") || strings.Contains(msg, "404")
}

// parseBrowserConfig builds BrowserOptions from the provider config map,
// falling back to HOVER_BROWSER_* env vars (via BrowserOptionsFromEnv),
// and then to DefaultBrowserOptions. Explicit config keys take precedence
// over env vars; env vars take precedence over defaults.
//
// Supported config keys:
//   - browser_path        (string)
//   - browser_download    (bool or "true"/"false" string)
//   - browser_headless    (bool or "true"/"false" string)
//   - browser_profile_dir (string)
func parseBrowserConfig(config map[string]any) (hoverclient.BrowserOptions, error) {
	// Start from env-var layer (which itself falls back to defaults).
	opts, err := hoverclient.BrowserOptionsFromEnv()
	if err != nil {
		return hoverclient.BrowserOptions{}, err
	}

	// Explicit config keys override env vars.
	if v, ok := config["browser_path"].(string); ok && strings.TrimSpace(v) != "" {
		opts.Path = strings.TrimSpace(v)
	}
	if v, ok := config["browser_profile_dir"].(string); ok && strings.TrimSpace(v) != "" {
		opts.ProfileDir = strings.TrimSpace(v)
	}
	if v, ok := config["browser_download"]; ok {
		b, err := parseBoolConfig("browser_download", v)
		if err != nil {
			return hoverclient.BrowserOptions{}, err
		}
		opts.Download = b
	}
	if v, ok := config["browser_headless"]; ok {
		b, err := parseBoolConfig("browser_headless", v)
		if err != nil {
			return hoverclient.BrowserOptions{}, err
		}
		opts.Headless = b
	}
	return opts, nil
}

// parseBoolConfig converts a config value (bool or string) to bool.
func parseBoolConfig(key string, v any) (bool, error) {
	switch val := v.(type) {
	case bool:
		return val, nil
	case string:
		b, err := strconv.ParseBool(strings.TrimSpace(val))
		if err != nil {
			return false, fmt.Errorf("%s must be boolean: %w", key, err)
		}
		return b, nil
	default:
		return false, fmt.Errorf("%s must be boolean, got %T", key, v)
	}
}
