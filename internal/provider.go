// Package internal implements the Hover IaC provider. Hover has no official
// API; this plugin uses the browser-side session flow (see
// internal/hover/client.go).
package internal

import (
	"context"
	"fmt"
	"strings"

	"github.com/GoCodeAlone/workflow-plugin-hover/internal/drivers"
	"github.com/GoCodeAlone/workflow-plugin-hover/internal/hover"
	"github.com/GoCodeAlone/workflow/interfaces"
	"github.com/GoCodeAlone/workflow/platform"
)

// Version is set at build time via -ldflags.
var Version = "dev"

// HoverProvider implements interfaces.IaCProvider for Hover.
// It supports a single resource type: infra.dns.
type HoverProvider struct {
	client  *hover.Client
	drivers map[string]interfaces.ResourceDriver
}

var _ interfaces.IaCProvider = (*HoverProvider)(nil)

// NewHoverProvider creates an uninitialised HoverProvider.
func NewHoverProvider() *HoverProvider { return &HoverProvider{} }

func (p *HoverProvider) Name() string    { return "hover" }
func (p *HoverProvider) Version() string { return Version }

// Initialize parses provider config and eagerly authenticates with Hover.
// Required keys:
//
//	username     — Hover account username / email
//	password     — Hover account password
//
// Optional keys:
//
//	totp_secret  — Base32-encoded TOTP seed (required if the account has MFA
//	               enabled; safe to omit when MFA is off)
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

	var totpSecret hover.TOTPSecret
	if totpRaw != "" {
		ts, err := hover.ParseBase32(totpRaw)
		if err != nil {
			return fmt.Errorf("hover: invalid totp_secret: %w", err)
		}
		totpSecret = ts
	}

	creds := hover.Credentials{
		Username:   username,
		Password:   password,
		TOTPSecret: totpSecret,
	}
	c, err := hover.NewClient(creds, nil)
	if err != nil {
		return fmt.Errorf("hover: client init: %w", err)
	}

	// Eager login so config errors (bad creds, MFA failure) surface at
	// Configure time rather than at first Plan/Apply invocation.
	if err := c.Login(ctx); err != nil {
		return fmt.Errorf("hover: initial login failed: %w", err)
	}

	p.client = c
	p.drivers = map[string]interfaces.ResourceDriver{
		"infra.dns": drivers.NewDNSDriver(c),
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
	return &plan, err
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

// Import is a stub: Hover does not support resource import via cloud ID.
func (p *HoverProvider) Import(_ context.Context, _ string, _ string) (*interfaces.ResourceState, error) {
	return nil, fmt.Errorf("hover: Import is not supported")
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

func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "not found") || strings.Contains(msg, "404")
}
