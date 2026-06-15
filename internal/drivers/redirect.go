package drivers

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/GoCodeAlone/workflow-plugin-hover/pkg/hoverclient"
	"github.com/GoCodeAlone/workflow/interfaces"
)

const hoverRedirectResourceType = "infra.http_redirect"

// HoverRedirectClient is the subset of hoverclient.Client used by RedirectDriver.
type HoverRedirectClient interface {
	GetForward(ctx context.Context, domain string) (*hoverclient.DomainForward, error)
	SetForward(ctx context.Context, domain string, forward hoverclient.DomainForward) error
}

// RedirectDriver manages Hover root web forwards.
type RedirectDriver struct {
	client HoverRedirectClient
}

func NewRedirectDriver(c *hoverclient.Client) *RedirectDriver {
	return &RedirectDriver{client: c}
}

func NewRedirectDriverWithClient(c HoverRedirectClient) *RedirectDriver {
	return &RedirectDriver{client: c}
}

func (d *RedirectDriver) SensitiveKeys() []string { return nil }

func (d *RedirectDriver) ProviderIDFormat() interfaces.ProviderIDFormat {
	return interfaces.IDFormatDomainName
}

func (d *RedirectDriver) AdoptionRef(spec interfaces.ResourceSpec) (interfaces.ResourceRef, bool, error) {
	s, err := parseHoverRedirectSpec(spec)
	if err != nil {
		return interfaces.ResourceRef{}, false, err
	}
	return interfaces.ResourceRef{Name: spec.Name, Type: hoverRedirectResourceType, ProviderID: s.domain}, true, nil
}

type hoverRedirectSpec struct {
	domain    string
	fromHost  string
	targetURL string
	stealth   bool
}

func parseHoverRedirectSpec(spec interfaces.ResourceSpec) (hoverRedirectSpec, error) {
	domain := strings.TrimSpace(stringConfig(spec.Config, "domain", spec.Name))
	if domain == "" || !interfaces.ValidateProviderID(domain, interfaces.IDFormatDomainName) {
		return hoverRedirectSpec{}, fmt.Errorf("hover redirect: domain %q is not a valid domain name", domain)
	}
	fromHost := strings.TrimSpace(stringConfig(spec.Config, "from_host", domain))
	if !strings.EqualFold(fromHost, domain) {
		return hoverRedirectSpec{}, fmt.Errorf("hover redirect %q: only root forwards are supported; from_host must equal domain", domain)
	}
	target := strings.TrimSpace(stringConfig(spec.Config, "target_url", ""))
	if target == "" {
		return hoverRedirectSpec{}, fmt.Errorf("hover redirect %q: target_url is required", domain)
	}
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return hoverRedirectSpec{}, fmt.Errorf("hover redirect %q: target_url must be an absolute http(s) URL", domain)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return hoverRedirectSpec{}, fmt.Errorf("hover redirect %q: target_url scheme must be http or https", domain)
	}
	stealth, err := optionalBool(spec.Config, "stealth", false)
	if err != nil {
		return hoverRedirectSpec{}, fmt.Errorf("hover redirect %q: %w", domain, err)
	}
	return hoverRedirectSpec{domain: domain, fromHost: fromHost, targetURL: target, stealth: stealth}, nil
}

func stringConfig(config map[string]any, key, fallback string) string {
	if v, ok := config[key].(string); ok {
		return v
	}
	return fallback
}

func optionalBool(config map[string]any, key string, fallback bool) (bool, error) {
	raw, ok := config[key]
	if !ok {
		return fallback, nil
	}
	v, ok := raw.(bool)
	if !ok {
		return false, fmt.Errorf("%s must be a boolean, got %T", key, raw)
	}
	return v, nil
}

func (s hoverRedirectSpec) forward() hoverclient.DomainForward {
	return hoverclient.DomainForward{
		Domain:  s.domain,
		URL:     s.targetURL,
		Stealth: s.stealth,
	}
}

func hoverRedirectOutput(name string, forward hoverclient.DomainForward) *interfaces.ResourceOutput {
	return &interfaces.ResourceOutput{
		Name:       name,
		Type:       hoverRedirectResourceType,
		ProviderID: forward.Domain,
		Outputs: map[string]any{
			"domain":     forward.Domain,
			"from_host":  forward.Domain,
			"target_url": forward.URL,
			"stealth":    forward.Stealth,
		},
		Status: "active",
	}
}

func (d *RedirectDriver) Create(ctx context.Context, spec interfaces.ResourceSpec) (*interfaces.ResourceOutput, error) {
	return d.reconcile(ctx, interfaces.ResourceRef{Name: spec.Name, Type: hoverRedirectResourceType}, spec)
}

func (d *RedirectDriver) Read(ctx context.Context, ref interfaces.ResourceRef) (*interfaces.ResourceOutput, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("hover redirect read %q: %w", ref.Name, err)
	}
	domain := ref.ProviderID
	if domain == "" {
		domain = ref.Name
	}
	forward, err := d.client.GetForward(ctx, domain)
	if err != nil {
		if errors.Is(err, hoverclient.ErrForwardNotFound) {
			return nil, fmt.Errorf("%w: hover redirect read %q: %w", interfaces.ErrResourceNotFound, ref.Name, err)
		}
		return nil, fmt.Errorf("hover redirect read %q: %w", ref.Name, err)
	}
	return hoverRedirectOutput(ref.Name, *forward), nil
}

func (d *RedirectDriver) Update(ctx context.Context, ref interfaces.ResourceRef, spec interfaces.ResourceSpec) (*interfaces.ResourceOutput, error) {
	return d.reconcile(ctx, ref, spec)
}

func (d *RedirectDriver) reconcile(ctx context.Context, ref interfaces.ResourceRef, spec interfaces.ResourceSpec) (*interfaces.ResourceOutput, error) {
	s, err := parseHoverRedirectSpec(spec)
	if err != nil {
		return nil, err
	}
	currentDomain := ref.ProviderID
	if currentDomain != "" && !strings.EqualFold(s.domain, currentDomain) {
		return nil, fmt.Errorf("hover redirect update %q: spec.domain %q does not match current %q - domain change requires resource replace, not update", ref.Name, s.domain, currentDomain)
	}
	current, err := d.client.GetForward(ctx, s.domain)
	if err != nil && !errors.Is(err, hoverclient.ErrForwardNotFound) {
		return nil, fmt.Errorf("hover redirect update %q: read forward: %w", spec.Name, err)
	}
	if current == nil || !sameHoverForward(*current, s.forward()) {
		desired := s.forward()
		if err := d.client.SetForward(ctx, s.domain, desired); err != nil {
			return nil, fmt.Errorf("hover redirect update %q: set forward: %w", spec.Name, err)
		}
		current = &desired
	}
	return hoverRedirectOutput(spec.Name, *current), nil
}

func sameHoverForward(a, b hoverclient.DomainForward) bool {
	return strings.EqualFold(a.Domain, b.Domain) && strings.TrimSpace(a.URL) == strings.TrimSpace(b.URL) && a.Stealth == b.Stealth
}

func (d *RedirectDriver) Delete(_ context.Context, ref interfaces.ResourceRef) error {
	return fmt.Errorf("hover redirect delete %q: removing forwards is not supported yet", ref.Name)
}

func (d *RedirectDriver) Diff(_ context.Context, desired interfaces.ResourceSpec, current *interfaces.ResourceOutput) (*interfaces.DiffResult, error) {
	s, err := parseHoverRedirectSpec(desired)
	if err != nil {
		return nil, err
	}
	if current == nil {
		return &interfaces.DiffResult{NeedsUpdate: true}, nil
	}
	if current.ProviderID != "" && !strings.EqualFold(s.domain, current.ProviderID) {
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
	changes := make([]interfaces.FieldChange, 0, 2)
	if current.Outputs["target_url"] != s.targetURL {
		changes = append(changes, interfaces.FieldChange{Path: "target_url", Old: current.Outputs["target_url"], New: s.targetURL})
	}
	if current.Outputs["stealth"] != s.stealth {
		changes = append(changes, interfaces.FieldChange{Path: "stealth", Old: current.Outputs["stealth"], New: s.stealth})
	}
	return &interfaces.DiffResult{NeedsUpdate: len(changes) > 0, Changes: changes}, nil
}

func (d *RedirectDriver) HealthCheck(ctx context.Context, ref interfaces.ResourceRef) (*interfaces.HealthResult, error) {
	if _, err := d.Read(ctx, ref); err != nil {
		return &interfaces.HealthResult{Healthy: false, Message: err.Error()}, nil
	}
	return &interfaces.HealthResult{Healthy: true, Message: "ok"}, nil
}

func (d *RedirectDriver) Scale(ctx context.Context, ref interfaces.ResourceRef, _ int) (*interfaces.ResourceOutput, error) {
	return d.Read(ctx, ref)
}
