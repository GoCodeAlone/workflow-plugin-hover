package drivers

import (
	"context"
	"fmt"
	"strings"

	"github.com/GoCodeAlone/workflow-plugin-hover/pkg/hoverclient"
	"github.com/GoCodeAlone/workflow/interfaces"
)

// HoverDomainClient is the subset of hoverclient.Client used by DomainDriver.
type HoverDomainClient interface {
	GetTransferLock(ctx context.Context, domain string) (bool, error)
	SetTransferLock(ctx context.Context, domain string, locked bool) error
}

// DomainDriver manages registrar-level domain settings for Hover domains.
type DomainDriver struct {
	client HoverDomainClient
}

func NewDomainDriver(c *hoverclient.Client) *DomainDriver {
	return &DomainDriver{client: c}
}

func NewDomainDriverWithClient(c HoverDomainClient) *DomainDriver {
	return &DomainDriver{client: c}
}

func (d *DomainDriver) SensitiveKeys() []string { return nil }

func (d *DomainDriver) ProviderIDFormat() interfaces.ProviderIDFormat {
	return interfaces.IDFormatDomainName
}

func (d *DomainDriver) AdoptionRef(spec interfaces.ResourceSpec) (interfaces.ResourceRef, bool, error) {
	s, err := parseDomainSpec(spec)
	if err != nil {
		return interfaces.ResourceRef{}, false, err
	}
	return interfaces.ResourceRef{
		Name:       spec.Name,
		Type:       "infra.domain",
		ProviderID: s.domain,
	}, true, nil
}

type domainSpec struct {
	domain       string
	transferLock *bool
}

func parseDomainSpec(spec interfaces.ResourceSpec) (domainSpec, error) {
	domain, _ := spec.Config["domain"].(string)
	if domain == "" {
		domain = spec.Name
	}
	if strings.TrimSpace(domain) == "" {
		return domainSpec{}, fmt.Errorf("hover domain: config missing required key 'domain' (or spec.Name)")
	}
	out := domainSpec{domain: strings.TrimSpace(domain)}
	if raw, ok := spec.Config["transfer_lock"]; ok {
		v, ok := raw.(bool)
		if !ok {
			return domainSpec{}, fmt.Errorf("hover domain %q: config 'transfer_lock' must be a boolean, got %T", out.domain, raw)
		}
		out.transferLock = &v
	}
	return out, nil
}

func domainOutput(name, domain string, transferLock bool) *interfaces.ResourceOutput {
	return &interfaces.ResourceOutput{
		Name:       name,
		Type:       "infra.domain",
		ProviderID: domain,
		Outputs: map[string]any{
			"domain":        domain,
			"transfer_lock": transferLock,
		},
		Status: "active",
	}
}

func (d *DomainDriver) Create(ctx context.Context, spec interfaces.ResourceSpec) (*interfaces.ResourceOutput, error) {
	return d.reconcile(ctx, interfaces.ResourceRef{Name: spec.Name, Type: "infra.domain"}, spec)
}

func (d *DomainDriver) Read(ctx context.Context, ref interfaces.ResourceRef) (*interfaces.ResourceOutput, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("hover domain read %q: %w", ref.Name, err)
	}
	domain := ref.ProviderID
	if domain == "" {
		domain = ref.Name
	}
	locked, err := d.client.GetTransferLock(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("hover domain read %q: %w", ref.Name, err)
	}
	return domainOutput(ref.Name, domain, locked), nil
}

func (d *DomainDriver) Update(ctx context.Context, ref interfaces.ResourceRef, spec interfaces.ResourceSpec) (*interfaces.ResourceOutput, error) {
	return d.reconcile(ctx, ref, spec)
}

func (d *DomainDriver) reconcile(ctx context.Context, ref interfaces.ResourceRef, spec interfaces.ResourceSpec) (*interfaces.ResourceOutput, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("hover domain reconcile %q: %w", spec.Name, err)
	}
	s, err := parseDomainSpec(spec)
	if err != nil {
		return nil, err
	}
	currentDomain := ref.ProviderID
	if currentDomain != "" && !strings.EqualFold(s.domain, currentDomain) {
		return nil, fmt.Errorf("hover domain update %q: spec.domain %q does not match current %q - domain change requires resource replace, not update", ref.Name, s.domain, currentDomain)
	}
	current, err := d.client.GetTransferLock(ctx, s.domain)
	if err != nil {
		return nil, fmt.Errorf("hover domain update %q: read transfer_lock: %w", spec.Name, err)
	}
	if s.transferLock != nil && current != *s.transferLock {
		if err := d.client.SetTransferLock(ctx, s.domain, *s.transferLock); err != nil {
			return nil, fmt.Errorf("hover domain update %q: set transfer_lock: %w", spec.Name, err)
		}
		current = *s.transferLock
	}
	return domainOutput(spec.Name, s.domain, current), nil
}

func (d *DomainDriver) Delete(_ context.Context, ref interfaces.ResourceRef) error {
	return fmt.Errorf("hover domain delete %q: refusing to delete registrar domain; remove state explicitly if unmanaged", ref.Name)
}

func (d *DomainDriver) Diff(_ context.Context, desired interfaces.ResourceSpec, current *interfaces.ResourceOutput) (*interfaces.DiffResult, error) {
	s, err := parseDomainSpec(desired)
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
	if s.transferLock != nil {
		currentLocked, ok := current.Outputs["transfer_lock"].(bool)
		if !ok || currentLocked != *s.transferLock {
			return &interfaces.DiffResult{
				NeedsUpdate: true,
				Changes: []interfaces.FieldChange{{
					Path: "transfer_lock",
					Old:  current.Outputs["transfer_lock"],
					New:  *s.transferLock,
				}},
			}, nil
		}
	}
	return &interfaces.DiffResult{NeedsUpdate: false}, nil
}

func (d *DomainDriver) HealthCheck(ctx context.Context, ref interfaces.ResourceRef) (*interfaces.HealthResult, error) {
	if _, err := d.Read(ctx, ref); err != nil {
		return &interfaces.HealthResult{Healthy: false, Message: err.Error()}, nil
	}
	return &interfaces.HealthResult{Healthy: true, Message: "ok"}, nil
}

func (d *DomainDriver) Scale(_ context.Context, _ interfaces.ResourceRef, _ int) (*interfaces.ResourceOutput, error) {
	return nil, fmt.Errorf("hover domain: scale is not supported")
}
