package drivers

import (
	"context"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-hover/pkg/hoverclient"
	"github.com/GoCodeAlone/workflow/interfaces"
)

type fakeHoverRedirectClient struct {
	current  *hoverclient.DomainForward
	getCalls int
	setCalls int
	setValue hoverclient.DomainForward
	getErr   error
	setErr   error
}

func (f *fakeHoverRedirectClient) GetForward(_ context.Context, _ string) (*hoverclient.DomainForward, error) {
	f.getCalls++
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.current == nil {
		return nil, hoverclient.ErrForwardNotFound
	}
	copy := *f.current
	return &copy, nil
}

func (f *fakeHoverRedirectClient) SetForward(_ context.Context, _ string, forward hoverclient.DomainForward) error {
	f.setCalls++
	f.setValue = forward
	if f.setErr != nil {
		return f.setErr
	}
	copy := forward
	f.current = &copy
	return nil
}

func TestHoverRedirectDriverUpdateSkipsWriteWhenForwardMatches(t *testing.T) {
	fc := &fakeHoverRedirectClient{current: &hoverclient.DomainForward{
		Domain:  "buymywishlist.net",
		URL:     "http://buymywishlist.com",
		Stealth: false,
	}}
	d := NewRedirectDriverWithClient(fc)

	out, err := d.Update(context.Background(),
		interfaces.ResourceRef{Name: "bmw-net-forward", Type: "infra.http_redirect", ProviderID: "buymywishlist.net"},
		interfaces.ResourceSpec{
			Name: "bmw-net-forward",
			Type: "infra.http_redirect",
			Config: map[string]any{
				"domain":     "buymywishlist.net",
				"target_url": "http://buymywishlist.com",
			},
		})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if fc.getCalls != 1 {
		t.Fatalf("GetForward calls = %d, want 1", fc.getCalls)
	}
	if fc.setCalls != 0 {
		t.Fatalf("SetForward calls = %d, want 0", fc.setCalls)
	}
	if out.Outputs["target_url"] != "http://buymywishlist.com" {
		t.Fatalf("target_url = %v", out.Outputs["target_url"])
	}
}

func TestHoverRedirectDriverCreateWritesWhenForwardMissing(t *testing.T) {
	fc := &fakeHoverRedirectClient{}
	d := NewRedirectDriverWithClient(fc)

	_, err := d.Create(context.Background(), interfaces.ResourceSpec{
		Name: "bmw-net-forward",
		Type: "infra.http_redirect",
		Config: map[string]any{
			"domain":     "buymywishlist.net",
			"target_url": "http://buymywishlist.com",
		},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if fc.getCalls != 1 {
		t.Fatalf("GetForward calls = %d, want 1", fc.getCalls)
	}
	if fc.setCalls != 1 {
		t.Fatalf("SetForward calls = %d, want 1", fc.setCalls)
	}
	if fc.setValue.URL != "http://buymywishlist.com" || fc.setValue.Stealth {
		t.Fatalf("setValue = %#v", fc.setValue)
	}
}

func TestHoverRedirectDriverDiff(t *testing.T) {
	d := NewRedirectDriverWithClient(&fakeHoverRedirectClient{})
	diff, err := d.Diff(context.Background(),
		interfaces.ResourceSpec{
			Name: "bmw-net-forward",
			Type: "infra.http_redirect",
			Config: map[string]any{
				"domain":     "buymywishlist.net",
				"target_url": "http://buymywishlist.com",
			},
		},
		&interfaces.ResourceOutput{
			Name:       "bmw-net-forward",
			Type:       "infra.http_redirect",
			ProviderID: "buymywishlist.net",
			Outputs: map[string]any{
				"domain":     "buymywishlist.net",
				"from_host":  "buymywishlist.net",
				"target_url": "https://old.example.com",
				"stealth":    false,
			},
		})
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if diff == nil || !diff.NeedsUpdate {
		t.Fatalf("NeedsUpdate = false, want true")
	}
}
