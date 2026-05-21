package internal

import (
	"testing"
)

func TestHoverProvider_Capabilities_IncludesDelegation(t *testing.T) {
	p := NewHoverProvider()
	caps := p.Capabilities()
	wantTypes := map[string]bool{
		"infra.dns":            false,
		"infra.dns_delegation": false,
	}
	for _, c := range caps {
		if _, ok := wantTypes[c.ResourceType]; ok {
			wantTypes[c.ResourceType] = true
		}
	}
	for rt, found := range wantTypes {
		if !found {
			t.Errorf("Capabilities missing %q", rt)
		}
	}
}
