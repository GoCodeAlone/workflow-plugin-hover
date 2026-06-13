package manifest_test

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"testing"
)

func TestEmbeddedPluginManifestMatchesRoot(t *testing.T) {
	root := readJSONFile(t, "plugin.json")
	embedded := readJSONFile(t, "cmd/workflow-plugin-hover/plugin.json")
	if !reflect.DeepEqual(root, embedded) {
		t.Fatal("embedded plugin manifest must match root plugin.json")
	}
}

func TestManifestDeclaresIaCProviderCapability(t *testing.T) {
	manifest := readPluginManifest(t, "plugin.json")
	assertIaCProviderCapability(t, manifest, "hover", []string{"infra.dns", "infra.dns_delegation"})
}

type pluginManifest struct {
	Capabilities struct {
		ResourceTypes []string `json:"resourceTypes"`
		IaCProvider   struct {
			Name          string   `json:"name"`
			ResourceTypes []string `json:"resourceTypes"`
		} `json:"iacProvider"`
	} `json:"capabilities"`
	IaCProvider struct {
		ComputePlanVersion string `json:"computePlanVersion"`
	} `json:"iacProvider"`
}

func assertIaCProviderCapability(t *testing.T, manifest pluginManifest, name string, resourceTypes []string) {
	t.Helper()
	if manifest.Capabilities.IaCProvider.Name != name {
		t.Fatalf("capabilities.iacProvider.name = %q, want %q", manifest.Capabilities.IaCProvider.Name, name)
	}
	if !slices.Equal(manifest.Capabilities.IaCProvider.ResourceTypes, resourceTypes) {
		t.Fatalf("capabilities.iacProvider.resourceTypes = %#v, want %#v", manifest.Capabilities.IaCProvider.ResourceTypes, resourceTypes)
	}
	if !slices.Equal(manifest.Capabilities.ResourceTypes, resourceTypes) {
		t.Fatalf("capabilities.resourceTypes = %#v, want %#v", manifest.Capabilities.ResourceTypes, resourceTypes)
	}
	if manifest.IaCProvider.ComputePlanVersion != "v2" {
		t.Fatalf("iacProvider.computePlanVersion = %q, want %q", manifest.IaCProvider.ComputePlanVersion, "v2")
	}
}

func readJSONFile(t *testing.T, path string) any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return value
}

func readPluginManifest(t *testing.T, path string) pluginManifest {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var value pluginManifest
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return value
}
