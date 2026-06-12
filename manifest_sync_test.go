package manifest_test

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestEmbeddedPluginManifestMatchesRoot(t *testing.T) {
	root := readJSONFile(t, "plugin.json")
	embedded := readJSONFile(t, "cmd/workflow-plugin-hover/plugin.json")
	if !reflect.DeepEqual(root, embedded) {
		t.Fatal("embedded plugin manifest must match root plugin.json")
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
