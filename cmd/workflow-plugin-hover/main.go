// Command workflow-plugin-hover is a workflow IaC plugin that
// implements `infra.dns` against Hover's account portal.
//
// Hover has no official API. This plugin mimics the browser-side
// auth (login + TOTP) used by pjslauta/hover-dyn-dns.
package main

import (
	_ "embed"

	"github.com/GoCodeAlone/workflow-plugin-hover/internal"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// pluginJSON is the committed plugin.json embedded at build time.
// goreleaser's before hook copies plugin.json from the repo root to this
// directory before building so go:embed resolves correctly.
//
//go:embed plugin.json
var pluginJSON []byte

func main() {
	sdk.ServeIaCPlugin(internal.NewIaCServer(), sdk.IaCServeOptions{
		ManifestProvider: sdk.MustEmbedManifest(pluginJSON),
		BuildVersion:     sdk.ResolveBuildVersion(internal.Version),
	})
}
