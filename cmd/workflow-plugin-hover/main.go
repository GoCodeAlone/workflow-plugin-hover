// Command workflow-plugin-hover is a workflow IaC plugin that
// implements `infra.dns` against Hover's account portal.
//
// Hover has no official API. This plugin mimics the browser-side
// auth (login + TOTP) used by pjslauta/hover-dyn-dns.
package main

import (
	"github.com/GoCodeAlone/workflow-plugin-hover/internal"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

func main() {
	sdk.ServeIaCPlugin(internal.NewIaCServer(), sdk.IaCServeOptions{
		BuildVersion: sdk.ResolveBuildVersion(internal.Version),
	})
}
