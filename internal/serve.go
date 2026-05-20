// Package internal — Hover plugin entry point.
package internal

import (
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// Serve starts the Hover IaC plugin gRPC server. Called from cmd/main.go.
// The SDK auto-registers every typed pb.IaCProvider*Server interface that
// *hoverIaCServer satisfies via Go type-assertion at plugin startup.
func Serve() {
	sdk.ServeIaCPlugin(NewIaCServer(), sdk.IaCServeOptions{})
}
