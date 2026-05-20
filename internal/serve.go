// Package internal — Hover plugin entry point.
package internal

// Serve is the gRPC plugin entry-point. Full driver registration
// lands once workflow#640 Phase 3 (typed IaC ResourceDriver
// surface) stabilises. Until then the Hover client lives in
// internal/hover and the scaffold compiles + tests on its own.
func Serve() {
	// placeholder; see workflow-plugin-namecheap/internal/serve.go
	// for the eventual SDK invocation.
}
