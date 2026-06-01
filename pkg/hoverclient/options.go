package hoverclient

// ClientOptions configures a Client beyond credentials.
// Zero value is valid; individual fields fall back to defaults.
type ClientOptions struct {
	Browser BrowserOptions
}
