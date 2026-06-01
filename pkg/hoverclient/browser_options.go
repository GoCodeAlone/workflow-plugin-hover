package hoverclient

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const defaultBrowserTimeout = 90 * time.Second

// BrowserOptions controls the local Chrome instance used for live Hover access.
type BrowserOptions struct {
	Path       string
	Download   bool
	Headless   bool
	ProfileDir string
	Timeout    time.Duration
}

// BrowserOptionsFromEnv returns BrowserOptions using HOVER_BROWSER_* env aliases.
func BrowserOptionsFromEnv() (BrowserOptions, error) {
	opts := DefaultBrowserOptions()
	if path := firstNonEmpty(os.Getenv("HOVER_BROWSER_PATH"), os.Getenv("ROD_BROWSER_PATH")); path != "" {
		opts.Path = path
	}
	if raw := strings.TrimSpace(os.Getenv("HOVER_BROWSER_DOWNLOAD")); raw != "" {
		v, err := strconv.ParseBool(raw)
		if err != nil {
			return BrowserOptions{}, fmt.Errorf("HOVER_BROWSER_DOWNLOAD must be boolean: %w", err)
		}
		opts.Download = v
	}
	if raw := strings.TrimSpace(os.Getenv("HOVER_BROWSER_HEADLESS")); raw != "" {
		v, err := strconv.ParseBool(raw)
		if err != nil {
			return BrowserOptions{}, fmt.Errorf("HOVER_BROWSER_HEADLESS must be boolean: %w", err)
		}
		opts.Headless = v
	}
	if dir := strings.TrimSpace(os.Getenv("HOVER_BROWSER_PROFILE_DIR")); dir != "" {
		opts.ProfileDir = dir
	}
	return opts, nil
}

// DefaultBrowserOptions returns conservative runtime defaults for Chrome.
func DefaultBrowserOptions() BrowserOptions {
	return BrowserOptions{
		Download:   true,
		Headless:   true,
		ProfileDir: defaultBrowserProfileDir(),
		Timeout:    defaultBrowserTimeout,
	}
}

func defaultBrowserProfileDir() string {
	if state := strings.TrimSpace(os.Getenv("XDG_STATE_HOME")); state != "" {
		return filepath.Join(state, "wfctl", "plugins", "hover", "browser-profile")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(os.TempDir(), "wfctl", "plugins", "hover", "browser-profile")
	}
	return filepath.Join(home, ".local", "state", "wfctl", "plugins", "hover", "browser-profile")
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
