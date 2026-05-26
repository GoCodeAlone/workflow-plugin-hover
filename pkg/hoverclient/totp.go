// Package hoverclient implements the Hover DNS provider client.
//
// Hover ships no official API. This package mimics the browser-side
// authentication flow exposed by Hover's signin UI:
//
//  1. POST https://www.hover.com/signin/auth.json (username, password).
//  2. POST https://www.hover.com/signin/auth2.json (code) when MFA is required.
//  3. Subsequent requests carry the session cookie jar.
//
// TOTP codes are RFC 6238 (HMAC-SHA1, 30s window, 6 digits).
package hoverclient

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// TOTPSecret holds a decoded HOTP key. Construct via ParseBase32.
type TOTPSecret struct {
	key []byte
}

// ParseBase32 parses a Google-Authenticator-style base32 seed (case-
// insensitive, padding optional) into a TOTPSecret. Spaces are
// stripped so users can paste from the Hover 2FA setup dialog.
func ParseBase32(seed string) (TOTPSecret, error) {
	s := strings.ReplaceAll(strings.ReplaceAll(seed, " ", ""), "-", "")
	s = strings.ToUpper(s)
	// Pad to a multiple of 8 (base32 requirement) using `=`.
	if mod := len(s) % 8; mod != 0 {
		s += strings.Repeat("=", 8-mod)
	}
	key, err := base32.StdEncoding.DecodeString(s)
	if err != nil {
		return TOTPSecret{}, fmt.Errorf("hover: invalid TOTP seed base32: %w", err)
	}
	if len(key) < 10 {
		return TOTPSecret{}, fmt.Errorf("hover: TOTP seed too short (decoded to %d bytes; RFC 6238 recommends ≥ 20)", len(key))
	}
	return TOTPSecret{key: key}, nil
}

// CodeAt returns the 6-digit code for the given Unix time t (seconds).
// 30-second step per RFC 6238 §4. Pure HMAC-SHA1 — no external deps.
func (s TOTPSecret) CodeAt(t int64) string {
	const step = 30
	counter := uint64(t / step)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)

	mac := hmac.New(sha1.New, s.key)
	_, _ = mac.Write(msg[:])
	sum := mac.Sum(nil)

	// RFC 6238 dynamic truncation: low nibble of last byte is the
	// offset into sum for the 31-bit code.
	offset := int(sum[len(sum)-1] & 0x0f)
	bin := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	code := bin % 1_000_000
	return fmt.Sprintf("%06d", code)
}

// Code returns the 6-digit code for the current wall-clock time.
func (s TOTPSecret) Code() string {
	return s.CodeAt(time.Now().Unix())
}
