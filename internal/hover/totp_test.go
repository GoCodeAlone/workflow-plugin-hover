package hover

import (
	"strings"
	"testing"
)

// RFC 6238 Appendix B test vectors (TOTP, SHA-1, 30s step).
//
//	T      Time (UTC)            Code
//	  59   1970-01-01 00:00:59  94287082
//	1111111109  287082
//	... etc.
//
// We use the canonical 20-byte ASCII secret "12345678901234567890",
// which encodes as base32 to: GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ.
const rfc6238Secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func mustParse(t *testing.T, s string) TOTPSecret {
	t.Helper()
	sec, err := ParseBase32(s)
	if err != nil {
		t.Fatalf("ParseBase32(%q): %v", s, err)
	}
	return sec
}

func TestParseBase32_AcceptsCanonicalSecret(t *testing.T) {
	sec := mustParse(t, rfc6238Secret)
	if string(sec.key) != "12345678901234567890" {
		t.Errorf("decoded key = %q want %q", sec.key, "12345678901234567890")
	}
}

func TestParseBase32_HandlesWhitespaceAndCase(t *testing.T) {
	sec := mustParse(t, "gezd gnbv gy3t qojq gezd gnbv gy3t qojq")
	if string(sec.key) != "12345678901234567890" {
		t.Errorf("whitespace+lowercase roundtrip failed: %q", sec.key)
	}
}

func TestParseBase32_RejectsTooShort(t *testing.T) {
	_, err := ParseBase32("AAAA")
	if err == nil {
		t.Fatal("expected error for too-short seed")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("err: %v", err)
	}
}

func TestParseBase32_RejectsBadAlphabet(t *testing.T) {
	_, err := ParseBase32("####################")
	if err == nil {
		t.Fatal("expected error for non-base32 chars")
	}
}

// TestCodeAt_RFC6238Vectors exercises the canonical RFC vectors.
func TestCodeAt_RFC6238Vectors(t *testing.T) {
	sec := mustParse(t, rfc6238Secret)
	cases := []struct {
		t    int64
		want string
	}{
		{59, "287082"},          // Truncated to last 6 of 94287082
		{1111111109, "081804"},  // Truncated to last 6 of 7081804
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	}
	for _, c := range cases {
		got := sec.CodeAt(c.t)
		if got != c.want {
			t.Errorf("CodeAt(%d) = %q want %q", c.t, got, c.want)
		}
	}
}

func TestCode_UsesWallClock(t *testing.T) {
	sec := mustParse(t, rfc6238Secret)
	got := sec.Code()
	if len(got) != 6 {
		t.Errorf("Code returned %q (len %d); want 6 digits", got, len(got))
	}
	for _, r := range got {
		if r < '0' || r > '9' {
			t.Errorf("non-digit %q in code %q", r, got)
		}
	}
}
