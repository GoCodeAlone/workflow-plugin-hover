package hover

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
)

// signinCSRFHTML is what we return on GET /signin + /signin/totp so
// the client's CSRF regex finds a token.
const signinCSRFHTML = `<form><input type="hidden" name="_token" value="t0kEnVaLuE"></form>`

func newStubClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	jar, _ := cookiejar.New(nil)
	httpc := &http.Client{
		Jar:       jar,
		Transport: rewriteTransport{base: srv.URL},
	}
	creds := Credentials{
		Username:   "alice",
		Password:   "pw",
		TOTPSecret: mustParse(t, rfc6238Secret),
	}
	c, err := NewClient(creds, httpc)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c, srv
}

type rewriteTransport struct{ base string }

func (r rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = r.base[len("http://"):]
	return http.DefaultTransport.RoundTrip(clone)
}

func TestClient_Login_TwoStep(t *testing.T) {
	var hits []string
	var totpForm string
	c, srv := newStubClient(t, func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/signin":
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(signinCSRFHTML))
				return
			}
			// POST: just succeed.
			w.WriteHeader(http.StatusOK)
		case "/signin/totp":
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(signinCSRFHTML))
				return
			}
			_ = r.ParseForm()
			totpForm = r.Form.Encode()
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected hit: %s %s", r.Method, r.URL.Path)
		}
	})
	defer srv.Close()

	if err := c.ensureLogin(context.Background()); err != nil {
		t.Fatalf("ensureLogin: %v", err)
	}

	wantHits := []string{
		"GET /signin",
		"POST /signin",
		"GET /signin/totp",
		"POST /signin/totp",
	}
	if len(hits) != len(wantHits) {
		t.Fatalf("hits = %v; want %v", hits, wantHits)
	}
	for i, want := range wantHits {
		if hits[i] != want {
			t.Errorf("hits[%d] = %q want %q", i, hits[i], want)
		}
	}

	// TOTP form must include a 6-digit code + the CSRF token from the
	// GET response.
	if !strings.Contains(totpForm, "_token=t0kEnVaLuE") {
		t.Errorf("TOTP POST missing CSRF: %q", totpForm)
	}
	if !strings.Contains(totpForm, "code=") {
		t.Errorf("TOTP POST missing code: %q", totpForm)
	}
}

func TestClient_Login_SkipsWhenFresh(t *testing.T) {
	var hits int
	c, srv := newStubClient(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(signinCSRFHTML))
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	if err := c.ensureLogin(context.Background()); err != nil {
		t.Fatal(err)
	}
	firstRound := hits
	if err := c.ensureLogin(context.Background()); err != nil {
		t.Fatal(err)
	}
	if hits != firstRound {
		t.Errorf("second ensureLogin hit network; want cache hit. first=%d second=%d", firstRound, hits)
	}
}

func TestClient_CSRFParseFailure_RaisesClearError(t *testing.T) {
	c, srv := newStubClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>no token here</html>"))
	})
	defer srv.Close()

	err := c.ensureLogin(context.Background())
	if err == nil {
		t.Fatal("expected CSRF parse error")
	}
	if !strings.Contains(err.Error(), "CSRF token not found") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestNewClient_RequiresCredentials(t *testing.T) {
	_, err := NewClient(Credentials{}, nil)
	if err == nil {
		t.Fatal("expected error on empty creds")
	}
}
