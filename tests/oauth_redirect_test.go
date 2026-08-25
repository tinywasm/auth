//go:build !wasm

package tests

import (
	"testing"

	"github.com/tinywasm/auth"
	"github.com/tinywasm/auth/authority"
	"github.com/tinywasm/auth/oauth2"
	googlemock "github.com/tinywasm/auth/oauth2/provider/google/mock"
	"github.com/tinywasm/router/mock"
)

func isVeltyCl(url string) bool {
	// Minimal host check, same shape as the real validator iam wires — see
	// veltylabs/iam/config/auth.go.
	const prefix = "https://"
	if len(url) < len(prefix) || url[:len(prefix)] != prefix {
		return false
	}
	rest := url[len(prefix):]
	for i := 0; i < len(rest); i++ {
		if rest[i] == '/' {
			rest = rest[:i]
			break
		}
	}
	return rest == "velty.cl" || (len(rest) > len(".velty.cl") && rest[len(rest)-len(".velty.cl"):] == ".velty.cl")
}

// TestOAuthRedirectURI_AllowedOverridesAfterLogin proves the full
// start→callback round trip: a validated redirect_uri set on /oauth/google
// survives (via the one-shot cookie) to the callback and overrides
// afterLogin.
func TestOAuthRedirectURI_AllowedOverridesAfterLogin(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}
	prov := &googlemock.MockProvider{User: auth.OAuthUserInfo{ID: "g1", Email: "u@test.com", Name: "U"}}
	m.Enable(oauth2.New(m, m, m, []auth.OAuthProvider{prov},
		oauth2.WithAfterLogin("/"),
		oauth2.WithRedirectValidator(isVeltyCl),
	))

	r := &mock.Router{}
	m.MountAPI(r)

	start := &mock.Context{InPath: "/oauth/google?redirect_uri=https://misitio.velty.cl/panel"}
	r.Invoke("GET", "/oauth/google", start)
	if start.Status != 302 {
		t.Fatalf("start status: got %d, want 302", start.Status)
	}
	redirectCookie, ok := start.Cookie("oauth_redirect")
	if !ok || redirectCookie.Value != "https://misitio.velty.cl/panel" {
		t.Fatalf("oauth_redirect cookie: got %+v, ok=%v", redirectCookie, ok)
	}
	location := start.GetHeader("Location")

	// The browser follows Location and carries the cookie the start handler
	// just set — mock.Context instances don't share state, so this is done
	// by hand, standing in for what a real browser does automatically.
	callback := &mock.Context{InPath: location}
	callback.SetCookie(redirectCookie)
	r.Invoke("GET", "/oauth/callback/google", callback)

	if callback.Status != 302 {
		t.Fatalf("callback status: got %d, want 302", callback.Status)
	}
	if got := callback.GetHeader("Location"); got != "https://misitio.velty.cl/panel" {
		t.Errorf("Location: got %q, want the validated redirect_uri", got)
	}
	// One-shot: the callback must clear it, not leave it lingering.
	if c, ok := callback.Cookie("oauth_redirect"); ok && c.MaxAge >= 0 {
		t.Errorf("oauth_redirect cookie not cleared: %+v", c)
	}
}

// TestOAuthRedirectURI_DisallowedFallsBackToAfterLogin proves an
// unvalidated redirect_uri never reaches Location — this is the
// open-redirect guard.
func TestOAuthRedirectURI_DisallowedFallsBackToAfterLogin(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}
	prov := &googlemock.MockProvider{User: auth.OAuthUserInfo{ID: "g1", Email: "u@test.com", Name: "U"}}
	m.Enable(oauth2.New(m, m, m, []auth.OAuthProvider{prov},
		oauth2.WithAfterLogin("/home"),
		oauth2.WithRedirectValidator(isVeltyCl),
	))

	r := &mock.Router{}
	m.MountAPI(r)

	start := &mock.Context{InPath: "/oauth/google?redirect_uri=https://evil.example.com/steal"}
	r.Invoke("GET", "/oauth/google", start)
	if _, ok := start.Cookie("oauth_redirect"); ok {
		t.Fatal("oauth_redirect cookie set for a disallowed redirect_uri")
	}

	callback := &mock.Context{InPath: start.GetHeader("Location")}
	r.Invoke("GET", "/oauth/callback/google", callback)

	if got := callback.GetHeader("Location"); got != "/home" {
		t.Errorf("Location: got %q, want afterLogin %q", got, "/home")
	}
}

// TestOAuthRedirectURI_NoValidatorIgnoresParam proves the option is fully
// additive: a caller that never calls WithRedirectValidator (nil, the
// default) gets byte-for-byte the same behavior as before this option
// existed, even if a caller sends ?redirect_uri=.
func TestOAuthRedirectURI_NoValidatorIgnoresParam(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}
	prov := &googlemock.MockProvider{User: auth.OAuthUserInfo{ID: "g1", Email: "u@test.com", Name: "U"}}
	m.Enable(oauth2.New(m, m, m, []auth.OAuthProvider{prov})) // no WithRedirectValidator

	r := &mock.Router{}
	m.MountAPI(r)

	start := &mock.Context{InPath: "/oauth/google?redirect_uri=https://misitio.velty.cl/panel"}
	r.Invoke("GET", "/oauth/google", start)
	if _, ok := start.Cookie("oauth_redirect"); ok {
		t.Fatal("oauth_redirect cookie set despite no validator configured")
	}

	callback := &mock.Context{InPath: start.GetHeader("Location")}
	r.Invoke("GET", "/oauth/callback/google", callback)
	if got := callback.GetHeader("Location"); got != auth.PathAfterLogin {
		t.Errorf("Location: got %q, want the default PathAfterLogin %q", got, auth.PathAfterLogin)
	}
}
