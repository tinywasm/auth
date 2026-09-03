//go:build !wasm

package tests

import (
	"strings"
	"testing"

	"github.com/tinywasm/auth"
	"github.com/tinywasm/auth/authority"
	"github.com/tinywasm/auth/oauth2"
	"github.com/tinywasm/ddl"
	"github.com/tinywasm/orm"
	"github.com/tinywasm/router"
	"github.com/tinywasm/router/mock"
	"github.com/tinywasm/sqlite"
)

func setupOAuthTestModule(t *testing.T) (*authority.Module, *mockPublisher, *mock.Router) {
	t.Helper()
	conn, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	db := orm.New(conn)
	if err := authority.Migrate(db.RawConn(), db.RawConn().(ddl.Compiler)); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}

	pub := &mockPublisher{}
	m, err := authority.New(db, auth.Config{IDs: testIDs, Events: pub})
	if err != nil {
		t.Fatalf("failed to create authority: %v", err)
	}

	mockP := &MockProvider{
		NameVal:         "google",
		ExchangeCodeVal: auth.OAuthToken{AccessToken: "mocktoken"},
		UserInfoVal:     auth.OAuthUserInfo{ID: "mockid", Email: "mock@example.com", Name: "Mock User", EmailVerified: true},
	}
	m.Enable(oauth2.New(m, m, m, []auth.OAuthProvider{mockP}))

	r := &mock.Router{}
	m.MountAPI(r)

	return m, pub, r
}

func TestOAuthCallbackRequiresNonceCookie(t *testing.T) {
	_, _, r := setupOAuthTestModule(t)

	// 1. Begin login
	ctxBegin := &mock.Context{InMethod: "GET", InPath: "/oauth/google"}
	r.Invoke("GET", "/oauth/google", ctxBegin)
	if ctxBegin.Status != 302 {
		t.Fatalf("expected 302, got %d", ctxBegin.Status)
	}
	loc := ctxBegin.GetHeader("Location")
	state := strings.TrimPrefix(loc, "http://mock/")

	// 2. Callback WITHOUT oauth_nonce cookie
	ctxCallback := &mock.Context{InMethod: "GET", InPath: "/oauth/callback/google?state=" + state + "&code=mockcode"}
	r.Invoke("GET", "/oauth/callback/google", ctxCallback)

	if ctxCallback.Status != 401 {
		t.Fatalf("expected 401 for missing nonce cookie, got %d", ctxCallback.Status)
	}
}

func TestOAuthCallbackRejectsForeignNonce(t *testing.T) {
	_, _, r := setupOAuthTestModule(t)

	// Begin login
	ctxBegin := &mock.Context{InMethod: "GET", InPath: "/oauth/google"}
	r.Invoke("GET", "/oauth/google", ctxBegin)
	loc := ctxBegin.GetHeader("Location")
	state := strings.TrimPrefix(loc, "http://mock/")

	// Callback with foreign nonce
	ctxCallback := &mock.Context{InMethod: "GET", InPath: "/oauth/callback/google?state=" + state + "&code=mockcode"}
	ctxCallback.SetCookie(router.Cookie{Name: "oauth_nonce", Value: "wrong_foreign_nonce"})
	r.Invoke("GET", "/oauth/callback/google", ctxCallback)

	if ctxCallback.Status != 401 {
		t.Fatalf("expected 401 for foreign nonce, got %d", ctxCallback.Status)
	}
}

func TestOAuthStateIsSingleUse(t *testing.T) {
	_, _, r := setupOAuthTestModule(t)

	ctxBegin := &mock.Context{InMethod: "GET", InPath: "/oauth/google"}
	r.Invoke("GET", "/oauth/google", ctxBegin)
	loc := ctxBegin.GetHeader("Location")
	state := strings.TrimPrefix(loc, "http://mock/")

	cookie, ok := ctxBegin.Cookie("oauth_nonce")
	if !ok || cookie.Value == "" {
		t.Fatalf("oauth_nonce cookie was not set on /oauth/google")
	}

	// First callback attempt -> Success
	ctxCallback1 := &mock.Context{InMethod: "GET", InPath: "/oauth/callback/google?state=" + state + "&code=mockcode"}
	ctxCallback1.SetCookie(cookie)
	r.Invoke("GET", "/oauth/callback/google", ctxCallback1)
	if ctxCallback1.Status != 302 {
		t.Fatalf("first callback failed with status %d", ctxCallback1.Status)
	}

	// Second callback attempt with SAME state+nonce -> Replay error 401
	ctxCallback2 := &mock.Context{InMethod: "GET", InPath: "/oauth/callback/google?state=" + state + "&code=mockcode"}
	ctxCallback2.SetCookie(cookie)
	r.Invoke("GET", "/oauth/callback/google", ctxCallback2)

	if ctxCallback2.Status != 401 {
		t.Fatalf("second callback attempt expected 401, got %d", ctxCallback2.Status)
	}
}

func TestOAuthStateConsumedEvenOnProviderMismatch(t *testing.T) {
	mod, _, _ := setupOAuthTestModule(t)

	state, nonce, err := mod.CreateState("google")
	if err != nil {
		t.Fatalf("CreateState failed: %v", err)
	}

	// Consume state with WRONG provider ("microsoft")
	err = mod.ConsumeState(state, nonce, "microsoft")
	if err != auth.ErrInvalidOAuthState {
		t.Fatalf("expected ErrInvalidOAuthState for provider mismatch, got %v", err)
	}

	// Try consuming state again with CORRECT provider ("google") -> state should be gone already
	err = mod.ConsumeState(state, nonce, "google")
	if err != auth.ErrInvalidOAuthState {
		t.Fatalf("expected state to be consumed and unavailable on second call, got %v", err)
	}
}

func TestOAuthStateEmitsReplayEvent(t *testing.T) {
	mod, pub, _ := setupOAuthTestModule(t)

	// Consume non-existent state
	_ = mod.ConsumeState("nonexistent_state", "nonce", "google")

	evs := pub.SecurityEvents()
	var found bool
	for _, e := range evs {
		if e.Type == auth.EventOAuthReplay {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected EventOAuthReplay security event to be published")
	}
}

func TestOAuthStateEmitsExpiredEvent(t *testing.T) {
	conn, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	db := orm.New(conn)
	if err := authority.Migrate(db.RawConn(), db.RawConn().(ddl.Compiler)); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}

	pub := &mockPublisher{}
	mod, err := authority.New(db, auth.Config{IDs: testIDs, Events: pub})
	if err != nil {
		t.Fatalf("failed to create authority: %v", err)
	}

	state, nonce, err := mod.CreateState("google")
	if err != nil {
		t.Fatalf("CreateState failed: %v", err)
	}

	// Set expires_at to past
	if err := db.RawConn().Exec("UPDATE oauth_state SET expires_at = 0 WHERE state = ?", state); err != nil {
		t.Fatalf("failed to expire oauth_state row: %v", err)
	}

	err = mod.ConsumeState(state, nonce, "google")
	if err != auth.ErrInvalidOAuthState {
		t.Fatalf("expected ErrInvalidOAuthState for expired state, got %v", err)
	}

	evs := pub.SecurityEvents()
	var found bool
	for _, e := range evs {
		if e.Type == auth.EventOAuthExpiredState {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected EventOAuthExpiredState security event to be published")
	}
}

func TestOAuthStateEmitsCrossProviderEvent(t *testing.T) {
	mod, pub, _ := setupOAuthTestModule(t)

	state, nonce, err := mod.CreateState("google")
	if err != nil {
		t.Fatalf("CreateState failed: %v", err)
	}

	_ = mod.ConsumeState(state, nonce, "microsoft")

	evs := pub.SecurityEvents()
	var found bool
	for _, e := range evs {
		if e.Type == auth.EventOAuthCrossProvider {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected EventOAuthCrossProvider security event to be published")
	}
}
