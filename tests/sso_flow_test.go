//go:build !wasm

package tests

import (
	"strings"
	"testing"

	"github.com/tinywasm/auth"
	"github.com/tinywasm/auth/authority"
	"github.com/tinywasm/auth/oauth2"
	googlemock "github.com/tinywasm/auth/oauth2/provider/google/mock"
	sessionjwt "github.com/tinywasm/auth/session/jwt"
	"github.com/tinywasm/ddl"
	"github.com/tinywasm/orm"
	"github.com/tinywasm/router/mock"
	"github.com/tinywasm/sqlite"
)

func TestSSOLoginFlow_EndToEndWithJWTStrategy(t *testing.T) {
	conn, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	db := orm.New(conn)
	if err := authority.Migrate(db.RawConn(), db.RawConn().(ddl.Compiler)); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}

	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatalf("failed to create authority: %v", err)
	}

	secret := []byte("secret-key-must-be-32-bytes-long!")
	jwtStrategy, err := sessionjwt.New(secret, 86400, m, m)
	if err != nil {
		t.Fatalf("failed to create jwt strategy: %v", err)
	}
	jwtStrategy.WithDomain(".velty.cl")
	m.SetStrategy(jwtStrategy)

	prov := &googlemock.MockProvider{
		User: auth.OAuthUserInfo{
			ID:            "g_sso_1",
			Email:         "sso@velty.cl",
			Name:          "SSO User",
			EmailVerified: true,
		},
	}
	m.Enable(oauth2.New(m, m, m, []auth.OAuthProvider{prov}))

	r := &mock.Router{}
	m.MountAPI(r)

	// 1. GET /oauth/google
	startCtx := &mock.Context{InMethod: "GET", InPath: "/oauth/google"}
	r.Invoke("GET", "/oauth/google", startCtx)
	if startCtx.Status != 302 {
		t.Fatalf("start status: got %d, want 302", startCtx.Status)
	}
	loc := startCtx.GetHeader("Location")
	state := strings.TrimPrefix(loc, auth.PathOAuthCallback("google")+"?state=")
	state = strings.Split(state, "&")[0]

	nonceCookie, ok := startCtx.Cookie("oauth_nonce")
	if !ok {
		t.Fatalf("expected oauth_nonce cookie")
	}

	// 2. GET /oauth/callback/google
	callbackCtx := &mock.Context{
		InMethod: "GET",
		InPath:   auth.PathOAuthCallback("google") + "?state=" + state + "&code=mockcode",
	}
	callbackCtx.SetCookie(nonceCookie)
	r.Invoke("GET", "/oauth/callback/google", callbackCtx)

	if callbackCtx.Status != 302 {
		t.Fatalf("callback status: got %d, want 302", callbackCtx.Status)
	}

	sessionCookie, ok := callbackCtx.Cookie("session")
	if !ok || sessionCookie.Value == "" {
		t.Fatalf("expected session cookie to be set")
	}

	// 3. Identify user with issued session cookie via JWT strategy
	reqCtx := &mock.Context{}
	reqCtx.SetCookie(sessionCookie)
	userID, err := jwtStrategy.Identify(reqCtx)
	if err != nil {
		t.Fatalf("jwtStrategy.Identify failed: %v", err)
	}

	u, err := m.UserByID(userID)
	if err != nil {
		t.Fatalf("UserByID failed: %v", err)
	}
	if u.Email != "sso@velty.cl" {
		t.Fatalf("resolved user email: got %s, want sso@velty.cl", u.Email)
	}
}

func TestDefaultStrategyIssuesAnUnguessableCookie(t *testing.T) {
	conn, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	db := orm.New(conn)
	if err := authority.Migrate(db.RawConn(), db.RawConn().(ddl.Compiler)); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}

	// authority.New without SetStrategy uses default cookie strategy
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatalf("failed to create authority: %v", err)
	}

	u, err := m.CreateUser("default_strat@example.com", "Default Strategy User", "")
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	sess1, err := m.CreateSession(u.Id, "127.0.0.1", "agent")
	if err != nil {
		t.Fatalf("failed to create session 1: %v", err)
	}
	sess2, err := m.CreateSession(u.Id, "127.0.0.1", "agent")
	if err != nil {
		t.Fatalf("failed to create session 2: %v", err)
	}

	if isAllDigits(sess1.Id) || isAllDigits(sess2.Id) {
		t.Fatalf("session IDs should not be pure decimal timestamps: %q, %q", sess1.Id, sess2.Id)
	}

	if commonPrefixLen(sess1.Id, sess2.Id) >= 16 {
		t.Fatalf("session IDs share prefix >= 16: %q vs %q", sess1.Id, sess2.Id)
	}
}
