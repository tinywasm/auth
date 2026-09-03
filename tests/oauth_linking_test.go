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
	"github.com/tinywasm/router/mock"
	"github.com/tinywasm/sqlite"
)

func TestUnverifiedEmailDoesNotLinkExistingAccount(t *testing.T) {
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

	// Create pre-existing user
	existingUser, err := m.CreateUser("victim@example.com", "Victim", "")
	if err != nil {
		t.Fatalf("failed to create victim user: %v", err)
	}

	mockP := &MockProvider{
		NameVal:         "unverified_provider",
		ExchangeCodeVal: auth.OAuthToken{AccessToken: "mocktoken"},
		UserInfoVal: auth.OAuthUserInfo{
			ID:            "attacker_id",
			Email:         "victim@example.com",
			Name:          "Attacker",
			EmailVerified: false, // Unverified!
		},
	}
	m.Enable(oauth2.New(m, m, m, []auth.OAuthProvider{mockP}))

	r := &mock.Router{}
	m.MountAPI(r)

	ctxBegin := &mock.Context{InMethod: "GET", InPath: "/oauth/unverified_provider"}
	r.Invoke("GET", "/oauth/unverified_provider", ctxBegin)
	loc := ctxBegin.GetHeader("Location")
	state := strings.TrimPrefix(loc, "http://mock/")

	ctxCallback := &mock.Context{
		InMethod: "GET",
		InPath:   "/oauth/callback/unverified_provider?state=" + state + "&code=mockcode",
	}
	if nonceCookie, ok := ctxBegin.Cookie("oauth_nonce"); ok {
		ctxCallback.SetCookie(nonceCookie)
	}
	r.Invoke("GET", "/oauth/callback/unverified_provider", ctxCallback)

	if ctxCallback.Status != 401 {
		t.Fatalf("expected 401 for unverified email on existing account, got %d", ctxCallback.Status)
	}

	// Ensure identity was NOT created/linked to existing user
	_, err = m.IdentityByProvider("unverified_provider", "attacker_id")
	if err == nil {
		t.Fatalf("unverified identity should NOT have been linked to victim user")
	}

	// Verify EventUnauthorizedAccess event was published
	var found bool
	for _, e := range pub.SecurityEvents() {
		if e.Type == auth.EventUnauthorizedAccess && e.Provider == "unverified_provider" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected EventUnauthorizedAccess security event to be published")
	}

	_ = existingUser
}

func TestVerifiedEmailLinksExistingAccount(t *testing.T) {
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

	existingUser, err := m.CreateUser("honest@example.com", "Honest User", "")
	if err != nil {
		t.Fatalf("failed to create honest user: %v", err)
	}

	mockP := &MockProvider{
		NameVal:         "verified_provider",
		ExchangeCodeVal: auth.OAuthToken{AccessToken: "mocktoken"},
		UserInfoVal: auth.OAuthUserInfo{
			ID:            "honest_ext_id",
			Email:         "honest@example.com",
			Name:          "Honest User",
			EmailVerified: true, // Verified!
		},
	}
	m.Enable(oauth2.New(m, m, m, []auth.OAuthProvider{mockP}))

	r := &mock.Router{}
	m.MountAPI(r)

	ctxBegin := &mock.Context{InMethod: "GET", InPath: "/oauth/verified_provider"}
	r.Invoke("GET", "/oauth/verified_provider", ctxBegin)
	loc := ctxBegin.GetHeader("Location")
	state := strings.TrimPrefix(loc, "http://mock/")

	ctxCallback := &mock.Context{
		InMethod: "GET",
		InPath:   "/oauth/callback/verified_provider?state=" + state + "&code=mockcode",
	}
	if nonceCookie, ok := ctxBegin.Cookie("oauth_nonce"); ok {
		ctxCallback.SetCookie(nonceCookie)
	}
	r.Invoke("GET", "/oauth/callback/verified_provider", ctxCallback)

	if ctxCallback.Status != 302 {
		t.Fatalf("expected 302 for verified email on existing account, got %d", ctxCallback.Status)
	}

	idRow, err := m.IdentityByProvider("verified_provider", "honest_ext_id")
	if err != nil {
		t.Fatalf("failed to find linked identity: %v", err)
	}
	if idRow.UserId != existingUser.Id {
		t.Fatalf("expected linked user ID %s, got %s", existingUser.Id, idRow.UserId)
	}
}
