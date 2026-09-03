//go:build !wasm

package tests

import (
	"errors"
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

type FailingProvider struct {
	NameVal        string
	ExchangeErr    error
	GetUserInfoErr error
	User           auth.OAuthUserInfo
}

func (p *FailingProvider) Name() string                    { return p.NameVal }
func (p *FailingProvider) AuthCodeURL(state string) string { return "http://mock/" + state }
func (p *FailingProvider) ExchangeCode(code string) (auth.OAuthToken, error) {
	if p.ExchangeErr != nil {
		return auth.OAuthToken{}, p.ExchangeErr
	}
	return auth.OAuthToken{AccessToken: "token"}, nil
}
func (p *FailingProvider) GetUserInfo(token auth.OAuthToken) (auth.OAuthUserInfo, error) {
	if p.GetUserInfoErr != nil {
		return auth.OAuthUserInfo{}, p.GetUserInfoErr
	}
	return p.User, nil
}

func TestCallbackNeverLeaksProviderError(t *testing.T) {
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

	secretErrText := "SECRET_PROVIDER_INTERNAL_DATABASE_CONNECTION_ERROR_EXPOSED"

	provFailExchange := &FailingProvider{
		NameVal:     "fail_exchange",
		ExchangeErr: errors.New(secretErrText),
	}
	provFailUserInfo := &FailingProvider{
		NameVal:        "fail_userinfo",
		GetUserInfoErr: errors.New(secretErrText),
	}

	m.Enable(oauth2.New(m, m, m, []auth.OAuthProvider{provFailExchange, provFailUserInfo}))

	r := &mock.Router{}
	m.MountAPI(r)

	// Case 1: ExchangeCode fails
	ctxBegin1 := &mock.Context{InMethod: "GET", InPath: "/oauth/fail_exchange"}
	r.Invoke("GET", "/oauth/fail_exchange", ctxBegin1)
	loc1 := ctxBegin1.GetHeader("Location")
	state1 := strings.TrimPrefix(loc1, "http://mock/")

	ctxCallback1 := &mock.Context{InMethod: "GET", InPath: "/oauth/callback/fail_exchange?state=" + state1 + "&code=code"}
	if nc, ok := ctxBegin1.Cookie("oauth_nonce"); ok {
		ctxCallback1.SetCookie(nc)
	}
	r.Invoke("GET", "/oauth/callback/fail_exchange", ctxCallback1)

	if ctxCallback1.Status != 401 {
		t.Fatalf("expected 401, got %d", ctxCallback1.Status)
	}
	body1 := string(ctxCallback1.ResponseBody())
	if body1 != "authentication failed" {
		t.Fatalf("expected body 'authentication failed', got %q", body1)
	}
	if strings.Contains(body1, secretErrText) {
		t.Fatalf("callback leaked provider error text: %s", body1)
	}

	// Case 2: GetUserInfo fails
	ctxBegin2 := &mock.Context{InMethod: "GET", InPath: "/oauth/fail_userinfo"}
	r.Invoke("GET", "/oauth/fail_userinfo", ctxBegin2)
	loc2 := ctxBegin2.GetHeader("Location")
	state2 := strings.TrimPrefix(loc2, "http://mock/")

	ctxCallback2 := &mock.Context{InMethod: "GET", InPath: "/oauth/callback/fail_userinfo?state=" + state2 + "&code=code"}
	if nc, ok := ctxBegin2.Cookie("oauth_nonce"); ok {
		ctxCallback2.SetCookie(nc)
	}
	r.Invoke("GET", "/oauth/callback/fail_userinfo", ctxCallback2)

	if ctxCallback2.Status != 401 {
		t.Fatalf("expected 401, got %d", ctxCallback2.Status)
	}
	body2 := string(ctxCallback2.ResponseBody())
	if body2 != "authentication failed" {
		t.Fatalf("expected body 'authentication failed', got %q", body2)
	}
	if strings.Contains(body2, secretErrText) {
		t.Fatalf("callback leaked provider error text: %s", body2)
	}

	// Case 3: Invalid state
	ctxCallback3 := &mock.Context{InMethod: "GET", InPath: "/oauth/callback/fail_exchange?state=invalid&code=code"}
	r.Invoke("GET", "/oauth/callback/fail_exchange", ctxCallback3)

	if ctxCallback3.Status != 401 {
		t.Fatalf("expected 401, got %d", ctxCallback3.Status)
	}
	body3 := string(ctxCallback3.ResponseBody())
	if body3 != "authentication failed" {
		t.Fatalf("expected body 'authentication failed', got %q", body3)
	}
}
