//go:build !wasm

package tests

import (
	"strings"
	"testing"

	"github.com/tinywasm/crypto/bcrypt"
	"github.com/tinywasm/ddl"
	tinyjwt "github.com/tinywasm/jwt"
	"github.com/tinywasm/orm"
	"github.com/tinywasm/router"
	"github.com/tinywasm/router/mock"
	"github.com/tinywasm/sqlite"
	"github.com/tinywasm/auth"
	"github.com/tinywasm/auth/authority"
	emailpassword "github.com/tinywasm/auth/email_password"
	"github.com/tinywasm/auth/oauth2"
	jwt "github.com/tinywasm/auth/session/jwt"
	trustedip "github.com/tinywasm/auth/trusted_ip"
)

func newTestDB(t *testing.T) *orm.DB {
	conn, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	t.Cleanup(func() {
		conn.Close()
	})
	db := orm.New(conn)
	if err := authority.Migrate(db.RawConn(), db.RawConn().(ddl.Compiler)); err != nil {
		t.Fatalf("failed to migrate schema: %v", err)
	}
	return db
}

func RunUserTests(t *testing.T) {
	emailpassword.DefaultHashCost = bcrypt.MinCost
	t.Run("TestInit", testInit)
	t.Run("TestCRUD", testCRUD)
	t.Run("TestAuth", testAuth)
	t.Run("TestSessions", testSessions)
	t.Run("TestOAuth", testOAuth)
	t.Run("TestLAN", testLAN)
	t.Run("TestJWTCookieMode", testJWTCookieMode)
}

func testJWTCookieMode(t *testing.T) {
	db := newTestDB(t)
	secret := []byte("test-secret-32-bytes-minimum-len")
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}

	strategy, err := jwt.New(secret, 86400, m, m)
	if err != nil {
		t.Fatal(err)
	}
	m.SetStrategy(strategy)
	m.Enable(emailpassword.New(m, m, m))

	userCRUD := getHandler(m, "users")
	res, err := userCRUD.Create(auth.User{Email: "jwt@test.com", Name: "JWT User"})
	if err != nil {
		t.Fatal(err)
	}
	u := res.(auth.User)
	_ = m.SetPassword(u.Id, "password123")
	logged, err := m.Login("jwt@test.com", "password123")
	if err != nil {
		t.Fatal("login failed:", err)
	}

	// Generar JWT como lo haría el módulo al emitir la cookie.
	token, err := tinyjwt.Sign(secret, tinyjwt.NewClaims(logged.Id, 86400))
	if err != nil {
		t.Fatal(err)
	}

	// Request con JWT en cookie → debe autenticar
	ctx := &mock.Context{}
	ctx.SetCookie(router.Cookie{Name: "session", Value: token})
	var authID string
	m.Authenticate()(func(c router.Context) {
		authID = c.UserID()
	})(ctx)
	if authID != logged.Id {
		t.Errorf("JWT middleware: expected user %s, got %q", logged.Id, authID)
	}

	// Token inválido → anónimo
	ctx2 := &mock.Context{}
	ctx2.SetCookie(router.Cookie{Name: "session", Value: "invalid.jwt.token"})
	authID = ""
	m.Authenticate()(func(c router.Context) {
		authID = c.UserID()
	})(ctx2)
	if authID != "" {
		t.Errorf("want empty userID for invalid JWT, got %q", authID)
	}
}

func testInit(t *testing.T) {
	db := newTestDB(t)
	cfg := auth.Config{
		IDs:        testIDs,
		CookieName: "test_session",
		TokenTTL:   3600,
	}
	m, err := authority.New(db, cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	m.Enable(emailpassword.New(m, m, m))
	_ = m // to be used later
}

func getHandler(m *authority.Module, name string) interface {
	Create(any) (any, error)
	Read(string) (any, error)
	Update(any) (any, error)
	Delete(string) error
} {
	for _, h := range m.Add() {
		if hr, ok := h.(interface{ HandlerName() string }); ok && hr.HandlerName() == name {
			return h.(interface {
				Create(any) (any, error)
				Read(string) (any, error)
				Update(any) (any, error)
				Delete(string) error
			})
		}
	}
	return nil
}

func testCRUD(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}

	userCRUD := getHandler(m, "users")
	if userCRUD == nil {
		t.Fatal("userCRUD handler not found")
	}

	res, err := userCRUD.Create(auth.User{Email: "test@example.com", Name: "Test User", Phone: "123456789"})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	u := res.(auth.User)
	if u.Email != "test@example.com" {
		t.Errorf("expected email 'test@example.com', got '%s'", u.Email)
	}

	res2, err := userCRUD.Read(u.Id)
	if err != nil {
		t.Fatalf("GetUser failed: %v", err)
	}
	u2 := res2.(auth.User)
	if u2.Id != u.Id {
		t.Errorf("expected ID '%s', got '%s'", u.Id, u2.Id)
	}

	u2.Name = "Updated Name"
	res3, err := userCRUD.Update(u2)
	if err != nil {
		t.Fatalf("UpdateUser failed: %v", err)
	}
	u3 := res3.(auth.User)
	if u3.Name != "Updated Name" {
		t.Errorf("expected Name 'Updated Name', got '%s'", u3.Name)
	}
}

func testAuth(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}
	m.Enable(emailpassword.New(m, m, m))

	userCRUD := getHandler(m, "users")
	res, err := userCRUD.Create(auth.User{Email: "auth@example.com", Name: "Auth User"})
	if err != nil {
		t.Fatal(err)
	}
	u := res.(auth.User)

	if err := m.SetPassword(u.Id, "password123"); err != nil {
		t.Fatalf("SetPassword failed: %v", err)
	}

	u2, err := m.Login("auth@example.com", "password123")
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if u2.Id != u.Id {
		t.Errorf("Login returned wrong user")
	}

	_, err = m.Login("auth@example.com", "wrongpass")
	if err != auth.ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}

	if err := m.VerifyPassword(u.Id, "password123"); err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
}

func testSessions(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs, TokenTTL: 3600})
	if err != nil {
		t.Fatal(err)
	}
	m.Enable(emailpassword.New(m, m, m))

	userCRUD := getHandler(m, "users")
	res, err := userCRUD.Create(auth.User{Email: "sess@example.com", Name: "Sess User"})
	if err != nil {
		t.Fatal(err)
	}
	u := res.(auth.User)

	sess, err := m.CreateSession(u.Id, "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Get Session
	s2, err := m.GetSession(sess.Id)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if s2.UserId != u.Id {
		t.Errorf("Session user ID mismatch")
	}

	// Instant expire via SQL
	if err := db.RawConn().Exec("UPDATE session SET expires_at = 0 WHERE id = ?", sess.Id); err != nil {
		t.Fatalf("failed to expire session in DB: %v", err)
	}

	// Re-init to flush memory cache
	m, _ = authority.New(db, auth.Config{IDs: testIDs, TokenTTL: 3600})
	m.Enable(emailpassword.New(m, m, m))

	_, err = m.GetSession(sess.Id)
	if err != auth.ErrSessionExpired {
		t.Errorf("expected ErrSessionExpired, got %v", err)
	}
}

type MockProvider struct {
	NameVal         string
	ExchangeCodeVal auth.OAuthToken
	UserInfoVal     auth.OAuthUserInfo
}

func (m *MockProvider) Name() string                    { return m.NameVal }
func (m *MockProvider) AuthCodeURL(state string) string { return "http://mock/" + state }
func (m *MockProvider) ExchangeCode(code string) (auth.OAuthToken, error) {
	return m.ExchangeCodeVal, nil
}
func (m *MockProvider) GetUserInfo(token auth.OAuthToken) (auth.OAuthUserInfo, error) {
	return m.UserInfoVal, nil
}

func testOAuth(t *testing.T) {
	db := newTestDB(t)
	mockP := &MockProvider{
		NameVal:         "mock",
		ExchangeCodeVal: auth.OAuthToken{AccessToken: "mocktoken"},
		UserInfoVal:     auth.OAuthUserInfo{ID: "mockid", Email: "mock@example.com", Name: "Mock User"},
	}

	cfg := auth.Config{IDs: testIDs}
	m, err := authority.New(db, cfg)
	if err != nil {
		t.Fatal(err)
	}
	m.Enable(oauth2.New(m, m, m, []auth.OAuthProvider{mockP}))

	r := &mock.Router{}
	m.MountAPI(r)

	// Simulate hitting GET /oauth/mock
	ctxBegin := &mock.Context{
		InMethod: "GET",
		InPath:   "/oauth/mock",
	}
	r.Invoke("GET", "/oauth/mock", ctxBegin)
	if ctxBegin.Status != 302 {
		t.Fatalf("expected status 302, got %d", ctxBegin.Status)
	}
	loc := ctxBegin.GetHeader("Location")
	if !strings.HasPrefix(loc, "http://mock/") {
		t.Fatalf("expected redirect to mock URL, got %s", loc)
	}
	state := strings.TrimPrefix(loc, "http://mock/")

	// Simulate hitting GET /oauth/callback/mock
	ctxCallback := &mock.Context{
		InMethod: "GET",
		InPath:   "/oauth/callback/mock?state=" + state + "&code=mockcode",
	}
	if c, ok := ctxBegin.Cookie("oauth_nonce"); ok {
		ctxCallback.SetCookie(c)
	}
	r.Invoke("GET", "/oauth/callback/mock", ctxCallback)
	if ctxCallback.Status != 302 {
		t.Fatalf("expected callback status 302, got %d", ctxCallback.Status)
	}
	if ctxCallback.GetHeader("Location") != auth.PathAfterLogin {
		t.Errorf("expected redirect after login to %s, got %s", auth.PathAfterLogin, ctxCallback.GetHeader("Location"))
	}

	// Verify user got created
	u, err := m.UserByEmail("mock@example.com")
	if err != nil {
		t.Fatalf("expected user mock@example.com to be created: %v", err)
	}
	if u.Name != "Mock User" {
		t.Errorf("expected name 'Mock User', got %s", u.Name)
	}

	// Second login (existing user)
	ctxBegin2 := &mock.Context{
		InMethod: "GET",
		InPath:   "/oauth/mock",
	}
	r.Invoke("GET", "/oauth/mock", ctxBegin2)
	loc2 := ctxBegin2.GetHeader("Location")
	state2 := strings.TrimPrefix(loc2, "http://mock/")

	ctxCallback2 := &mock.Context{
		InMethod: "GET",
		InPath:   "/oauth/callback/mock?state=" + state2 + "&code=mockcode",
	}
	if c, ok := ctxBegin2.Cookie("oauth_nonce"); ok {
		ctxCallback2.SetCookie(c)
	}
	r.Invoke("GET", "/oauth/callback/mock", ctxCallback2)
	if ctxCallback2.Status != 302 {
		t.Fatalf("expected callback 2 status 302, got %d", ctxCallback2.Status)
	}

	// Verify we still have the same user
	u2, err := m.UserByEmail("mock@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if u2.Id != u.Id {
		t.Errorf("expected same user ID, got %s vs %s", u.Id, u2.Id)
	}
}

func testLAN(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs, TrustProxy: true})
	if err != nil {
		t.Fatal(err)
	}
	m.Enable(trustedip.New(m, m, m, m, true))

	userCRUD := getHandler(m, "users")
	res, err := userCRUD.Create(auth.User{Email: "lan@example.com", Name: "LAN User"})
	if err != nil {
		t.Fatal(err)
	}
	u := res.(auth.User)

	if err := m.RegisterLAN(u.Id, "12345678-5"); err != nil {
		t.Fatalf("RegisterLAN failed: %v", err)
	}

	if err := m.AssignLANIP(u.Id, "192.168.1.10", "Home"); err != nil {
		t.Fatalf("AssignLANIP failed: %v", err)
	}

	ctx := &mock.Context{}
	ctx.SetValue("RemoteAddr", "192.168.1.10:1234")

	u2, err := m.LoginLAN("12345678-5", ctx)
	if err != nil {
		t.Fatalf("LoginLAN failed: %v", err)
	}
	if u2.Id != u.Id {
		t.Errorf("expected same user ID")
	}

	_, err = m.LoginLAN("123", ctx)
	if err != auth.ErrInvalidRUT {
		t.Errorf("expected ErrInvalidRUT, got %v", err)
	}

	ctxW := &mock.Context{}
	ctxW.SetValue("RemoteAddr", "10.0.0.1:1234")
	_, err = m.LoginLAN("12345678-5", ctxW)
	if err != auth.ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials for wrong IP, got %v", err)
	}

	ctxP := &mock.Context{}
	ctxP.SetValue("RemoteAddr", "10.0.0.1:1234")
	ctxP.SetHeader("X-Forwarded-For", "192.168.1.10")
	u3, err := m.LoginLAN("12345678-5", ctxP)
	if err != nil {
		t.Fatalf("LoginLAN with proxy failed: %v", err)
	}
	if u3.Id != u.Id {
		t.Errorf("expected same user ID")
	}

	if err := m.RevokeLANIP(u.Id, "192.168.1.10"); err != nil {
		t.Fatalf("RevokeLANIP failed: %v", err)
	}

	_, err = m.LoginLAN("12345678-5", ctxP)
	if err != auth.ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials after revoke, got %v", err)
	}

	if err := m.UnregisterLAN(u.Id); err != nil {
		t.Fatalf("UnregisterLAN failed: %v", err)
	}

	_, err = m.LoginLAN("12345678-5", ctxP)
	if err != auth.ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials after unregister, got %v", err)
	}
}

func setupModule(t *testing.T) *authority.Module {
	db := newTestDB(t)
	m, _ := authority.New(db, auth.Config{IDs: testIDs})
	m.Enable(emailpassword.New(m, m, m))
	return m
}
