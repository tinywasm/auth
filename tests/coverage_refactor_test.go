//go:build !wasm

package tests

import (
	"strings"
	"testing"

	"github.com/tinywasm/json"
	"github.com/tinywasm/model"
	"github.com/tinywasm/router"
	"github.com/tinywasm/router/mock"
	"github.com/tinywasm/auth"
	"github.com/tinywasm/auth/authority"
	emailpassword "github.com/tinywasm/auth/email_password"
	"github.com/tinywasm/auth/oauth2"
	"github.com/tinywasm/auth/session/cookie"
	jwt "github.com/tinywasm/auth/session/jwt"
	trustedip "github.com/tinywasm/auth/trusted_ip"
)

func TestCoverage_SessionCookie(t *testing.T) {
	db := newTestDB(t)
	m, _ := authority.New(db, auth.Config{IDs: testIDs})

	strategy := cookie.New(m, "custom_cookie", 3600, false)

	t.Run("Round-trip session cookie success", func(t *testing.T) {
		userCRUD := getHandler(m, "users")
		res, _ := userCRUD.Create(auth.User{Email: "cookie@test.com", Name: "Cookie User"})
		u := res.(auth.User)

		ctx := &mock.Context{}
		if err := strategy.Issue(ctx, u.Id); err != nil {
			t.Fatal(err)
		}

		c, ok := ctx.Cookie("custom_cookie")
		if !ok || c.Value == "" {
			t.Fatal("cookie not set")
		}

		ctx2 := &mock.Context{}
		ctx2.SetCookie(c)

		uid, err := strategy.Identify(ctx2)
		if err != nil {
			t.Fatal(err)
		}
		if uid != u.Id {
			t.Errorf("expected %s, got %s", u.Id, uid)
		}

		// Revoke
		ctx3 := &mock.Context{}
		ctx3.SetCookie(c)
		if err := strategy.Revoke(ctx3); err != nil {
			t.Fatal(err)
		}

		// Check session is revoked
		ctx4 := &mock.Context{}
		ctx4.SetCookie(c)
		_, err = strategy.Identify(ctx4)
		if err == nil {
			t.Error("expected error for revoked session")
		}
	})

	t.Run("Non-existent cookie returns ErrSessionExpired", func(t *testing.T) {
		ctx := &mock.Context{}
		_, err := strategy.Identify(ctx)
		if err != auth.ErrSessionExpired {
			t.Errorf("expected ErrSessionExpired, got %v", err)
		}
	})
}

func TestCoverage_SessionJWT(t *testing.T) {
	db := newTestDB(t)
	m, _ := authority.New(db, auth.Config{IDs: testIDs})

	userCRUD := getHandler(m, "users")
	res, _ := userCRUD.Create(auth.User{Email: "jwt_cov@test.com", Name: "JWT Cov User"})
	u := res.(auth.User)

	secret := []byte("my-test-secret-must-be-long-32-")
	strategy, err := jwt.New(secret, 3600, m, m)
	if err != nil {
		t.Fatal(err)
	}

	strategy.WithCookieName("my_jwt_cookie")

	t.Run("GenerateAPIToken round-trip", func(t *testing.T) {
		token, err := strategy.GenerateAPIToken(u.Id, 0)
		if err != nil {
			t.Fatal(err)
		}

		// Verify with Bearer Strategy
		bearerStrategy, _ := jwt.New(secret, 3600, m, m)
		bearerStrategy.AsBearer()

		ctx := &mock.Context{}
		ctx.SetHeader("Authorization", "Bearer "+token)

		uid, err := bearerStrategy.Identify(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if uid != u.Id {
			t.Errorf("expected %s, got %s", u.Id, uid)
		}

		// Issue and Revoke in Bearer Mode
		ctxIssue := &mock.Context{}
		if err := bearerStrategy.Issue(ctxIssue, u.Id); err != nil {
			t.Fatal(err)
		}
		if err := bearerStrategy.Revoke(ctxIssue); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Identify with forged token", func(t *testing.T) {
		pub := &mockPublisher{}
		mNotifying, _ := authority.New(db, auth.Config{IDs: testIDs, Events: pub})
		notifyingStrategy, _ := jwt.New(secret, 3600, mNotifying, mNotifying)

		ctx := &mock.Context{}
		ctx.SetCookie(router.Cookie{Name: "session", Value: "completely.forged.token"})

		_, err := notifyingStrategy.Identify(ctx)
		if err == nil {
			t.Error("expected error for forged token")
		}

		found := false
		for _, ev := range pub.SecurityEvents() {
			if ev.Type == auth.EventJWTTampered {
				found = true
			}
		}
		if !found {
			t.Error("expected EventJWTTampered security event")
		}
	})
}

func TestCoverage_EmailPassword(t *testing.T) {
	db := newTestDB(t)
	pub := &mockPublisher{}
	m, _ := authority.New(db, auth.Config{IDs: testIDs, Events: pub})

	userCRUD := getHandler(m, "users")
	res, _ := userCRUD.Create(auth.User{Email: "ep_cov@test.com", Name: "EP Cov User"})
	u := res.(auth.User)
	_ = m.SetPassword(u.Id, "password123")

	r := &mock.Router{}
	m.Enable(emailpassword.New(m, m, m, emailpassword.WithTrustProxy(true), emailpassword.WithAfterLogin("/custom_after")))
	m.MountAPI(r)

	t.Run("Rate limit error emission", func(t *testing.T) {
		blockedIP := "100.100.100.100"
		rateLimitFn := func(ip string) error {
			if ip == blockedIP {
				return auth.ErrInvalidCredentials
			}
			return nil
		}

		// Recreate with rate limit
		m2, _ := authority.New(db, auth.Config{IDs: testIDs, Events: pub})
		m2.Enable(emailpassword.New(m2, m2, m2, emailpassword.WithRateLimit(rateLimitFn)))
		r2 := &mock.Router{}
		m2.MountAPI(r2)

		ctx := &mock.Context{
			InMethod: "POST",
			InPath:   auth.PathLogin,
		}
		ctx.SetValue("RemoteAddr", blockedIP+":1234")
		ctx.SetHeader("Content-Type", "application/json")
		json.Encode(&auth.LoginData{Email: "ep_cov@test.com", Password: "password123"}, &ctx.InBody)

		r2.Invoke("POST", auth.PathLogin, ctx)
		if ctx.Status != 429 {
			t.Errorf("expected 429, got %d", ctx.Status)
		}

		found := false
		for _, ev := range pub.SecurityEvents() {
			if ev.Type == auth.EventRateLimited && ev.IP == blockedIP {
				found = true
			}
		}
		if !found {
			t.Error("expected EventRateLimited security event for rate-limited IP")
		}
	})

	t.Run("Wrong password with DummyCompare", func(t *testing.T) {
		ctx := &mock.Context{
			InMethod: "POST",
			InPath:   auth.PathLogin,
		}
		ctx.SetHeader("Content-Type", "application/json")
		json.Encode(&auth.LoginData{Email: "ep_cov@test.com", Password: "wrong_password"}, &ctx.InBody)

		r.Invoke("POST", auth.PathLogin, ctx)
		if ctx.Status != 401 {
			t.Errorf("expected 401, got %d", ctx.Status)
		}
	})

	t.Run("Login with suspended user", func(t *testing.T) {
		m.SuspendUser(u.Id)

		ctx := &mock.Context{
			InMethod: "POST",
			InPath:   auth.PathLogin,
		}
		ctx.SetHeader("Content-Type", "application/json")
		json.Encode(&auth.LoginData{Email: "ep_cov@test.com", Password: "password123"}, &ctx.InBody)

		r.Invoke("POST", auth.PathLogin, ctx)
		if ctx.Status != 401 {
			t.Errorf("expected 401, got %d", ctx.Status)
		}

		// Reactivate
		m.ReactivateUser(u.Id)
	})
}

func TestCoverage_TrustedIP(t *testing.T) {
	db := newTestDB(t)
	pub := &mockPublisher{}
	m, _ := authority.New(db, auth.Config{IDs: testIDs, Events: pub})

	userCRUD := getHandler(m, "users")
	res, _ := userCRUD.Create(auth.User{Email: "ip_cov@test.com", Name: "IP Cov User"})
	u := res.(auth.User)

	_ = m.RegisterLAN(u.Id, "12345678-5")
	_ = m.AssignLANIP(u.Id, "192.168.10.10", "Office")

	r := &mock.Router{}
	m.Enable(trustedip.New(m, m, m, m, true, trustedip.WithAfterLogin("/custom_after")))
	m.MountAPI(r)

	t.Run("RUT valid and trusted IP success", func(t *testing.T) {
		ctx := &mock.Context{
			InMethod: "POST",
			InPath:   "/login/rut",
		}
		ctx.SetHeader("Content-Type", "application/json")
		ctx.SetValue("RemoteAddr", "192.168.10.10:1234")
		ctx.InBody = []byte(`{"rut":"12345678-5"}`)

		r.Invoke("POST", "/login/rut", ctx)
		if ctx.Status != 302 {
			t.Errorf("expected 302, got %d", ctx.Status)
		}
	})

	t.Run("RUT valid but IP mismatch", func(t *testing.T) {
		ctx := &mock.Context{
			InMethod: "POST",
			InPath:   "/login/rut",
		}
		ctx.SetHeader("Content-Type", "application/json")
		ctx.SetValue("RemoteAddr", "192.168.10.99:1234")
		ctx.InBody = []byte(`{"rut":"12345678-5"}`)

		r.Invoke("POST", "/login/rut", ctx)
		if ctx.Status != 401 {
			t.Errorf("expected 401, got %d", ctx.Status)
		}

		found := false
		for _, ev := range pub.SecurityEvents() {
			if ev.Type == auth.EventIPMismatch && ev.IP == "192.168.10.99" {
				found = true
			}
		}
		if !found {
			t.Error("expected EventIPMismatch security event")
		}
	})

	t.Run("RUT invalid does not touch store", func(t *testing.T) {
		ctx := &mock.Context{
			InMethod: "POST",
			InPath:   "/login/rut",
		}
		ctx.SetHeader("Content-Type", "application/json")
		ctx.InBody = []byte(`{"rut":"invalid-rut"}`)

		r.Invoke("POST", "/login/rut", ctx)
		if ctx.Status != 401 {
			t.Errorf("expected 401, got %d", ctx.Status)
		}
	})
}

func TestCoverage_OAuth2(t *testing.T) {
	db := newTestDB(t)
	m, _ := authority.New(db, auth.Config{IDs: testIDs})

	mockP := &MockProvider{
		NameVal:         "covmock",
		ExchangeCodeVal: auth.OAuthToken{AccessToken: "covtoken"},
		UserInfoVal:     auth.OAuthUserInfo{ID: "cSubject", Email: "c@test.com", Name: "Cov OAuth User", EmailVerified: true},
	}

	r := &mock.Router{}
	m.Enable(oauth2.New(m, m, m, []auth.OAuthProvider{mockP}, oauth2.WithAfterLogin("/custom_after")))
	m.MountAPI(r)

	t.Run("Replay state token error", func(t *testing.T) {
		ctxBegin := &mock.Context{InMethod: "GET", InPath: "/oauth/covmock"}
		r.Invoke("GET", "/oauth/covmock", ctxBegin)
		loc := ctxBegin.GetHeader("Location")
		state := strings.TrimPrefix(loc, "http://mock/")

		// Consume it once successfully
		ctxCallback1 := &mock.Context{
			InMethod: "GET",
			InPath:   "/oauth/callback/covmock?state=" + state + "&code=mockcode",
		}
		if nonceCookie, ok := ctxBegin.Cookie("oauth_nonce"); ok {
			ctxCallback1.SetCookie(nonceCookie)
		}
		r.Invoke("GET", "/oauth/callback/covmock", ctxCallback1)
		if ctxCallback1.Status != 302 {
			t.Fatalf("first callback failed: %d", ctxCallback1.Status)
		}

		// Replay it (must fail since ConsumeState is single-use)
		ctxCallback2 := &mock.Context{
			InMethod: "GET",
			InPath:   "/oauth/callback/covmock?state=" + state + "&code=mockcode",
		}
		if nonceCookie, ok := ctxBegin.Cookie("oauth_nonce"); ok {
			ctxCallback2.SetCookie(nonceCookie)
		}
		r.Invoke("GET", "/oauth/callback/covmock", ctxCallback2)
		if ctxCallback2.Status != 401 {
			t.Errorf("expected 401 on replay, got %d", ctxCallback2.Status)
		}
	})

	t.Run("Vínculo a usuario existente por email", func(t *testing.T) {
		// Create a local user first with the same email
		userCRUD := getHandler(m, "users")
		_, err := userCRUD.Create(auth.User{Email: "link@test.com", Name: "Existing Local"})
		if err != nil {
			t.Fatal(err)
		}

		mockP2 := &MockProvider{
			NameVal:         "covmock2",
			ExchangeCodeVal: auth.OAuthToken{AccessToken: "covtoken2"},
			UserInfoVal:     auth.OAuthUserInfo{ID: "cSubject2", Email: "link@test.com", Name: "Same Email OAuth", EmailVerified: true},
		}

		m.Enable(oauth2.New(m, m, m, []auth.OAuthProvider{mockP2}))
		m.MountAPI(r)

		ctxBegin := &mock.Context{InMethod: "GET", InPath: "/oauth/covmock2"}
		r.Invoke("GET", "/oauth/covmock2", ctxBegin)
		loc := ctxBegin.GetHeader("Location")
		state := strings.TrimPrefix(loc, "http://mock/")

		ctxCallback := &mock.Context{
			InMethod: "GET",
			InPath:   "/oauth/callback/covmock2?state=" + state + "&code=mockcode",
		}
		if nonceCookie, ok := ctxBegin.Cookie("oauth_nonce"); ok {
			ctxCallback.SetCookie(nonceCookie)
		}
		r.Invoke("GET", "/oauth/callback/covmock2", ctxCallback)
		if ctxCallback.Status != 302 {
			t.Fatalf("expected 302, got %d", ctxCallback.Status)
		}

		// Verify that they are the same user (vínculo exitoso)
		idRow, err := m.IdentityByProvider("covmock2", "cSubject2")
		if err != nil {
			t.Fatal("failed to find linked identity:", err)
		}

		u, err := m.UserByID(idRow.UserId)
		if err != nil {
			t.Fatal(err)
		}
		if u.Email != "link@test.com" {
			t.Errorf("expected linked email, got %s", u.Email)
		}
	})
}

func TestCoverage_CompositionIsolatedRoutes(t *testing.T) {
	db := newTestDB(t)
	m, _ := authority.New(db, auth.Config{IDs: testIDs})

	// Enable only email_password
	m.Enable(emailpassword.New(m, m, m))

	r := &mock.Router{}
	m.MountAPI(r)

	// Validate registered routes
	hasLogin := false
	hasRUTLogin := false

	for _, rt := range r.Routes() {
		if rt.Path == auth.PathLogin {
			hasLogin = true
		}
		if rt.Path == "/login/rut" {
			hasRUTLogin = true
		}
	}

	if !hasLogin {
		t.Error("expected login route to be mounted")
	}
	if hasRUTLogin {
		t.Error("did not expect /login/rut route to be mounted since trusted_ip is not enabled")
	}
}

func TestCoverage_SecurityEventEncode(t *testing.T) {
	e := &auth.SecurityEvent{
		Type:      auth.EventJWTTampered,
		IP:        "127.0.0.1",
		UserID:    "u1",
		Provider:  "google",
		Resource:  "res",
		Timestamp: 123456,
	}
	if e.IsNil() {
		t.Error("expected non-nil")
	}
	var out string
	if err := json.Encode(e, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"type":0`) {
		t.Errorf("unexpected json: %s", out)
	}
}

func TestCoverage_AuthorityPortsAndHelper(t *testing.T) {
	db := newTestDB(t)
	m, _ := authority.New(db, auth.Config{IDs: testIDs})

	m.SetLog(func(args ...any) {})

	if err := m.PurgeExpiredOAuthStates(); err != nil {
		t.Fatal(err)
	}

	createdUser, err := m.CreateUser("new_user@test.com", "New User", "123")
	if err != nil {
		t.Fatal(err)
	}
	if createdUser.Email != "new_user@test.com" {
		t.Errorf("expected email new_user@test.com, got %s", createdUser.Email)
	}
}

func TestCoverage_OAuthTokenDecode(t *testing.T) {
	tok := &auth.OAuthToken{}
	if tok.IsNil() {
		t.Error("expected non-nil")
	}
	var in = `{"access_token":"token123","token_type":"Bearer","expires_in":3600}`
	if err := json.Decode([]byte(in), tok); err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "token123" || tok.TokenType != "Bearer" || tok.ExpiresIn != 3600 {
		t.Errorf("unexpected decoded values: %+v", tok)
	}
}

func TestCoverage_GeneratedTypes(t *testing.T) {
	models := []model.Model{
		&auth.User{},
		&auth.Identity{}, &auth.LANIP{},
		&auth.OAuthState{},
		&auth.Session{},
	}
	for _, m := range models {
		_ = m.ModelName()
		_ = m.Schema()
		_ = m.Pointers()
		_ = m.IsNil()

		var out string
		_ = json.Encode(m, &out)
		_ = json.Decode([]byte(out), m)
	}

	lists := []model.ModelSlice{
		&auth.UserList{},
		&auth.IdentityList{}, &auth.LANIPList{},
		&auth.OAuthStateList{},
		&auth.SessionList{},
	}
	for _, l := range lists {
		_ = l.Schema()
		_ = l.Pointers()
		_ = l.Len()
		_ = l.IsNil()
		_ = l.Append()
		_ = l.At(0)
		_ = l.Len()
	}
}
