//go:build !wasm

package tests

import (
	"errors"
	"strings"
	"testing"

	"github.com/tinywasm/json"
	"github.com/tinywasm/model"
	"github.com/tinywasm/router"
	"github.com/tinywasm/router/mock"
	"github.com/tinywasm/auth"
	"github.com/tinywasm/auth/authority"
	emailpassword "github.com/tinywasm/auth/email_password"
	"github.com/tinywasm/auth/session/jwt"
)

func TestCookieSecurity(t *testing.T) {
	login := func(m *authority.Module, cookieName, email, pass string) router.Cookie {
		r := &mock.Router{}
		m.MountAPI(r)

		loginData := &auth.LoginData{Email: email, Password: pass}
		var postBody string
		json.Encode(loginData, &postBody)
		ctx := &mock.Context{
			InMethod: "POST",
			InPath:   auth.PathLogin,
			InBody:   []byte(postBody),
		}
		ctx.SetHeader("Content-Type", "application/json")

		r.Invoke("POST", auth.PathLogin, ctx)
		if ctx.Status != 302 {
			t.Fatalf("login failed: status %d, body %s", ctx.Status, string(ctx.ResponseBody()))
		}

		c, ok := ctx.Cookie(cookieName)
		if !ok {
			t.Fatal("no cookie set")
		}
		return c
	}

	t.Run("Cookie Mode Flags", func(t *testing.T) {
		db := newTestDB(t)
		m, err := authority.New(db, auth.Config{IDs: testIDs, TokenTTL: 3600, CookieName: "session"})
		if err != nil {
			t.Fatalf("authority.New failed: %v", err)
		}
		m.Enable(emailpassword.New(m, m, m))
		email, pass := "cookie1@example.com", "password123"
		if err := m.Bootstrap(authority.Seed{Email: email, Password: pass, Name: "Admin", Role: "admin", Grants: []model.Grant{{Resource: model.Wildcard, Actions: model.AllActions}}}); err != nil {
			t.Fatal(err)
		}

		c := login(m, "session", email, pass)

		if c.Name != "session" {
			t.Errorf("expected cookie name 'session', got %s", c.Name)
		}
		if !c.HttpOnly {
			t.Errorf("expected HttpOnly=true")
		}
		if !c.Secure {
			t.Errorf("expected Secure=true")
		}
		if c.SameSite != router.SameSiteStrict {
			t.Errorf("expected SameSite=Strict, got %v", c.SameSite)
		}
		if c.Path != "/" {
			t.Errorf("expected Path=/, got %s", c.Path)
		}
		if c.MaxAge != 3600 {
			t.Errorf("expected MaxAge=3600, got %d", c.MaxAge)
		}
	})

	t.Run("JWT Mode Cookie", func(t *testing.T) {
		db := newTestDB(t)
		m, err := authority.New(db, auth.Config{IDs: testIDs, TokenTTL: 7200, CookieName: "session"})
		if err != nil {
			t.Fatalf("authority.New failed: %v", err)
		}
		strategy, err := jwt.New([]byte("sec"), 7200, m, m)
		if err != nil {
			t.Fatal(err)
		}
		m.SetStrategy(strategy)
		m.Enable(emailpassword.New(m, m, m))
		email, pass := "cookie2@example.com", "password123"
		if err := m.Bootstrap(authority.Seed{Email: email, Password: pass, Name: "Admin", Role: "admin", Grants: []model.Grant{{Resource: model.Wildcard, Actions: model.AllActions}}}); err != nil {
			t.Fatal(err)
		}

		c := login(m, "session", email, pass)

		if !c.HttpOnly || !c.Secure || c.SameSite != router.SameSiteStrict {
			t.Errorf("JWT cookie missing security flags")
		}

		parts := strings.Split(c.Value, ".")
		if len(parts) != 3 {
			t.Errorf("expected JWT value (3 parts), got %d parts", len(parts))
		}
	})

	t.Run("Custom Cookie Name", func(t *testing.T) {
		db := newTestDB(t)
		m, err := authority.New(db, auth.Config{IDs: testIDs, CookieName: "custom_auth"})
		if err != nil {
			t.Fatalf("authority.New failed: %v", err)
		}
		m.Enable(emailpassword.New(m, m, m))
		email, pass := "cookie3@example.com", "password123"
		if err := m.Bootstrap(authority.Seed{Email: email, Password: pass, Name: "Admin", Role: "admin", Grants: []model.Grant{{Resource: model.Wildcard, Actions: model.AllActions}}}); err != nil {
			t.Fatal(err)
		}

		c := login(m, "custom_auth", email, pass)

		if c.Name != "custom_auth" {
			t.Errorf("expected cookie name 'custom_auth', got %s", c.Name)
		}
	})
}

func TestSessionRotation(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs, TokenTTL: 3600})
	if err != nil {
		t.Fatalf("authority.New failed: %v", err)
	}
	m.Enable(emailpassword.New(m, m, m))

	userCRUD := getHandler(m, "users")
	res, err := userCRUD.Create(auth.User{Email: "rot@example.com", Name: "Rot"})
	if err != nil {
		t.Fatalf("userCRUD.Create failed: %v", err)
	}
	u := res.(auth.User)

	t.Run("RotateSession valid", func(t *testing.T) {
		sess1, _ := m.CreateSession(u.Id, "10.0.0.1", "ua1")

		sess2, err := m.RotateSession(sess1.Id, "10.0.0.2", "ua2")
		if err != nil {
			t.Fatalf("RotateSession failed: %v", err)
		}

		if sess2.Id == sess1.Id {
			t.Errorf("expected new session ID")
		}
		if sess2.UserId != u.Id {
			t.Errorf("expected same UserId")
		}
		if sess2.Ip != "10.0.0.2" {
			t.Errorf("expected updated IP")
		}

		// Ensure old session is gone
		_, err = m.GetSession(sess1.Id)
		if err != auth.ErrNotFound {
			t.Errorf("expected ErrNotFound for old session, got %v", err)
		}
	})

	t.Run("RotateSession expired", func(t *testing.T) {
		sess3, _ := m.CreateSession(u.Id, "10.0.0.1", "ua1")
		// Manually expire
		db.RawConn().Exec("UPDATE session SET expires_at = 0 WHERE id = ?", sess3.Id)
		m, err = authority.New(db, auth.Config{IDs: testIDs, TokenTTL: 3600}) // Clear cache
		if err != nil {
			t.Fatalf("authority.New failed: %v", err)
		}
		m.Enable(emailpassword.New(m, m, m))

		_, err := m.RotateSession(sess3.Id, "10.0.0.1", "ua1")
		if err != auth.ErrSessionExpired {
			t.Errorf("expected ErrSessionExpired, got %v", err)
		}
	})

	t.Run("RotateSession not found", func(t *testing.T) {
		_, err := m.RotateSession("nope", "10.0.0.1", "ua1")
		if err != auth.ErrNotFound {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("Middleware Continuity", func(t *testing.T) {
		sessOld, _ := m.CreateSession(u.Id, "10.0.0.1", "ua1")
		sessNew, _ := m.RotateSession(sessOld.Id, "10.0.0.1", "ua1")

		ctxOld := &mock.Context{}
		ctxOld.SetCookie(router.Cookie{Name: "session", Value: sessOld.Id})
		var authID string
		m.Authenticate()(func(c router.Context) {
			authID = c.UserID()
		})(ctxOld)
		if authID != "" {
			t.Errorf("expected empty identity for old session")
		}

		ctxNew := &mock.Context{}
		ctxNew.SetCookie(router.Cookie{Name: "session", Value: sessNew.Id})
		m.Authenticate()(func(c router.Context) {
			authID = c.UserID()
		})(ctxNew)
		if authID != u.Id {
			t.Errorf("expected identity %s for new session, got %q", u.Id, authID)
		}
	})
}

func TestPasswordHook(t *testing.T) {
	db := newTestDB(t)

	errHook := errors.New("custom password hook error")
	cfg := auth.Config{
		IDs: testIDs,
		OnPasswordValidate: func(password string) error {
			if strings.Contains(password, "bad") {
				return errHook
			}
			return nil
		},
	}
	m, err := authority.New(db, cfg)
	if err != nil {
		t.Fatalf("authority.New failed: %v", err)
	}
	m.Enable(emailpassword.New(m, m, m))

	userCRUD := getHandler(m, "users")
	resU, err := userCRUD.Create(auth.User{Email: "hook@example.com", Name: "Hook"})
	if err != nil {
		t.Fatalf("userCRUD.Create failed: %v", err)
	}
	u := resU.(auth.User)
	_ = m.SetPassword(u.Id, "goodpass123") // Baseline

	t.Run("Hook rejection", func(t *testing.T) {
		err := m.SetPassword(u.Id, "thisisbadpass")
		if err != errHook {
			t.Errorf("expected custom hook error, got %v", err)
		}

		// Old password should still work
		if err := m.VerifyPassword(u.Id, "goodpass123"); err != nil {
			t.Errorf("expected old password to still be valid")
		}
	})

	t.Run("Hook success", func(t *testing.T) {
		err := m.SetPassword(u.Id, "thisisokpass")
		if err != nil {
			t.Errorf("expected nil, got %v", err)
		}

		if err := m.VerifyPassword(u.Id, "thisisokpass"); err != nil {
			t.Errorf("expected new password to work")
		}
	})

	t.Run("Length runs before hook", func(t *testing.T) {
		err := m.SetPassword(u.Id, "bad") // short and "bad"
		if err != auth.ErrWeakPassword {
			t.Errorf("expected ErrWeakPassword, got %v", err)
		}
	})
}
