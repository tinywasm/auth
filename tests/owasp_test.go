//go:build !wasm

package tests

import (
	"testing"

	"github.com/tinywasm/json"
	"github.com/tinywasm/router/mock"
	"github.com/tinywasm/auth"
	"github.com/tinywasm/auth/authority"
	emailpassword "github.com/tinywasm/auth/email_password"
)

func TestOWASP(t *testing.T) {
	db := newTestDB(t)
	m, _ := authority.New(db, auth.Config{IDs: testIDs})
	m.Enable(emailpassword.New(m, m, m))

	email := "active@test.com"
	pass := "password123"
	admin, err := m.CreateUser(email, "Admin", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetPassword(admin.Id, pass); err != nil {
		t.Fatal(err)
	}

	suspended := "suspended@test.com"
	uSuspNew, err := m.CreateUser(suspended, "Suspended", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetPassword(uSuspNew.Id, pass); err != nil {
		t.Fatal(err)
	}
	m.SuspendUser(uSuspNew.Id)

	t.Run("Uniform 401 Responses", func(t *testing.T) {
		r := &mock.Router{}
		m.MountAPI(r)

		cases := []struct {
			name  string
			email string
			pass  string
		}{
			{"Non-existent user", "nonexistent@test.com", "anypass"},
			{"Existing user, wrong pass", email, "wrongpass"},
			{"Suspended user, right pass", suspended, pass},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				loginData := &auth.LoginData{Email: tc.email, Password: tc.pass}
				var body string
				json.Encode(loginData, &body)
				ctx := &mock.Context{
					InMethod: "POST",
					InPath:   auth.PathLogin,
					InBody:   []byte(body),
				}
				ctx.SetHeader("Content-Type", "application/json")
				r.Invoke("POST", auth.PathLogin, ctx)

				if ctx.Status != 401 {
					t.Errorf("expected 401, got %d", ctx.Status)
				}
				if string(ctx.ResponseBody()) != "access denied" {
					t.Errorf("expected 'access denied', got %q", string(ctx.ResponseBody()))
				}
			})
		}
	})

	t.Run("Rate Limit Hook", func(t *testing.T) {
		db := newTestDB(t)
		pub := &mockPublisher{}
		m, _ := authority.New(db, auth.Config{
			IDs:    testIDs,
			Events: pub,
		})
		rateLimitFn := func(ip string) error {
			if ip == "1.2.3.4" {
				return auth.ErrInvalidCredentials // Simulating rejection
			}
			return nil
		}
		m.Enable(emailpassword.New(m, m, m, emailpassword.WithRateLimit(rateLimitFn)))
		r := &mock.Router{}
		m.MountAPI(r)

		t.Run("Blocked IP", func(t *testing.T) {
			// Clear events
			pub.mu.Lock()
			pub.events = nil
			pub.mu.Unlock()

			ctx := &mock.Context{
				InMethod: "POST",
				InPath:   auth.PathLogin,
			}
			ctx.SetValue("RemoteAddr", "1.2.3.4:1234")
			ctx.SetHeader("Content-Type", "application/json")
			json.Encode(&auth.LoginData{Email: email, Password: pass}, &ctx.InBody)

			r.Invoke("POST", auth.PathLogin, ctx)
			if ctx.Status != 429 {
				t.Errorf("expected 429, got %d", ctx.Status)
			}

			found := false
			for _, e := range pub.SecurityEvents() {
				if e.Type == auth.EventRateLimited {
					found = true
					if e.UserID != email {
						t.Errorf("expected UserID %s, got %s", email, e.UserID)
					}
					if e.IP != "1.2.3.4" {
						t.Errorf("expected IP 1.2.3.4, got %s", e.IP)
					}
				}
			}
			if !found {
				t.Error("EventRateLimited not found in security events")
			}
		})

		t.Run("Allowed IP", func(t *testing.T) {
			ctx := &mock.Context{
				InMethod: "POST",
				InPath:   auth.PathLogin,
			}
			ctx.SetValue("RemoteAddr", "5.6.7.8:1234")
			ctx.SetHeader("Content-Type", "application/json")
			json.Encode(&auth.LoginData{Email: email, Password: pass}, &ctx.InBody)

			r.Invoke("POST", auth.PathLogin, ctx)
			// Status should be 401 (access denied) because user doesn't exist in this new DB,
			// but NOT 429.
			if ctx.Status != 401 {
				t.Errorf("expected 401, got %d", ctx.Status)
			}
		})
	})
}
