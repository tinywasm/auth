//go:build !wasm

package tests

import (
	"testing"

	"github.com/tinywasm/auth"
	"github.com/tinywasm/auth/authority"
	jwtstrategy "github.com/tinywasm/auth/session/jwt"
	"github.com/tinywasm/router"
	"github.com/tinywasm/router/mock"
)

// TestWithDomain_Issue proves WithDomain(".velty.cl") produces a
// router.Cookie with that Domain on Issue, and that a Strategy that never
// calls it keeps Domain empty — behavior unchanged for every existing
// caller of jwt.Strategy that predates this method.
func TestWithDomain_Issue(t *testing.T) {
	secret := []byte("test-secret-32-bytes-long-000000")
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}
	userCRUD := getHandler(m, "users")
	res, err := userCRUD.Create(auth.User{Email: "sso@test.com", Name: "SSO"})
	if err != nil {
		t.Fatal(err)
	}
	u := res.(auth.User)

	t.Run("with WithDomain", func(t *testing.T) {
		strategy, err := jwtstrategy.New(secret, 0, m, m)
		if err != nil {
			t.Fatal(err)
		}
		strategy.WithDomain(".velty.cl")

		ctx := &mock.Context{}
		if err := strategy.Issue(ctx, u.Id); err != nil {
			t.Fatal(err)
		}
		c, ok := ctx.Cookie("session")
		if !ok {
			t.Fatal("Issue did not set the session cookie")
		}
		if c.Domain != ".velty.cl" {
			t.Errorf("Domain: got %q, want %q", c.Domain, ".velty.cl")
		}
	})

	t.Run("without WithDomain", func(t *testing.T) {
		strategy, err := jwtstrategy.New(secret, 0, m, m)
		if err != nil {
			t.Fatal(err)
		}

		ctx := &mock.Context{}
		if err := strategy.Issue(ctx, u.Id); err != nil {
			t.Fatal(err)
		}
		c, ok := ctx.Cookie("session")
		if !ok {
			t.Fatal("Issue did not set the session cookie")
		}
		if c.Domain != "" {
			t.Errorf("Domain: got %q, want empty (unchanged default)", c.Domain)
		}
	})
}

// TestWithDomain_Revoke proves the deletion cookie Revoke sets also carries
// the configured Domain — a delete cookie with the wrong Domain deletes
// nothing.
func TestWithDomain_Revoke(t *testing.T) {
	secret := []byte("test-secret-32-bytes-long-000000")
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}

	strategy, err := jwtstrategy.New(secret, 0, m, m)
	if err != nil {
		t.Fatal(err)
	}
	strategy.WithDomain(".velty.cl")

	ctx := &mock.Context{}
	if err := strategy.Revoke(ctx); err != nil {
		t.Fatal(err)
	}
	c, ok := ctx.Cookie("session")
	if !ok {
		t.Fatal("Revoke did not set the deletion cookie")
	}
	if c.Domain != ".velty.cl" {
		t.Errorf("Domain: got %q, want %q", c.Domain, ".velty.cl")
	}
	if c.MaxAge != -1 {
		t.Errorf("MaxAge: got %d, want -1 (delete)", c.MaxAge)
	}
}

// TestWithDomain_SameSiteStays proves SameSite stays Strict — this method
// must not be used as a workaround for a SameSite problem (see
// veltylabs/iam/docs/ARCHITECTURE.md §7).
func TestWithDomain_SameSiteStays(t *testing.T) {
	secret := []byte("test-secret-32-bytes-long-000000")
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}
	userCRUD := getHandler(m, "users")
	res, err := userCRUD.Create(auth.User{Email: "samesite@test.com", Name: "SameSite"})
	if err != nil {
		t.Fatal(err)
	}
	u := res.(auth.User)

	strategy, err := jwtstrategy.New(secret, 0, m, m)
	if err != nil {
		t.Fatal(err)
	}
	strategy.WithDomain(".velty.cl")

	ctx := &mock.Context{}
	if err := strategy.Issue(ctx, u.Id); err != nil {
		t.Fatal(err)
	}
	c, _ := ctx.Cookie("session")
	if c.SameSite != router.SameSiteStrict {
		t.Errorf("SameSite: got %v, want Strict", c.SameSite)
	}
}
