//go:build !wasm

package tests

import (
	"testing"

	"github.com/tinywasm/orm"
	"github.com/tinywasm/auth"
	"github.com/tinywasm/auth/authority"
)

func TestSQLBoundary(t *testing.T) {
	db := newTestDB(t)
	m, _ := authority.New(db, auth.Config{IDs: testIDs})

	userCRUD := getHandler(m, "users")
	resU, _ := userCRUD.Create(auth.User{Email: "sql@example.com", Name: "SQL Test"})
	u := resU.(auth.User)
	_ = m.SetPassword(u.Id, "password123")

	t.Run("Login Injection", func(t *testing.T) {
		_, err := m.Login("' OR 1=1 --", "password123")
		if err != auth.ErrInvalidCredentials {
			t.Errorf("expected ErrInvalidCredentials, got %v", err)
		}
	})

	t.Run("SetPassword Injection", func(t *testing.T) {
		err := m.SetPassword("'; DROP TABLE users; --", "password123")
		// The error from getting identity or updating should not be nil.
		// It will return ErrNotFound or some identity creation error, but NOT crash or drop tables.
		if err == nil {
			t.Errorf("expected error for injected user ID")
		}

		// Ensure table still exists
		_, err = m.GetUser(u.Id)
		if err != nil {
			t.Errorf("expected table to still exist, got %v", err)
		}
	})

	t.Run("RegisterLAN Injection", func(t *testing.T) {
		err := m.RegisterLAN(u.Id, "12345678-5'; --")
		if err != auth.ErrInvalidRUT {
			t.Errorf("expected ErrInvalidRUT, got %v", err)
		}
	})

	t.Run("GetUser Injection", func(t *testing.T) {
		_, err := m.GetUser("1 UNION SELECT * FROM user_identities")
		if err != auth.ErrNotFound {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("GetRoleByCode Injection", func(t *testing.T) {
		_, err := m.GetRoleByCode("admin' OR '1'='1")
		if err != orm.ErrNotFound {
			t.Errorf("expected orm.ErrNotFound, got %v", err)
		}
	})
}
