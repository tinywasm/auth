//go:build !wasm

package tests

import (
	"testing"
	"time"

	"github.com/tinywasm/auth"
	"github.com/tinywasm/auth/authority"
)

func TestTimingSafeAuth(t *testing.T) {
	db := newTestDB(t)
	m, _ := authority.New(db, auth.Config{IDs: testIDs})

	userCRUD := getHandler(m, "users")
	resU, _ := userCRUD.Create(auth.User{Email: "timing@example.com", Name: "Timing User"})
	u := resU.(auth.User)
	_ = m.SetPassword(u.Id, "password123")

	// Create an OAuth-only user (no local identity)
	resO, _ := userCRUD.Create(auth.User{Email: "oauth@example.com", Name: "OAuth User"})
	uOauth := resO.(auth.User)
	_ = m.RegisterLAN(uOauth.Id, "12345")

	// Suspend a user
	resS, _ := userCRUD.Create(auth.User{Email: "susp@example.com", Name: "Susp User"})
	uSusp := resS.(auth.User)
	_ = m.SetPassword(uSusp.Id, "password123")
	m.SuspendUser(uSusp.Id)

	measure := func(email, pass string) (time.Duration, error) {
		start := time.Now()
		_, err := m.Login(email, pass)
		return time.Since(start), err
	}

	// 1. Wrong password (baseline, real bcrypt)
	durReal, err := measure("timing@example.com", "wrong")
	if err != auth.ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials")
	}

	// 2. Non-existent user
	durMiss, err := measure("nobody@example.com", "wrong")
	if err != auth.ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials")
	}

	// 3. Suspended user
	durSusp, err := measure("susp@example.com", "wrong")
	if err != auth.ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials")
	}

	// 4. OAuth-only user
	durOauth, err := measure("oauth@example.com", "wrong")
	if err != auth.ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials")
	}

	// Real assertions on timing in CI environments can be flaky.
	// We check they are roughly similar to real bcrypt execution by ensuring they took a proportional amount of time.

	if durReal < 10*time.Millisecond {
		t.Logf("real hash check took %v, might be too fast to test timing reliably", durReal)
	}

	if durMiss < durReal/2 {
		t.Errorf("non-existent user check is too fast: %v vs %v", durMiss, durReal)
	}
	if durSusp < durReal/2 {
		t.Errorf("suspended user check is too fast: %v vs %v", durSusp, durReal)
	}
	if durOauth < durReal/2 {
		t.Errorf("oauth user check is too fast: %v vs %v", durOauth, durReal)
	}
}
