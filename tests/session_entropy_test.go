//go:build !wasm

package tests

import (
	"testing"

	"github.com/tinywasm/auth"
	"github.com/tinywasm/auth/authority"
	"github.com/tinywasm/ddl"
	"github.com/tinywasm/orm"
	"github.com/tinywasm/sqlite"
)

func isAllDigits(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func commonPrefixLen(a, b string) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

func setupTestModule(t *testing.T) *authority.Module {
	t.Helper()
	conn, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("failed to open sqlite db: %v", err)
	}
	t.Cleanup(func() {
		conn.Close()
	})
	db := orm.New(conn)
	compiler, ok := db.RawConn().(ddl.Compiler)
	if !ok {
		t.Fatalf("RawConn does not implement ddl.Compiler")
	}
	if err := authority.Migrate(db.RawConn(), compiler); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}
	mod, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatalf("failed to create authority: %v", err)
	}
	return mod
}

func TestSessionIDIsNotDerivedFromTime(t *testing.T) {
	mod := setupTestModule(t)

	u, err := mod.CreateUser("user1@example.com", "User 1", "")
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	const count = 200
	sessions := make([]string, count)
	for i := 0; i < count; i++ {
		sess, err := mod.CreateSession(u.Id, "127.0.0.1", "test-agent")
		if err != nil {
			t.Fatalf("failed to create session %d: %v", i, err)
		}
		sessions[i] = sess.Id
	}

	for i := 0; i < count; i++ {
		if isAllDigits(sessions[i]) {
			t.Fatalf("session ID %q contains only decimal digits (looks like a timestamp)", sessions[i])
		}
	}

	for i := 0; i < count; i++ {
		for j := i + 1; j < count; j++ {
			if commonPrefixLen(sessions[i], sessions[j]) >= len(sessions[i]) {
				t.Fatalf("session %d and %d are identical", i, j)
			}
		}
	}

	for i := 0; i < count-1; i++ {
		if commonPrefixLen(sessions[i], sessions[i+1]) >= 16 {
			t.Fatalf("consecutive sessions %d and %d share >= 16 bytes prefix: %q vs %q", i, i+1, sessions[i], sessions[i+1])
		}
	}
}

func TestSessionIDIsNotGuessableFromNeighbour(t *testing.T) {
	mod := setupTestModule(t)

	u, err := mod.CreateUser("user2@example.com", "User 2", "")
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	sess1, err := mod.CreateSession(u.Id, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("failed to create session 1: %v", err)
	}
	sess2, err := mod.CreateSession(u.Id, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("failed to create session 2: %v", err)
	}

	if commonPrefixLen(sess1.Id, sess2.Id) >= 16 {
		t.Fatalf("sessions created back-to-back share prefix >= 16 bytes: %q vs %q", sess1.Id, sess2.Id)
	}
}

func TestOAuthStateIsNotDerivedFromTime(t *testing.T) {
	mod := setupTestModule(t)

	const count = 200
	states := make([]string, count)
	for i := 0; i < count; i++ {
		st, _, err := mod.CreateState("google")
		if err != nil {
			t.Fatalf("failed to create state %d: %v", i, err)
		}
		states[i] = st
	}

	for i := 0; i < count; i++ {
		if isAllDigits(states[i]) {
			t.Fatalf("state %q contains only decimal digits (looks like a timestamp)", states[i])
		}
	}

	for i := 0; i < count; i++ {
		for j := i + 1; j < count; j++ {
			if commonPrefixLen(states[i], states[j]) >= len(states[i]) {
				t.Fatalf("states %d and %d are identical", i, j)
			}
		}
	}

	for i := 0; i < count-1; i++ {
		if commonPrefixLen(states[i], states[i+1]) >= 16 {
			t.Fatalf("consecutive states %d and %d share >= 16 bytes prefix: %q vs %q", i, i+1, states[i], states[i+1])
		}
	}
}
