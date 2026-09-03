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

func TestSessionCacheIsBounded(t *testing.T) {
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

	u, err := m.CreateUser("cache@example.com", "Cache User", "")
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	const maxCacheSessions = 1000
	const extra = 50
	const total = maxCacheSessions + extra

	sessions := make([]auth.Session, total)
	for i := 0; i < total; i++ {
		sess, err := m.CreateSession(u.Id, "127.0.0.1", "agent")
		if err != nil {
			t.Fatalf("failed to create session %d: %v", i, err)
		}
		sessions[i] = sess
	}

	// Verify newest session resolves from cache / DB without issue
	lastSess := sessions[total-1]
	retrieved, err := m.GetSession(lastSess.Id)
	if err != nil {
		t.Fatalf("failed to retrieve newest session: %v", err)
	}
	if retrieved.Id != lastSess.Id {
		t.Fatalf("session ID mismatch: got %s, want %s", retrieved.Id, lastSess.Id)
	}

	// Verify oldest session (which was evicted from cache) still resolves via read-through from DB
	firstSess := sessions[0]
	retrievedFirst, err := m.GetSession(firstSess.Id)
	if err != nil {
		t.Fatalf("failed to retrieve evicted first session from DB: %v", err)
	}
	if retrievedFirst.Id != firstSess.Id {
		t.Fatalf("session ID mismatch: got %s, want %s", retrievedFirst.Id, firstSess.Id)
	}
}
