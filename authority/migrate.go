package authority

import (
	"github.com/tinywasm/auth"
	"github.com/tinywasm/ddl"
	"github.com/tinywasm/model"
)

// Migrate reconciles the database schema this package owns: User, Identity,
// LANIP, OAuthState and Session, in dependency order.
//
// It is deliberately NOT called by New. Schema reconciliation is deploy-time
// work — running it per process start costs a network round trip per model,
// which in a Cloudflare Worker is paid again on every isolate cold start
// (measured at 8.5–10.4 s across ~14 models in veltylabs/iam). Call this
// once from a migration binary, then let New assume the schema exists.
//
// conn is a ddl.Execer, not an *orm.DB, so a deploy-time transport that can
// only execute DDL satisfies it — goflare.NewD1Migrator returns exactly that.
// An *orm.DB's RawConn() also satisfies it, for local/test callers:
//
//	// deploy time, against D1's HTTP API:
//	conn, _ := goflare.NewD1Migrator(accountID, databaseID, apiToken)
//	err := authority.Migrate(conn, sqlt.NewCompiler())
//
//	// local dev / tests, against an in-memory or sqlite DB:
//	err := authority.Migrate(db.RawConn(), db.RawConn().(ddl.Compiler))
func Migrate(conn ddl.Execer, ddlCompiler ddl.Compiler) error {
	models := []model.Model{
		&auth.User{}, &auth.Identity{}, &auth.LANIP{},
		&auth.OAuthState{}, &auth.Session{},
	}
	sorted, err := ddl.TopologicalSort(models)
	if err != nil {
		return err
	}
	return ddl.New(conn, ddlCompiler).Sync(sorted...)
}
