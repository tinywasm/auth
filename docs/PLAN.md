---
PLAN: "feat!: Migrate is explicit — authority.New stops running schema DDL"
EXECUTOR: jules
REVIEWER: none
STATUS: running
SESSION: 3644196144230114495
---

> This plan is dispatched via the CodeJob workflow. See skill: agents-workflow.
>
> **Companion plan:** `tinywasm/rbac` gets the identical change
> (`rbac/docs/PLAN.md`). They are independent — neither imports the other —
> but a consumer needs both published before it can drop schema work from
> its startup path, so they should land together.

# Plan — `tinywasm/auth`: `authority.Migrate`, called by the deployer, not the constructor

## Why

`authority.New` runs `initSchema(db)` (authority/module.go:52), which calls
`ddl.New(...).Sync(...)` over five models (authority/migrate.go). In a
Cloudflare Worker that means **five schema round trips on every isolate cold
start** — work whose result is identical every time, on the request path.

Measured in `veltylabs/iam`, whose `main()` builds `authority` + `rbac` +
its own project schema (~14 models total): instrumented with `Date.now()`
deltas, deployed, and the instrumentation reverted (see that repo's two
`debug:` commits, 2026-08-25):

```
timing: d1.NewEdge                0 ms
timing: unixid.NewUnixID          0 ms
timing: NewProductionBackend   8531 ms  /  10407 ms
```

Cloudflare recycles isolates constantly, so real users pay those seconds
regularly. The schema must be reconciled **once at deploy time** instead.
`tinywasm/goflare` already ships the transport for that
(`goflare.NewD1Migrator`, v0.5.22 — a `ddl.Execer` over D1's HTTP API).
What is missing is a way for a deployer to run *this package's* migration
without constructing the whole module: today the DDL is welded to the
constructor and cannot be reached any other way.

## Stage 1 — export `Migrate`, drop the implicit call

`authority/migrate.go`: rename `initSchema` to `Migrate` and widen its
parameter so a deployer can pass a migration-only connection.

```go
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
```

Two behavioral notes the executor must not "tidy away":

- The old `initSchema` silently returned `nil` when
  `db.RawConn().(ddl.Compiler)` failed. That swallow is gone on purpose:
  the compiler is now a required argument, so a caller that cannot provide
  one gets a compile error instead of a migration that quietly did nothing.
- `Migrate` takes the compiler explicitly rather than type-asserting it out
  of the connection, because a `ddl.Execer` carries no compiler at all —
  that is the whole point of `tinywasm/ddl` v0.0.12's `Execer` (see that
  repo's `docs/LAST_PLAN_EXECUTED.md` or git history).

`authority/module.go`: delete the `initSchema` call at line ~52 and its
error branch. `New` no longer touches the schema.

## Stage 2 — fix every caller that relied on the implicit migration

This is the breaking half. `New` no longer creates tables, so **anything
that called `authority.New` against an empty database and then used it will
now fail at the first query** — silently in the sense that the error surfaces
later, at the query, not at construction.

Find them: `grep -rn "authority.New(" --include="*.go" .` across this repo.
Every test fixture that built a module against a fresh in-memory DB must now
call `authority.Migrate(db.RawConn(), db.RawConn().(ddl.Compiler))` first.
Do not add a helper that hides the call — the explicitness is the feature.

## Stage 3 — documentation

- `docs/ARCHITECTURE.md` (and `README.md` if it shows a setup example):
  the setup sequence gains a `Migrate` step, and must state that `New`
  assumes the schema exists.
- `AGENTS.md`: if it describes `New` as initializing the schema, correct it.

## Known risk — verify before publishing

This repo currently pins `github.com/tinywasm/router v0.1.27`, and
`user.go:200` reads `ctx.Value("RemoteAddr").(string)`. Router **v0.1.28**
changed `Value` to return `string`, which makes that type assertion a
compile error. `gopush` bumps dependencies, so publishing this plan may pull
router forward and break that line.

If it does: the fix is to drop the `.(string)` assertion (the value is
already a string), **not** to pin router back. But check the state of
`tinywasm/server` first — it consumes `router.Context` too and was left
unpublished as of 2026-08-25 (local commit only), so a router bump here can
cascade. If the cascade is not clean, publish this plan with the router
version held and record the `.(string)` cleanup as follow-up work rather
than half-migrating the ecosystem.

## Acceptance criteria

- [ ] `go build ./...` and `go vet ./...` clean.
- [ ] `gotest` green.
- [ ] `grep -rn "initSchema" --include="*.go" .` → empty.
- [ ] `grep -n "Migrate" authority/module.go` → empty (the constructor does
      not call it).
- [ ] `authority.Migrate` accepts a `ddl.Execer` — confirm by compiling a
      throwaway snippet that passes something implementing *only*
      `Exec(string, ...any) error`.
- [ ] No test fixture silently depends on `New` creating tables.

| Stage | File(s) | Done when |
|---|---|---|
| 1 | `authority/migrate.go`, `authority/module.go` | `Migrate(conn ddl.Execer, c ddl.Compiler)` exported; `New` no longer runs DDL |
| 2 | test fixtures across the repo | Every caller migrates explicitly; suite green |
| 3 | `docs/ARCHITECTURE.md`, `README.md`, `AGENTS.md` | Setup sequence shows the explicit `Migrate` step |
