# tinywasm/auth
<img src="docs/img/badges.svg">

Authentication mechanisms, sessions, identities, and OAuth providers for the
TinyWasm ecosystem. Authorization belongs to `tinywasm/rbac`. Both are siblings
that depend only on `tinywasm/user` and never on each other.

> **BREAKING CHANGE**: `StateStore.CreateState` and `StateStore.ConsumeState` changed signatures to support browser-bound OAuth state nonces:
> - `CreateState(provider string) (state, nonce string, err error)`
> - `ConsumeState(state, nonce, provider string) error`
>
> Known consumers to update: `oauth2/oauth.go` (updated in this repo) and any custom implementations of `auth.StateStore`.

```mermaid
flowchart TD
    U[user] --> A[auth]
    U --> R[rbac]
    A --> C[app]
    R --> C
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — Dependency rules, packages, local simulator

## Packages

- `auth` — Core ports: `SubjectStore`, `SessionIssuer`, `IdentityStore`,
  `StateStore`, `SecurityNotifier`, `SessionRepo`, `Config`, `ProfileDTO`,
  `ShellProfile`, OAuth types.
- `authority` — Concrete module (`Module`) implementing the ports, caches,
  migrations, and middleware. Configures a secure opaque cookie session strategy by default using 256-bit CSPRNG entropy (`tinywasm/crypto/rand`) for session IDs and OAuth states.
- `oauth2` + `oauth2/provider/google`, `oauth2/provider/microsoft` — OAuth flow
  and providers.
- `session/cookie`, `session/jwt` — Session transports.
- `email_password`, `trusted_ip` — Credential authenticators.
- `local` — Development selector authenticator; no network, no env vars.

## Local Development

```go
scenarios := []local.Scenario{
    {ID: "user_admin", Name: "Alice", Email: "alice@example.com", Avatar: "", Roles: []string{"Administrator"}},
    {ID: "user_viewer", Name: "Bob", Email: "bob@example.com", Avatar: "", Roles: []string{"Viewer"}},
}
_ = authority.Migrate(db.RawConn(), db.RawConn().(ddl.Compiler))
authMod, _ := authority.New(db, auth.Config{IDs: ids})
rbacSvc, _ := rbac.New(db)
// seed subjects and assignments via rbac before mounting
for _, s := range scenarios { /* ensure user and AssignRole via rbacSvc */ }
localAuth := local.New(scenarios, authMod, authMod, local.WithAfterLogin("/"))
authMod.Enable(localAuth)
```

Production builds use `oauth2.New` with a real `google.GoogleProvider` and never
register `local`.
