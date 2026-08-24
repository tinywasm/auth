package authority

import (
	"github.com/tinywasm/router"
)

// Authenticate returns a router.Middleware that asks the active SessionStrategy
// to identify the caller. If valid, sets UserId in the context via
// ctx.SetUserID(id). If invalid, UserId remains empty (anonymous).
//
// authority identifies; it never authorizes — that is rbac.Service.Can (see
// ARCHITECTURE.md). A composition root wires Authenticate() as Authn and
// rbac.Service.Can as Authorize, two separate ports.
func (m *Module) Authenticate() router.Middleware {
	return func(next router.HandlerFunc) router.HandlerFunc {
		return func(ctx router.Context) {
			if userID, err := m.strategy.Identify(ctx); err == nil && userID != "" {
				ctx.SetUserID(userID)
			}
			next(ctx)
		}
	}
}
