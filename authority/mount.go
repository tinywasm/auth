package authority

import (
	"github.com/tinywasm/router"
	"github.com/tinywasm/auth"
)

var _ router.APIModule = (*Module)(nil)

func (m *Module) ModelName() string { return "user" }

// MountAPI mounts the one session-termination endpoint centrally — logout ends
// a session the same way no matter which mode started it (strategy.Revoke) —
// then lets every enabled Authenticator mount its own login route. authority
// never inspects what a mode mounts.
func (m *Module) MountAPI(r router.Router) {
	r.Post(auth.PathLogout, func(ctx router.Context) {
		m.strategy.Revoke(ctx)
		ctx.SetHeader("Location", auth.PathLogin)
		ctx.WriteStatus(302)
	}).Public()

	for _, auth := range m.authenticators {
		auth.Mount(r)
	}
}
