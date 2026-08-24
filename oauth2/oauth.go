package oauth2

import (
	"github.com/tinywasm/fmt"
	"github.com/tinywasm/router"
	"github.com/tinywasm/auth"
)

type Authenticator struct {
	store      auth.IdentityStore
	states     auth.StateStore
	sessions   auth.SessionIssuer
	providers  []auth.OAuthProvider
	afterLogin string
}

type Option func(*Authenticator)

func WithAfterLogin(path string) Option { return func(a *Authenticator) { a.afterLogin = path } }

func New(store auth.IdentityStore, states auth.StateStore, sessions auth.SessionIssuer, providers []auth.OAuthProvider, opts ...Option) *Authenticator {
	a := &Authenticator{store: store, states: states, sessions: sessions, providers: providers}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

func (a *Authenticator) Name() string { return "oauth2" }

func (a *Authenticator) provider(name string) auth.OAuthProvider {
	for _, p := range a.providers {
		if p.Name() == name {
			return p
		}
	}
	return nil
}

func (a *Authenticator) Mount(r router.Router) {
	afterLogin := a.afterLogin
	if afterLogin == "" {
		afterLogin = auth.PathAfterLogin
	}

	for _, p := range a.providers {
		providerName := p.Name()

		r.Get(auth.PathOAuthStart(providerName), func(ctx router.Context) {
			state, err := a.states.CreateState(providerName)
			if err != nil {
				ctx.WriteStatus(500)
				return
			}
			ctx.SetHeader("Location", p.AuthCodeURL(state))
			ctx.WriteStatus(302)
		}).Public()

		r.Get(auth.PathOAuthCallback(providerName), func(ctx router.Context) {
			var state, code string
			path := ctx.Path()
			if fmt.Contains(path, "?") {
				query := fmt.Split(path, "?")[1]
				for _, part := range fmt.Split(query, "&") {
					kv := fmt.Split(part, "=")
					if len(kv) == 2 {
						if kv[0] == "state" {
							state = kv[1]
						} else if kv[0] == "code" {
							code = kv[1]
						}
					}
				}
			}

			if err := a.states.ConsumeState(state, providerName); err != nil {
				ctx.WriteStatus(401)
				ctx.Write([]byte(auth.ErrInvalidOAuthState.Error()))
				return
			}
			prov := a.provider(providerName)
			if prov == nil {
				ctx.WriteStatus(500)
				return
			}
			token, err := prov.ExchangeCode(code)
			if err != nil {
				ctx.WriteStatus(401)
				ctx.Write([]byte(err.Error()))
				return
			}
			info, err := prov.GetUserInfo(token)
			if err != nil {
				ctx.WriteStatus(401)
				ctx.Write([]byte(err.Error()))
				return
			}

			var u auth.User
			if identity, err := a.store.IdentityByProvider(providerName, info.ID); err == nil {
				u, err = a.store.UserByID(identity.UserId)
				if err != nil {
					ctx.WriteStatus(500)
					return
				}
			} else if existing, err := a.store.UserByEmail(info.Email); err == nil {
				u = existing
				_ = a.store.UpsertIdentity(u.Id, providerName, info.ID, info.Email)
			} else {
				created, err := a.store.CreateUser(info.Email, info.Name, "")
				if err != nil {
					ctx.WriteStatus(500)
					return
				}
				u = created
				_ = a.store.UpsertIdentity(u.Id, providerName, info.ID, info.Email)
			}

			if info.Avatar != "" {
				if err := a.store.UpdateUserAvatar(u.Id, info.Avatar); err == nil {
					u.Avatar = info.Avatar
				}
			}

			if err := a.sessions.IssueSession(ctx, u.Id); err != nil {
				ctx.WriteStatus(500)
				return
			}
			ctx.SetHeader("Location", afterLogin)
			ctx.WriteStatus(302)
		}).Public()
	}
}

var _ auth.Authenticator = (*Authenticator)(nil)
