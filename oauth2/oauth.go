package oauth2

import (
	"github.com/tinywasm/auth"
	"github.com/tinywasm/router"
)

type Authenticator struct {
	store      auth.IdentityStore
	states     auth.StateStore
	sessions   auth.SessionIssuer
	providers  []auth.OAuthProvider
	afterLogin string
	// isAllowedRedirect validates a caller-supplied ?redirect_uri= before
	// trusting it as the post-login destination. nil (default) means the
	// param is ignored entirely: afterLogin always wins, exactly the
	// behavior before this option existed. Never wire redirect_uri without
	// one — an unchecked redirect target is an open-redirect vulnerability.
	isAllowedRedirect func(string) bool
}

type Option func(*Authenticator)

func WithAfterLogin(path string) Option { return func(a *Authenticator) { a.afterLogin = path } }

// WithRedirectValidator lets /oauth/<provider>?redirect_uri=<url> override
// afterLogin for THIS login, once <url> passes fn — e.g. an identity
// provider (iam) serving several consumer domains under one SSO login,
// returning the browser to whichever one it came from. Ignored entirely if
// never called.
func WithRedirectValidator(fn func(string) bool) Option {
	return func(a *Authenticator) { a.isAllowedRedirect = fn }
}

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

// oauthRedirectCookie carries a validated redirect_uri from /oauth/<provider>
// to its callback, across the top-level navigation to the provider and back.
// SameSite=Lax (not Strict, unlike the session cookie): the callback request
// is a top-level GET navigation ARRIVING from a different site (the
// provider), which Strict would drop.
const oauthRedirectCookie = "oauth_redirect"

// oauthNonceCookie lleva el nonce del state desde /oauth/<provider> hasta su
// callback. SameSite=Lax como el cookie de redirect: el callback llega como
// navegación top-level desde el sitio del proveedor, y Strict la descartaría.
const oauthNonceCookie = "oauth_nonce"

// oauthCookieMaxAge: 300 s. Un intercambio OAuth que tarda más de cinco
// minutos ya no es un usuario, es un replay.
const oauthCookieMaxAge = 300

// bodyOAuthFailed es lo ÚNICO que el callback devuelve ante cualquier fallo.
// Distinguir "state inválido" de "el proveedor rechazó el code" le dice al
// atacante en qué paso está. Ver la misma doctrina en session/jwt/jwt.go
// (errInvalidToken).
const bodyOAuthFailed = "authentication failed"

func (a *Authenticator) Mount(r router.Router) {
	afterLogin := a.afterLogin
	if afterLogin == "" {
		afterLogin = auth.PathAfterLogin
	}

	for _, p := range a.providers {
		providerName := p.Name()

		r.Get(auth.PathOAuthStart(providerName), func(ctx router.Context) {
			state, nonce, err := a.states.CreateState(providerName)
			if err != nil {
				ctx.WriteStatus(500)
				return
			}
			ctx.SetCookie(router.Cookie{
				Name: oauthNonceCookie, Value: nonce, HttpOnly: true, Secure: true,
				SameSite: router.SameSiteLax, MaxAge: oauthCookieMaxAge, Path: "/",
			})
			if a.isAllowedRedirect != nil {
				if redirectURI, ok := router.QueryParam(ctx.Path(), "redirect_uri"); ok && a.isAllowedRedirect(redirectURI) {
					ctx.SetCookie(router.Cookie{
						Name: oauthRedirectCookie, Value: redirectURI, HttpOnly: true, Secure: true,
						SameSite: router.SameSiteLax, MaxAge: oauthCookieMaxAge, Path: "/",
					})
				}
			}
			ctx.SetHeader("Location", p.AuthCodeURL(state))
			ctx.WriteStatus(302)
		}).Public()

		r.Get(auth.PathOAuthCallback(providerName), func(ctx router.Context) {
			state, _ := router.QueryParam(ctx.Path(), "state")
			code, _ := router.QueryParam(ctx.Path(), "code")

			var nonce string
			if c, ok := ctx.Cookie(oauthNonceCookie); ok {
				nonce = c.Value
			}
			ctx.SetCookie(router.Cookie{
				Name: oauthNonceCookie, Value: "", HttpOnly: true, Secure: true,
				SameSite: router.SameSiteLax, MaxAge: -1, Path: "/",
			})

			if err := a.states.ConsumeState(state, nonce, providerName); err != nil {
				ctx.WriteStatus(401)
				ctx.Write([]byte(bodyOAuthFailed))
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
				ctx.Write([]byte(bodyOAuthFailed))
				return
			}
			info, err := prov.GetUserInfo(token)
			if err != nil {
				ctx.WriteStatus(401)
				ctx.Write([]byte(bodyOAuthFailed))
				return
			}

			var u auth.User
			if identity, err := a.store.IdentityByProvider(providerName, info.ID); err == nil {
				u, err = a.store.UserByID(identity.UserId)
				if err != nil {
					ctx.WriteStatus(500)
					return
				}
			} else if info.EmailVerified {
				if existing, err := a.store.UserByEmail(info.Email); err == nil {
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
			} else {
				if _, err := a.store.UserByEmail(info.Email); err == nil {
					if notifier, ok := a.store.(auth.SecurityNotifier); ok {
						notifier.Notify(auth.SecurityEvent{Type: auth.EventUnauthorizedAccess, Provider: providerName})
					}
					ctx.WriteStatus(401)
					ctx.Write([]byte(bodyOAuthFailed))
					return
				}
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

			location := afterLogin
			if a.isAllowedRedirect != nil {
				if c, ok := ctx.Cookie(oauthRedirectCookie); ok && a.isAllowedRedirect(c.Value) {
					location = c.Value
					// Clear it: a one-shot cookie, not a lingering redirect target.
					ctx.SetCookie(router.Cookie{Name: oauthRedirectCookie, Value: "", MaxAge: -1, Path: "/"})
				}
			}
			ctx.SetHeader("Location", location)
			ctx.WriteStatus(302)
		}).Public()
	}
}


var _ auth.Authenticator = (*Authenticator)(nil)
