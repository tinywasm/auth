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
			if a.isAllowedRedirect != nil {
				if redirectURI, ok := queryParam(ctx.Path(), "redirect_uri"); ok && a.isAllowedRedirect(redirectURI) {
					ctx.SetCookie(router.Cookie{
						Name: oauthRedirectCookie, Value: redirectURI, HttpOnly: true, Secure: true,
						SameSite: router.SameSiteLax, MaxAge: 300, Path: "/",
					})
				}
			}
			ctx.SetHeader("Location", p.AuthCodeURL(state))
			ctx.WriteStatus(302)
		}).Public()

		r.Get(auth.PathOAuthCallback(providerName), func(ctx router.Context) {
			state, _ := queryParam(ctx.Path(), "state")
			code, _ := queryParam(ctx.Path(), "code")

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

// queryParam does a minimal, dependency-free extraction of one key from a
// "path?k=v&k2=v2" string — the same manual parsing this handler already
// used inline for state/code, now shared with redirect_uri. It does not
// URL-decode values: every caller here controls what it puts in the query
// (an opaque state token, an authorization code, or a redirect_uri this
// package itself only ever received %-free from its own /oauth/<provider>
// callers — see WithRedirectValidator's doc).
func queryParam(path, key string) (string, bool) {
	if !fmt.Contains(path, "?") {
		return "", false
	}
	query := fmt.Split(path, "?")[1]
	for _, part := range fmt.Split(query, "&") {
		kv := fmt.Split(part, "=")
		if len(kv) == 2 && kv[0] == key {
			return kv[1], true
		}
	}
	return "", false
}

var _ auth.Authenticator = (*Authenticator)(nil)
