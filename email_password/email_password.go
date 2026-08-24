package emailpassword

import (
	"github.com/tinywasm/router"
	"github.com/tinywasm/auth"

	"github.com/tinywasm/crypto/bcrypt"
)

type Authenticator struct {
	store      auth.IdentityStore
	sessions   auth.SessionIssuer
	notify     auth.SecurityNotifier
	afterLogin string
	rateLimit  func(ip string) error
	trustProxy bool
}

type Option func(*Authenticator)

func WithAfterLogin(path string) Option { return func(a *Authenticator) { a.afterLogin = path } }
func WithRateLimit(fn func(ip string) error) Option {
	return func(a *Authenticator) { a.rateLimit = fn }
}
func WithTrustProxy(v bool) Option { return func(a *Authenticator) { a.trustProxy = v } }

// New builds the email+password mode. store/sessions/notify are required ports;
// everything else is an Option with a safe zero-value default.
func New(store auth.IdentityStore, sessions auth.SessionIssuer, notify auth.SecurityNotifier, opts ...Option) *Authenticator {
	a := &Authenticator{store: store, sessions: sessions, notify: notify}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

func (a *Authenticator) Name() string { return "email_password" }

func (a *Authenticator) Mount(r router.Router) {
	afterLogin := a.afterLogin
	if afterLogin == "" {
		afterLogin = auth.PathAfterLogin
	}

	r.Post(auth.PathLogin, func(ctx router.Context) {
		ip := auth.ClientIP(ctx, a.trustProxy)
		data := &auth.LoginData{}
		if err := ctx.Decode(data); err != nil {
			ctx.WriteStatus(400)
			ctx.Write([]byte(err.Error()))
			return
		}

		if a.rateLimit != nil {
			if err := a.rateLimit(ip); err != nil {
				a.notify.Notify(auth.SecurityEvent{Type: auth.EventRateLimited, IP: ip, UserID: data.Email})
				ctx.WriteStatus(429)
				ctx.Write([]byte(err.Error()))
				return
			}
		}

		u, err := a.store.UserByEmail(data.Email)
		if err != nil {
			DummyCompare(data.Password, DefaultHashCost)
			ctx.WriteStatus(401)
			ctx.Write([]byte(auth.ErrInvalidCredentials.Error()))
			return
		}
		if u.Status != "active" {
			a.notify.Notify(auth.SecurityEvent{Type: auth.EventNonActiveAccess, UserID: u.Id})
			DummyCompare(data.Password, DefaultHashCost)
			ctx.WriteStatus(401)
			ctx.Write([]byte(auth.ErrInvalidCredentials.Error()))
			return
		}

		identity, err := a.store.IdentityFor(u.Id, "email_password")
		if err != nil {
			DummyCompare(data.Password, DefaultHashCost)
			ctx.WriteStatus(401)
			ctx.Write([]byte(auth.ErrInvalidCredentials.Error()))
			return
		}
		if err := VerifyPassword(identity.ProviderId, data.Password); err != nil {
			a.notify.Notify(auth.SecurityEvent{Type: auth.EventAccessDenied, IP: ip, UserID: u.Id})
			ctx.WriteStatus(401)
			ctx.Write([]byte(err.Error()))
			return
		}

		if err := a.sessions.IssueSession(ctx, u.Id); err != nil {
			ctx.WriteStatus(500)
			ctx.Write([]byte(err.Error()))
			return
		}
		ctx.SetHeader("Location", afterLogin)
		ctx.WriteStatus(302)
	}).Public()
}

var _ auth.Authenticator = (*Authenticator)(nil)

// DefaultHashCost is bcrypt's cost factor. Tests lower it (bcrypt.MinCost) for
// speed — same knob as the old package-level authority.PasswordHashCost.
var DefaultHashCost = bcrypt.DefaultCost

var dummyHashOnce []byte

func getDummyHash(cost int) []byte {
	if len(dummyHashOnce) == 0 {
		dummyHashOnce, _ = bcrypt.GenerateFromPassword([]byte("dummy"), cost)
	}
	return dummyHashOnce
}

// DummyCompare burns the same time a real bcrypt comparison would, so a caller
// can't distinguish "no such user" from "wrong password" by timing.
func DummyCompare(password string, cost int) {
	bcrypt.CompareHashAndPassword(getDummyHash(cost), []byte(password))
}

// HashPassword is the ONLY place bcrypt.GenerateFromPassword is called in this
// repo. authority/credentials_password.go calls this — it never calls bcrypt
// directly.
func HashPassword(password string, cost int) (string, error) {
	if len(password) < 8 {
		return "", auth.ErrWeakPassword
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// VerifyPassword is the ONLY place bcrypt.CompareHashAndPassword is called for a
// real (non-dummy) comparison in this repo.
func VerifyPassword(hash, password string) error {
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return auth.ErrInvalidCredentials
	}
	return nil
}
