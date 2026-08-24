package trustedip

import (
	"github.com/tinywasm/fmt"
	"github.com/tinywasm/model"
	"github.com/tinywasm/router"
	"github.com/tinywasm/auth"
)

type Authenticator struct {
	store      auth.IdentityStore
	trusted    auth.TrustedIPStore
	sessions   auth.SessionIssuer
	notify     auth.SecurityNotifier
	trustProxy bool
	afterLogin string
}

type Option func(*Authenticator)

func WithAfterLogin(path string) Option { return func(a *Authenticator) { a.afterLogin = path } }

// New builds the trusted-IP mode. trustProxy is required (not an Option): this
// mode's entire security property is "the request's real IP is on the
// allowlist" — silently defaulting it to false behind a real proxy would make
// every request look like it came from the proxy's own IP.
func New(store auth.IdentityStore, trusted auth.TrustedIPStore, sessions auth.SessionIssuer, notify auth.SecurityNotifier, trustProxy bool, opts ...Option) *Authenticator {
	a := &Authenticator{store: store, trusted: trusted, sessions: sessions, notify: notify, trustProxy: trustProxy}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

func (a *Authenticator) Name() string { return "trusted_ip" }

type loginRUTData struct{ RUT string }

func (d *loginRUTData) IsNil() bool                      { return d == nil }
func (d *loginRUTData) DecodeFields(r model.FieldReader) { d.RUT, _ = r.String("rut") }

func (a *Authenticator) Mount(r router.Router) {
	afterLogin := a.afterLogin
	if afterLogin == "" {
		afterLogin = auth.PathAfterLogin
	}

	r.Post("/login/rut", func(ctx router.Context) {
		ip := auth.ClientIP(ctx, a.trustProxy)
		data := &loginRUTData{}
		if err := ctx.Decode(data); err != nil {
			ctx.WriteStatus(400)
			return
		}

		normalized, err := ValidateRUT(data.RUT)
		if err != nil {
			ctx.WriteStatus(401)
			ctx.Write([]byte(err.Error()))
			return
		}

		identity, err := a.store.IdentityByProvider("trusted_ip", normalized)
		if err != nil {
			ctx.WriteStatus(401)
			ctx.Write([]byte(auth.ErrInvalidCredentials.Error()))
			return
		}
		u, err := a.store.UserByID(identity.UserId)
		if err != nil {
			ctx.WriteStatus(401)
			return
		}
		if u.Status != "active" {
			a.notify.Notify(auth.SecurityEvent{Type: auth.EventNonActiveAccess, UserID: u.Id})
			ctx.WriteStatus(401)
			return
		}
		if !a.trusted.IsTrustedIP(u.Id, ip) {
			a.notify.Notify(auth.SecurityEvent{Type: auth.EventIPMismatch, UserID: u.Id, IP: ip})
			ctx.WriteStatus(401)
			ctx.Write([]byte(auth.ErrInvalidCredentials.Error()))
			return
		}

		if err := a.sessions.IssueSession(ctx, u.Id); err != nil {
			ctx.WriteStatus(500)
			return
		}
		ctx.SetHeader("Location", afterLogin)
		ctx.WriteStatus(302)
	}).Public()
}

var _ auth.Authenticator = (*Authenticator)(nil)

// ValidateRUT normalizes and checksum-validates a Chilean RUT. Pure, stateless —
// no ports, no DB — so both this package's Mount handler and
// authority/credentials_lan.go (LoginLAN, RegisterLAN — direct, non-HTTP entry
// points kept for admin use and unit testing) call the exact SAME algorithm.
// Body copied verbatim from the current authority/lan.go — do not rewrite the
// checksum logic, only relocate it.
func ValidateRUT(rut string) (string, error) {
	rut = fmt.Convert(rut).TrimSpace().String()
	rut = fmt.Convert(rut).Replace(".", "").Replace("-", "").String()

	if len(rut) < 2 {
		return "", auth.ErrInvalidRUT
	}
	bodyStr := rut[:len(rut)-1]
	dvStr := fmt.ToUpper(rut[len(rut)-1:])
	if _, err := fmt.Convert(bodyStr).Int(); err != nil {
		return "", auth.ErrInvalidRUT
	}
	sum := 0
	multiplier := 2
	for i := len(bodyStr) - 1; i >= 0; i-- {
		digit := int(bodyStr[i] - '0')
		sum += digit * multiplier
		multiplier++
		if multiplier > 7 {
			multiplier = 2
		}
	}
	expectedDV := 11 - (sum % 11)
	var expectedDVStr string
	if expectedDV == 11 {
		expectedDVStr = "0"
	} else if expectedDV == 10 {
		expectedDVStr = "K"
	} else {
		expectedDVStr = fmt.Convert(expectedDV).String()
	}
	if dvStr != expectedDVStr {
		return "", auth.ErrInvalidRUT
	}
	return bodyStr + "-" + expectedDVStr, nil
}
