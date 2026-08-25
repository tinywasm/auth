package jwt

import (
	"github.com/tinywasm/fmt"
	tinyjwt "github.com/tinywasm/jwt"
	"github.com/tinywasm/model"
	"github.com/tinywasm/router"
	"github.com/tinywasm/auth"
)

// errInvalidToken stays deliberately vague: telling a caller WHY a token failed
// tells an attacker where they stand.
var errInvalidToken = fmt.Err("token", "invalid")

// ErrJWTSecretRequired is returned by New when secret is empty.
var ErrJWTSecretRequired = fmt.Err("JWTSecret", "is", "required")

// Strategy is a stateless SessionStrategy: no DB lookup per request, no
// server-side revocation. bearer=false (default) carries the JWT in an HttpOnly
// cookie (browser-friendly, supports the same redirect-after-login flow as
// cookie.Strategy). bearer=true reads/writes via the "Authorization: Bearer"
// header instead (API/MCP clients that can't use cookies) — call AsBearer().
type Strategy struct {
	secret     []byte
	ttl        int
	bearer     bool
	cookieName string
	domain     string // "" (default) = cookie scoped to the exact host, unchanged
	// behavior. A non-empty value (e.g. ".velty.cl") shares the cookie across
	// subdomains of that parent domain — set via WithDomain.
	notify auth.SecurityNotifier
	users  auth.IdentityStore
}

// New builds a JWT strategy. Fails fast if secret is empty — a JWT strategy with
// no secret can mint tokens nobody can validate.
func New(secret []byte, ttl int, notify auth.SecurityNotifier, users auth.IdentityStore) (*Strategy, error) {
	if len(secret) == 0 {
		return nil, ErrJWTSecretRequired
	}
	if ttl == 0 {
		ttl = 86400
	}
	return &Strategy{secret: secret, ttl: ttl, cookieName: "session", notify: notify, users: users}, nil
}

// WithCookieName overrides the cookie the JWT travels in (bearer mode ignores it).
func (s *Strategy) WithCookieName(name string) *Strategy { s.cookieName = name; return s }

// AsBearer switches transport to the Authorization header — for stateless API
// clients (MCP servers, IDEs, LLMs) that cannot use cookies.
func (s *Strategy) AsBearer() *Strategy { s.bearer = true; return s }

// WithDomain sets the cookie's Domain attribute — for a session meant to be
// shared across subdomains of a parent domain (e.g. ".velty.cl"). Ignored in
// bearer mode (no cookie is set). Empty string (default) leaves Domain
// unset: the browser scopes the cookie to the exact host that issued it,
// unchanged from before this method existed.
func (s *Strategy) WithDomain(domain string) *Strategy { s.domain = domain; return s }

func (s *Strategy) Issue(ctx router.Context, userID string) error {
	token, err := s.sign(userID, s.ttl)
	if err != nil {
		return err
	}
	if s.bearer {
		return ctx.Encode(&tokenResponse{Token: token})
	}
	ctx.SetCookie(router.Cookie{
		Name: s.cookieName, Value: token, Domain: s.domain, HttpOnly: true, Secure: true,
		SameSite: router.SameSiteStrict, MaxAge: s.ttl, Path: "/",
	})
	return nil
}

func (s *Strategy) Identify(ctx router.Context) (string, error) {
	var token string
	if s.bearer {
		t, ok := tinyjwt.FromBearer(ctx.GetHeader("Authorization"))
		if !ok {
			return "", auth.ErrSessionExpired
		}
		token = t
	} else {
		c, ok := ctx.Cookie(s.cookieName)
		if !ok {
			return "", auth.ErrSessionExpired
		}
		token = c.Value
	}
	claims, outcome, err := tinyjwt.Verify(s.secret, token)
	if err != nil {
		return "", err // misconfigured (empty secret): not an attack, not a bad token
	}
	switch outcome {
	case tinyjwt.Expired:
		// The quietest event there is: a session ran out. Raising the tampering
		// alarm here would bury the real forgeries in noise.
		return "", auth.ErrSessionExpired
	case tinyjwt.Forged:
		s.notify.Notify(auth.SecurityEvent{Type: auth.EventJWTTampered})
		return "", errInvalidToken
	}
	u, err := s.users.UserByID(claims.Sub)
	if err != nil {
		return "", err
	}
	if u.Status != "active" {
		s.notify.Notify(auth.SecurityEvent{Type: auth.EventNonActiveAccess, UserID: u.Id})
		return "", auth.ErrSuspended
	}
	return u.Id, nil
}

func (s *Strategy) Revoke(ctx router.Context) error {
	if s.bearer {
		return nil // stateless: nothing to revoke server-side
	}
	ctx.SetCookie(router.Cookie{Name: s.cookieName, Value: "", Domain: s.domain, Path: "/", MaxAge: -1, HttpOnly: true})
	return nil
}

// GenerateAPIToken mints a signed, long-lived Bearer token for API access (MCP
// clients, IDEs, LLMs) — independent of how browser sessions are carried.
// ttl==0 → 50 years (effectively no expiry; not 100: this module compiles for
// the edge, where int is 32-bit, and 100 years of seconds overflows int32).
// Call it on whichever Strategy value the app already holds (bearer or not —
// signing doesn't depend on transport).
func (s *Strategy) GenerateAPIToken(userID string, ttl int) (string, error) {
	if ttl == 0 {
		ttl = 365 * 24 * 3600 * 50
	}
	return s.sign(userID, ttl)
}

func (s *Strategy) sign(userID string, ttl int) (string, error) {
	return tinyjwt.Sign(s.secret, tinyjwt.NewClaims(userID, ttl))
}

type tokenResponse struct{ Token string }

func (t *tokenResponse) IsNil() bool                      { return t == nil }
func (t *tokenResponse) EncodeFields(w model.FieldWriter) { w.String("token", t.Token) }

var _ auth.SessionStrategy = (*Strategy)(nil)
