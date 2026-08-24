package cookie

import (
	"github.com/tinywasm/router"
	"github.com/tinywasm/auth"
)

// Strategy is the default SessionStrategy: an opaque session ID in an HttpOnly
// cookie, backed by whatever SessionRepo the consumer injects (authority.Module
// implements it with its own session table + in-memory cache).
type Strategy struct {
	repo       auth.SessionRepo
	name       string
	ttl        int
	trustProxy bool
}

// New builds a cookie strategy. cookieName=="" defaults to "session"; ttl==0
// defaults to 86400 (seconds).
func New(repo auth.SessionRepo, cookieName string, ttl int, trustProxy bool) *Strategy {
	if cookieName == "" {
		cookieName = "session"
	}
	if ttl == 0 {
		ttl = 86400
	}
	return &Strategy{repo: repo, name: cookieName, ttl: ttl, trustProxy: trustProxy}
}

func (s *Strategy) Issue(ctx router.Context, userID string) error {
	ip := auth.ClientIP(ctx, s.trustProxy)
	ua := ctx.GetHeader("User-Agent")
	sess, err := s.repo.CreateSession(userID, ip, ua)
	if err != nil {
		return err
	}
	ctx.SetCookie(router.Cookie{
		Name: s.name, Value: sess.Id, HttpOnly: true, Secure: true,
		SameSite: router.SameSiteStrict, MaxAge: s.ttl, Path: "/",
	})
	return nil
}

func (s *Strategy) Identify(ctx router.Context) (string, error) {
	c, ok := ctx.Cookie(s.name)
	if !ok {
		return "", auth.ErrSessionExpired
	}
	sess, err := s.repo.GetSession(c.Value)
	if err != nil {
		return "", err
	}
	return sess.UserId, nil
}

func (s *Strategy) Revoke(ctx router.Context) error {
	if c, ok := ctx.Cookie(s.name); ok {
		s.repo.DeleteSession(c.Value)
	}
	ctx.SetCookie(router.Cookie{Name: s.name, Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	return nil
}

var _ auth.SessionStrategy = (*Strategy)(nil)
