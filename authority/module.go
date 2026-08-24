package authority

import (
	"github.com/tinywasm/events"
	"github.com/tinywasm/fmt"
	"github.com/tinywasm/model"
	"github.com/tinywasm/orm"
	"github.com/tinywasm/time"
	"github.com/tinywasm/auth"
	"github.com/tinywasm/auth/session/cookie"
)

// Module is the user/auth/rbac handle. All backend operations are methods on
// this type. Created exclusively via New().
type Module struct {
	db     *orm.DB
	cache  *sessionCache
	ucache *userCache
	config auth.Config
	log    func(...any)
	ids    model.IDGenerator
	events events.Publisher

	strategy       auth.SessionStrategy
	authenticators []auth.Authenticator
}

// New initializes the schema, warms the session cache, and wires the default
// session strategy (an opaque cookie over this Module's own session table).
// Call SetStrategy/Enable afterward to customize.
func New(db *orm.DB, cfg auth.Config) (*Module, error) {
	if cfg.IDs == nil {
		return nil, fmt.Err("user:", "Config.IDs", "is", "required")
	}
	if cfg.CookieName == "" {
		cfg.CookieName = "session"
	}
	if cfg.TokenTTL == 0 {
		cfg.TokenTTL = 86400
	}

	m := &Module{
		db:     db,
		cache:  newSessionCache(),
		ucache: newUserCache(),
		config: cfg,
		ids:    cfg.IDs,
		events: cfg.Events,
	}
	m.strategy = cookie.New(m, cfg.CookieName, cfg.TokenTTL, cfg.TrustProxy)

	if err := initSchema(db); err != nil {
		return nil, err
	}
	if err := m.cache.warmUp(db); err != nil {
		return nil, err
	}
	return m, nil
}

// SetStrategy overrides how sessions are carried. Call before mounting. A nil
// argument is ignored — the default set by New is already production-ready;
// this exists to opt into session/jwt or a custom strategy, never to unset it.
func (m *Module) SetStrategy(s auth.SessionStrategy) {
	if s != nil {
		m.strategy = s
	}
}

// Enable registers the authentication modes this app supports — 1 or N.
// authority never constructs a mode itself: the consumer builds each one
// (injecting whichever ports of m it needs) and hands it here.
func (m *Module) Enable(auths ...auth.Authenticator) {
	m.authenticators = append(m.authenticators, auths...)
}

// SetLog configures optional logging. Call immediately after New(). Default: no-op.
func (m *Module) SetLog(fn func(...any)) { m.log = fn }

func (m *Module) notify(e auth.SecurityEvent) {
	if m.events == nil {
		return
	}
	e.Timestamp = time.Now() / 1e9
	m.events.Publish(events.Event{Topic: auth.TopicSecurity, Payload: &e})
}

// SuspendUser sets Status = "suspended". Evicts user from cache.
func (m *Module) SuspendUser(id string) error { return suspendUser(m.db, m.ucache, id) }

// ReactivateUser sets Status = "active". Evicts user from cache.
func (m *Module) ReactivateUser(id string) error { return reactivateUser(m.db, m.ucache, id) }

// PurgeSessionsByUser deletes all sessions belonging to userID from cache and DB.
func (m *Module) PurgeSessionsByUser(userID string) error {
	qb := m.db.Query(&auth.Session{}).Where(auth.Session_.UserId).Eq(userID)
	sessions, err := auth.ReadAllSession(qb)
	if err != nil {
		return err
	}
	for _, s := range sessions {
		m.db.Delete(s, orm.Eq(auth.Session_.Id, s.Id))
		m.cache.delete(s.Id)
	}
	return nil
}

// Add returns all admin-managed CRUDP handlers for registration.
// Usage: cp.RegisterHandlers(m.Add()...)
func (m *Module) Add() []any {
	return []any{
		&userCRUD{db: m.db, cache: m.ucache, ids: m.ids},
		&lanipCRUD{m: m},
	}
}
