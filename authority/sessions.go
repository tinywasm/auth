package authority

import (
	"sync"

	"github.com/tinywasm/time"

	"github.com/tinywasm/orm"
	"github.com/tinywasm/auth"
)

type sessionItem struct {
	key string
	val auth.Session
}

type sessionCache struct {
	mu    sync.RWMutex
	items []sessionItem
}

func newSessionCache() *sessionCache {
	return &sessionCache{
		items: make([]sessionItem, 0),
	}
}

func (c *sessionCache) set(id string, s auth.Session) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, item := range c.items {
		if item.key == id {
			c.items[i].val = s
			return
		}
	}
	c.items = append(c.items, sessionItem{key: id, val: s})
}

func (c *sessionCache) get(id string) (auth.Session, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, item := range c.items {
		if item.key == id {
			return item.val, true
		}
	}
	return auth.Session{}, false
}

func (c *sessionCache) delete(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, item := range c.items {
		if item.key == id {
			c.items = append(c.items[:i], c.items[i+1:]...)
			return
		}
	}
}

// RotateSession atomically deletes the old session and creates a new one
// with the same userID, updated IP/UserAgent, and a fresh TTL.
// Prevents session fixation attacks when called post-login.
func (m *Module) RotateSession(oldID, ip, userAgent string) (auth.Session, error) {
	oldSess, err := m.GetSession(oldID)
	if err != nil {
		return auth.Session{}, err
	}

	err = m.DeleteSession(oldID)
	if err != nil {
		return auth.Session{}, err
	}

	return m.CreateSession(oldSess.UserId, ip, userAgent)
}

func (m *Module) CreateSession(userID, ip, userAgent string) (auth.Session, error) {
	ttl := m.config.TokenTTL
	if ttl == 0 {
		ttl = 86400
	}

	now := time.Now() / 1e9
	sess := auth.Session{
		Id:        m.ids.NewID(),
		UserId:    userID,
		ExpiresAt: now + int64(ttl),
		Ip:        ip,
		UserAgent: userAgent,
		CreatedAt: now,
	}

	if err := m.db.Create(&sess); err != nil {
		return auth.Session{}, err
	}
	m.cache.set(sess.Id, sess)
	return sess, nil
}

func (m *Module) GetSession(id string) (auth.Session, error) {
	if s, ok := m.cache.get(id); ok {
		if s.ExpiresAt < time.Now()/1e9 {
			m.cache.delete(id)
			return auth.Session{}, auth.ErrSessionExpired
		}
		return s, nil
	}

	qb := m.db.Query(&auth.Session{}).Where(auth.Session_.Id).Eq(id)
	results, err := auth.ReadAllSession(qb)

	if err != nil {
		return auth.Session{}, err
	}
	if len(results) == 0 {
		return auth.Session{}, auth.ErrNotFound
	}
	s := *results[0]

	if s.ExpiresAt < time.Now()/1e9 {
		return auth.Session{}, auth.ErrSessionExpired
	}

	m.cache.set(s.Id, s)
	return s, nil
}

func (m *Module) DeleteSession(id string) error {
	m.cache.delete(id)
	qb := m.db.Query(&auth.Session{}).Where(auth.Session_.Id).Eq(id)
	results, err := auth.ReadAllSession(qb)
	if err == nil && len(results) > 0 {
		return m.db.Delete(results[0], orm.Eq(auth.Session_.Id, results[0].Id))
	}
	return err
}

func (m *Module) PurgeExpiredSessions() error {
	now := time.Now() / 1e9

	m.cache.mu.Lock()
	var active []sessionItem
	for _, item := range m.cache.items {
		if item.val.ExpiresAt >= now {
			active = append(active, item)
		}
	}
	m.cache.items = active
	m.cache.mu.Unlock()

	qb := m.db.Query(&auth.Session{}).Where(auth.Session_.ExpiresAt).Lt(now)
	sessions, _ := auth.ReadAllSession(qb)
	for _, s := range sessions {
		m.db.Delete(s, orm.Eq(auth.Session_.Id, s.Id))
	}

	return nil
}
