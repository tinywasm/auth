package authority

import (
	"github.com/tinywasm/fmt"
	"github.com/tinywasm/orm"
	"github.com/tinywasm/router"
	"github.com/tinywasm/time"
	"github.com/tinywasm/auth"
	"github.com/tinywasm/user"
)

var (
	_ auth.IdentityStore    = (*Module)(nil)
	_ auth.StateStore       = (*Module)(nil)
	_ auth.TrustedIPStore   = (*Module)(nil)
	_ auth.SessionRepo      = (*Module)(nil)
	_ auth.SecurityNotifier = (*Module)(nil)
	_ auth.SessionIssuer    = (*Module)(nil)
	_ auth.SubjectStore     = (*Module)(nil)
)

func (m *Module) UserByID(id string) (auth.User, error) { return getUser(m.db, m.ucache, id) }
func (m *Module) UserByEmail(email string) (auth.User, error) {
	return getUserByEmail(m.db, m.ucache, email)
}
func (m *Module) CreateUser(email, name, phone string) (auth.User, error) {
	return createUser(m.db, m.ids, email, name, phone)
}
func (m *Module) IdentityByProvider(provider, providerID string) (auth.Identity, error) {
	return getIdentityByProvider(m.db, provider, providerID)
}
func (m *Module) IdentityFor(userID, provider string) (auth.Identity, error) {
	return getIdentityByUserAndProvider(m.db, userID, provider)
}
func (m *Module) UpsertIdentity(userID, provider, providerID, email string) error {
	return upsertIdentity(m.db, m.ids, userID, provider, providerID, email)
}
func (m *Module) UpdateUserAvatar(userID, avatar string) error {
	return updateUserAvatar(m.db, m.ucache, userID, avatar)
}

func (m *Module) CreateState(provider string) (string, error) {
	state := m.ids.NewID()
	now := time.Now() / 1e9
	s := &auth.OAuthState{State: state, Provider: provider, ExpiresAt: now + 600, CreatedAt: now}
	if err := m.db.Create(s); err != nil {
		return "", err
	}
	return state, nil
}
func (m *Module) ConsumeState(state, provider string) error {
	return consumeState(m.db, state, provider)
}

// PurgeExpiredOAuthStates is maintenance, not part of any port — call it
// periodically from a cron-like task in the consuming app.
func (m *Module) PurgeExpiredOAuthStates() error {
	qb := m.db.Query(&auth.OAuthState{}).Where(auth.OAuthState_.ExpiresAt).Lt(time.Now() / 1e9)
	states, _ := auth.ReadAllOAuthState(qb)
	for _, s := range states {
		m.db.Delete(s, orm.Eq(auth.OAuthState_.State, s.State))
	}
	return nil
}

func (m *Module) IsTrustedIP(userID, ip string) bool { return checkLANIP(m.db, userID, ip) == nil }

func (m *Module) Notify(e auth.SecurityEvent) { m.notify(e) }

func (m *Module) IssueSession(ctx router.Context, userID string) error {
	return m.strategy.Issue(ctx, userID)
}

func (m *Module) GetOrCreateSubject(id user.SubjectID, email, name, avatar string) (user.Subject, error) {
	if string(id) == "" {
		return user.Subject{}, fmt.Err("subject", "id", "is", "required")
	}
	if u, err := m.GetUser(string(id)); err == nil {
		if avatar != "" && u.Avatar != avatar {
			_ = updateUserAvatar(m.db, m.ucache, u.Id, avatar)
			u.Avatar = avatar
		}
		return user.Subject{ID: id, Email: u.Email, Name: u.Name, Avatar: u.Avatar}, nil
	}
	if email != "" {
		if u, err := getUserByEmail(m.db, m.ucache, email); err == nil {
			if avatar != "" && u.Avatar != avatar {
				_ = updateUserAvatar(m.db, m.ucache, u.Id, avatar)
				u.Avatar = avatar
			}
			return user.Subject{ID: user.SubjectID(u.Id), Email: u.Email, Name: u.Name, Avatar: u.Avatar}, nil
		}
	}
	now := time.Now() / 1e9
	newUser := auth.User{
		Id:        string(id),
		Email:     email,
		Name:      name,
		Avatar:    avatar,
		Status:    "active",
		CreatedAt: now,
	}
	if err := m.db.Create(&newUser); err != nil {
		if isUniqueViolation(err) {
			if u, err2 := m.GetUser(string(id)); err2 == nil {
				return user.Subject{ID: user.SubjectID(u.Id), Email: u.Email, Name: u.Name, Avatar: u.Avatar}, nil
			}
			if email != "" {
				if u, err2 := getUserByEmail(m.db, m.ucache, email); err2 == nil {
					return user.Subject{ID: user.SubjectID(u.Id), Email: u.Email, Name: u.Name, Avatar: u.Avatar}, nil
				}
			}
		}
		return user.Subject{}, err
	}
	return user.Subject{ID: id, Email: email, Name: name, Avatar: avatar}, nil
}

func consumeState(db *orm.DB, state, provider string) error {
	qb := db.Query(&auth.OAuthState{}).Where(auth.OAuthState_.State).Eq(state)
	results, err := auth.ReadAllOAuthState(qb)
	if err != nil {
		return err
	}
	if len(results) == 0 {
		return auth.ErrInvalidOAuthState
	}
	stateObj := results[0]
	if stateObj.Provider != provider {
		return auth.ErrInvalidOAuthState
	}
	if err := db.Delete(stateObj, orm.Eq(auth.OAuthState_.State, stateObj.State)); err != nil {
		return err
	}
	if stateObj.ExpiresAt < time.Now()/1e9 {
		return auth.ErrInvalidOAuthState
	}
	return nil
}
