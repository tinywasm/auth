package authority

import (
	"github.com/tinywasm/time"

	"github.com/tinywasm/model"
	"github.com/tinywasm/orm"
	"github.com/tinywasm/auth"
)

func createIdentity(db *orm.DB, ids model.IDGenerator, userID, provider, providerID, email string) error {
	// Verify user exists to enforce relationship before insert
	qb := db.Query(&auth.User{}).Where(auth.User_.Id).Eq(userID)
	users, errRead := auth.ReadAllUser(qb)
	if errRead != nil || len(users) == 0 {
		return auth.ErrNotFound
	}

	id := ids.NewID()
	now := time.Now() / 1e9

	i := &auth.Identity{
		Id:         id,
		UserId:     userID,
		Provider:   provider,
		ProviderId: providerID,
		Email:      email,
		CreatedAt:  now,
	}

	if err := db.Create(i); err != nil {
		if isUniqueViolation(err) {
			return err
		}
		return err
	}
	return nil
}

func getIdentityByProvider(db *orm.DB, provider, providerID string) (auth.Identity, error) {
	qb := db.Query(&auth.Identity{}).
		Where(auth.Identity_.Provider).Eq(provider).
		Where(auth.Identity_.ProviderId).Eq(providerID)

	results, err := auth.ReadAllIdentity(qb)
	if err != nil {
		return auth.Identity{}, err
	}
	if len(results) == 0 {
		return auth.Identity{}, auth.ErrNotFound
	}
	return *results[0], nil
}

func getIdentityByUserAndProvider(db *orm.DB, userID, provider string) (auth.Identity, error) {
	qb := db.Query(&auth.Identity{}).
		Where(auth.Identity_.UserId).Eq(userID).
		Where(auth.Identity_.Provider).Eq(provider)

	results, err := auth.ReadAllIdentity(qb)
	if err != nil {
		return auth.Identity{}, err
	}
	if len(results) == 0 {
		return auth.Identity{}, auth.ErrNotFound
	}
	return *results[0], nil
}

func (m *Module) GetUserIdentities(userID string) ([]auth.Identity, error) {
	qb := m.db.Query(&auth.Identity{}).Where(auth.Identity_.UserId).Eq(userID)
	results, err := auth.ReadAllIdentity(qb)
	if err != nil {
		return nil, err
	}

	var identities []auth.Identity
	for _, i := range results {
		identities = append(identities, *i)
	}
	return identities, nil
}

func upsertIdentity(db *orm.DB, ids model.IDGenerator, userID, provider, providerID, email string) error {
	qb := db.Query(&auth.Identity{}).
		Where(auth.Identity_.UserId).Eq(userID).
		Where(auth.Identity_.Provider).Eq(provider)

	results, err := auth.ReadAllIdentity(qb)
	if err == nil && len(results) > 0 {
		i := results[0]
		i.ProviderId = providerID
		i.Email = email
		return db.Update(i, orm.Eq(auth.Identity_.Id, i.Id))
	} else if len(results) == 0 {
		return createIdentity(db, ids, userID, provider, providerID, email)
	} else {
		return err
	}
}

func (m *Module) UnlinkIdentity(userID, provider string) error {
	identities, err := m.GetUserIdentities(userID)
	if err != nil {
		return err
	}

	found := false
	for _, id := range identities {
		if id.Provider == provider {
			found = true
			break
		}
	}
	if !found {
		return auth.ErrNotFound
	}

	if len(identities) <= 1 {
		return auth.ErrCannotUnlink
	}

	qb := m.db.Query(&auth.Identity{}).Where(auth.Identity_.UserId).Eq(userID).Where(auth.Identity_.Provider).Eq(provider)
	results, err := auth.ReadAllIdentity(qb)
	if err != nil {
		return err
	}
	if len(results) > 0 {
		return m.db.Delete(results[0], orm.Eq(auth.Identity_.Id, results[0].Id))
	}
	return auth.ErrNotFound
}
