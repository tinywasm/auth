package authority

import (
	"github.com/tinywasm/orm"
	"github.com/tinywasm/time"
	trustedip "github.com/tinywasm/auth/trusted_ip"

	"github.com/tinywasm/router"
	"github.com/tinywasm/auth"
)

// LoginLAN verifies a RUT + the caller's IP directly (no HTTP) — used by tests
// and any admin flow. Mirrors exactly what trusted_ip's Mount handler does,
// using the same ValidateRUT algorithm — see §7's doc comment on ValidateRUT.
func (m *Module) LoginLAN(rut string, ctx router.Context) (auth.User, error) {
	normalized, err := trustedip.ValidateRUT(rut)
	if err != nil {
		return auth.User{}, auth.ErrInvalidRUT
	}
	identity, err := m.IdentityByProvider("trusted_ip", normalized)
	if err != nil {
		return auth.User{}, auth.ErrInvalidCredentials
	}
	u, err := m.UserByID(identity.UserId)
	if err != nil {
		return auth.User{}, auth.ErrInvalidCredentials
	}
	if u.Status == "suspended" {
		return auth.User{}, auth.ErrSuspended
	}
	ip := auth.ClientIP(ctx, m.config.TrustProxy)
	if !m.IsTrustedIP(u.Id, ip) {
		return auth.User{}, auth.ErrInvalidCredentials
	}
	return u, nil
}

// RegisterLAN links a RUT to userID as their trusted_ip identity.
func (m *Module) RegisterLAN(userID, rut string) error {
	normalized, err := trustedip.ValidateRUT(rut)
	if err != nil {
		return auth.ErrInvalidRUT
	}
	id, err := m.IdentityByProvider("trusted_ip", normalized)
	if err == nil {
		if id.UserId != userID {
			return auth.ErrRUTTaken
		}
		return nil
	} else if err != auth.ErrNotFound {
		return err
	}
	return m.UpsertIdentity(userID, "trusted_ip", normalized, "")
}

// UnregisterLAN removes userID's trusted_ip identity and all their allowed IPs.
func (m *Module) UnregisterLAN(userID string) error {
	_, err := m.IdentityFor(userID, "trusted_ip")
	if err == auth.ErrNotFound {
		return auth.ErrNotFound
	}
	if err != nil {
		return err
	}
	qb := m.db.Query(&auth.LANIP{}).Where(auth.LANIP_.UserId).Eq(userID)
	ips, _ := auth.ReadAllLANIP(qb)
	for _, ip := range ips {
		m.db.Delete(ip, orm.Eq(auth.LANIP_.Id, ip.Id))
	}
	qbId := m.db.Query(&auth.Identity{}).Where(auth.Identity_.UserId).Eq(userID).Where(auth.Identity_.Provider).Eq("trusted_ip")
	ids, _ := auth.ReadAllIdentity(qbId)
	for _, id := range ids {
		m.db.Delete(id, orm.Eq(auth.Identity_.Id, id.Id))
	}
	return nil
}

func (m *Module) AssignLANIP(userID, ip, label string) error {
	qb := m.db.Query(&auth.LANIP{}).Where(auth.LANIP_.Ip).Eq(ip)
	results, err := auth.ReadAllLANIP(qb)
	if err != nil {
		return err
	}
	if len(results) > 0 {
		return auth.ErrIPTaken
	}
	i := &auth.LANIP{Id: m.ids.NewID(), UserId: userID, Ip: ip, Label: label, CreatedAt: time.Now() / 1e9}
	return m.db.Create(i)
}

func (m *Module) RevokeLANIP(userID, ip string) error {
	qb := m.db.Query(&auth.LANIP{}).Where(auth.LANIP_.UserId).Eq(userID).Where(auth.LANIP_.Ip).Eq(ip)
	results, err := auth.ReadAllLANIP(qb)
	if err != nil {
		return err
	}
	if len(results) == 0 {
		return auth.ErrNotFound
	}
	return m.db.Delete(results[0], orm.Eq(auth.LANIP_.Id, results[0].Id))
}

func (m *Module) GetLANIPs(userID string) ([]auth.LANIP, error) {
	qb := m.db.Query(&auth.LANIP{}).Where(auth.LANIP_.UserId).Eq(userID).OrderBy(auth.LANIP_.CreatedAt).Asc()
	results, err := auth.ReadAllLANIP(qb)
	if err != nil {
		return nil, err
	}
	ips := make([]auth.LANIP, 0, len(results))
	for _, r := range results {
		ips = append(ips, *r)
	}
	return ips, nil
}

// checkLANIP is used by both LoginLAN above and Module.IsTrustedIP (ports.go) —
// the TrustedIPStore port implementation.
func checkLANIP(db *orm.DB, userID, ip string) error {
	qb := db.Query(&auth.LANIP{}).Where(auth.LANIP_.UserId).Eq(userID).Where(auth.LANIP_.Ip).Eq(ip)
	results, err := auth.ReadAllLANIP(qb)
	if err != nil || len(results) == 0 {
		return auth.ErrInvalidCredentials
	}
	return nil
}
