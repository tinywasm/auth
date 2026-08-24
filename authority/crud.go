package authority

import (
	"github.com/tinywasm/model"
	"github.com/tinywasm/orm"
	"github.com/tinywasm/auth"
)

// --- userCRUD ---
type userCRUD struct {
	db    *orm.DB
	cache *userCache
	ids   model.IDGenerator
}

func (h *userCRUD) HandlerName() string { return "users" }
func (h *userCRUD) AllowedRoles(action model.Action) []model.RoleCode {
	return []model.RoleCode{model.RoleCode("admin")}
}
func (h *userCRUD) ValidateData(action model.Action, _ any) error { return nil }

func (h *userCRUD) Create(payload any) (any, error) {
	u := payload.(auth.User)
	return createUser(h.db, h.ids, u.Email, u.Name, u.Phone)
}
func (h *userCRUD) Read(id string) (any, error) { return getUser(h.db, h.cache, id) }
func (h *userCRUD) List() (any, error)          { return listUsers(h.db) }
func (h *userCRUD) Update(payload any) (any, error) {
	u := payload.(auth.User)
	return u, updateUser(h.db, h.cache, u.Id, u.Name, u.Phone)
}
func (h *userCRUD) Delete(id string) error { return deleteUser(h.db, h.cache, id) }

// --- lanipCRUD ---
type lanipCRUD struct{ m *Module }

func (h *lanipCRUD) HandlerName() string { return "lan_ips" }
func (h *lanipCRUD) AllowedRoles(action model.Action) []model.RoleCode {
	return []model.RoleCode{model.RoleCode("admin")}
}
func (h *lanipCRUD) ValidateData(action model.Action, _ any) error { return nil }

func (h *lanipCRUD) Create(payload any) (any, error) {
	ip := payload.(auth.LANIP)
	err := h.m.AssignLANIP(ip.UserId, ip.Ip, ip.Label)
	return ip, err
}
func (h *lanipCRUD) Read(id string) (any, error) {
	qb := h.m.db.Query(&auth.LANIP{}).Where(auth.LANIP_.Id).Eq(id)
	results, err := auth.ReadAllLANIP(qb)
	if err != nil || len(results) == 0 {
		return auth.LANIP{}, err
	}
	return *results[0], nil
}
func (h *lanipCRUD) List() (any, error) {
	qb := h.m.db.Query(&auth.LANIP{})
	ips, err := auth.ReadAllLANIP(qb)
	if err != nil {
		return nil, err
	}
	res := make([]auth.LANIP, len(ips))
	for i, ip := range ips {
		res[i] = *ip
	}
	return res, nil
}
func (h *lanipCRUD) Update(payload any) (any, error) {
	return payload, nil // update isn't strictly defined for LANIPs beyond assigning
}
func (h *lanipCRUD) Delete(id string) error {
	qb := h.m.db.Query(&auth.LANIP{}).Where(auth.LANIP_.Id).Eq(id)
	results, err := auth.ReadAllLANIP(qb)
	if err != nil || len(results) == 0 {
		return err
	}
	return h.m.RevokeLANIP(results[0].UserId, results[0].Ip)
}
