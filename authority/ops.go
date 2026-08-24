package authority

import (
	"github.com/tinywasm/model"
	"github.com/tinywasm/router"
	"github.com/tinywasm/auth"
)

var _ router.OpModule = (*Module)(nil)

func (m *Module) MountOps(reg router.OpRegistry) {
	reg.Op(auth.OpMe, m.opMe).Authenticated()
	reg.Op(auth.OpListUsers, m.opListUsers).Requires("users", model.Read)
	reg.Op(auth.OpUpsertUser, m.opUpsertUser).Requires("users", model.Create|model.Update).Accepts(&auth.User{})
	reg.Op(auth.OpDeleteUser, m.opDeleteUser).Requires("users", model.Delete).Accepts(&auth.User{})
}

func (m *Module) opMe(ctx router.Context) {
	userID := ctx.UserID()
	if userID == "" {
		ctx.WriteStatus(401)
		return
	}
	u, err := m.GetUser(userID)
	if err != nil {
		ctx.WriteStatus(404)
		return
	}
	profile := auth.ProfileDTO{Id: u.Id, Name: u.Name, Email: u.Email, Avatar: u.Avatar}
	for _, r := range u.Roles {
		profile.Roles = append(profile.Roles, r.Code)
		profile.RoleNames = append(profile.RoleNames, r.Name)
	}
	profile.Permissions = permissionsOf(u)
	if err := ctx.Encode(&profile); err != nil {
		ctx.WriteStatus(500)
	}
}

func (m *Module) opListUsers(ctx router.Context) {
	us, err := listUsers(m.db)
	if err != nil {
		ctx.WriteStatus(500)
		return
	}
	list := make(auth.UserList, 0, len(us))
	for i := range us {
		list = append(list, &us[i])
	}
	if err := ctx.Encode(&list); err != nil {
		ctx.WriteStatus(500)
	}
}

func (m *Module) opUpsertUser(ctx router.Context) {
	var u auth.User
	if err := ctx.Decode(&u); err != nil {
		ctx.WriteStatus(400)
		return
	}
	if u.Id == "" {
		if _, err := createUser(m.db, m.ids, u.Email, u.Name, u.Phone); err != nil {
			ctx.WriteStatus(500)
		}
		return
	}
	if err := updateUser(m.db, m.ucache, u.Id, u.Name, u.Phone); err != nil {
		ctx.WriteStatus(500)
	}
}

func (m *Module) opDeleteUser(ctx router.Context) {
	var u auth.User
	if err := ctx.Decode(&u); err != nil {
		ctx.WriteStatus(400)
		return
	}
	if err := deleteUser(m.db, m.ucache, u.Id); err != nil {
		ctx.WriteStatus(500)
	}
}

func permissionsOf(u auth.User) []string {
	var perms []string
	for _, p := range u.Permissions {
		perms = append(perms, p.Resource+":"+p.Action)
	}
	return perms
}
