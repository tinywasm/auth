package authority

import (
	"github.com/tinywasm/model"
	"github.com/tinywasm/auth"
)

// Seed is the INITIAL security policy of the app: declared by the consumer.
// This library only persists it with hashing and invariants.
type Seed struct {
	Email    string
	Password string
	Name     string
	Role     model.RoleCode
	Grants   []model.Grant
}

// Bootstrap seeds the first user and their initial permissions. NO-OP if the users
// table is already populated. It does not invent roles or wildcards: it only
// persists what the Seed declares.
func (m *Module) Bootstrap(s Seed) error {
	if s.Email == "" || s.Password == "" || s.Name == "" || s.Role == "" {
		return auth.ErrInvalidCredentials
	}

	// Check if any users exist
	qb := m.db.Query(&auth.User{})
	users, err := auth.ReadAllUser(qb)
	if err != nil {
		return err
	}
	if len(users) > 0 {
		return nil
	}

	// 1. Create User
	u, err := createUser(m.db, m.ids, s.Email, s.Name, "")
	if err != nil {
		return err
	}

	// 2. Set Password
	if err := m.SetPassword(u.Id, s.Password); err != nil {
		return err
	}

	// 3. Create Role
	roleID := "role_" + string(s.Role)
	if err := m.CreateRole(roleID, s.Role, string(s.Role), "Seed role"); err != nil {
		return err
	}

	// 4. Create Permissions and Assign to Role
	for _, g := range s.Grants {
		permID := "perm_" + string(g.Resource) + "_" + g.Actions.String()
		if err := m.CreatePermission(permID, permID, g.Resource, g.Actions); err != nil {
			return err
		}
		if err := m.AssignPermission(roleID, permID); err != nil {
			return err
		}
	}

	// 5. Assign Role to User
	if err := m.AssignRole(u.Id, roleID); err != nil {
		return err
	}

	return nil
}
