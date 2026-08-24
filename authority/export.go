package authority

import "github.com/tinywasm/auth"

func (m *Module) GetUserByEmail(email string) (auth.User, error) {
	return getUserByEmail(m.db, m.ucache, email)
}
