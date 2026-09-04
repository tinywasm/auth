package auth

import (
	"github.com/tinywasm/model"
	"github.com/tinywasm/router"
	"github.com/tinywasm/view"
)

// NewView builds the user-administration Presenter — the tech-agnostic engine a
// renderer (crudview, or any other) wraps. The app decides which renderer draws it.
func NewView(caller router.Caller) view.Presenter {
	b := view.NewCallerBackend(caller,
		view.Ops{List: OpListUsers, Save: OpUpsertUser, Delete: OpDeleteUser},
		func() model.ModelSlice { return &UserList{} })
	return view.New(b, &User{}, view.WithTitle("Usuarios"))
}

// Item projects a User as a list row (view.Itemizer) — the ONLY view-specific
// code this module writes on its model.
func (m *User) Item() view.Item {
	return view.Item{ID: m.Id, Label: m.Name, Description: m.Email}
}
