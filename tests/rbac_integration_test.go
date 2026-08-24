//go:build !wasm

package tests

import (
	"testing"

	"github.com/tinywasm/model"
	"github.com/tinywasm/auth"
	"github.com/tinywasm/auth/authority"
)

type mockHandler struct {
	name  string
	roles map[model.Action][]model.RoleCode
}

func (h *mockHandler) HandlerName() string { return h.name }
func (h *mockHandler) AllowedRoles(action model.Action) []model.RoleCode {
	return h.roles[action]
}

func TestIntegration_FullFlow(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}

	if err := m.CreateRole("rid1", "a", "Admin", "Desc"); err != nil {
		t.Fatalf("CreateRole failed: %v", err)
	}
	if err := m.CreateRole("rid2", "e", "Editor", "Desc"); err != nil {
		t.Fatalf("CreateRole failed: %v", err)
	}

	h := &mockHandler{
		name: "invoice",
		roles: map[model.Action][]model.RoleCode{
			model.Read:   {"a", "e"},
			model.Update: {"a"},
		},
	}
	if err := m.Register(h); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	userCRUD := getHandler(m, "users")
	res, err := userCRUD.Create(auth.User{Email: "uid1@test.com", Name: "Test"})
	if err != nil {
		t.Fatal(err)
	}
	u := res.(auth.User)

	if err := m.AssignRole(u.Id, "rid2"); err != nil {
		t.Fatalf("AssignRole failed: %v", err)
	}

	ok, err := m.HasPermission(u.Id, "invoice", model.Read)
	if err != nil {
		t.Fatalf("HasPermission failed: %v", err)
	}
	if !ok {
		t.Error("Editor should be able to read invoice")
	}

	ok, err = m.HasPermission(u.Id, "invoice", model.Update)
	if err != nil {
		t.Fatalf("HasPermission failed: %v", err)
	}
	if ok {
		t.Error("Editor should NOT be able to write invoice")
	}

	if err := m.DeleteRole("rid2"); err != nil {
		t.Fatalf("DeleteRole failed: %v", err)
	}

	ok, err = m.HasPermission(u.Id, "invoice", model.Read)
	if err != nil {
		t.Fatalf("HasPermission failed: %v", err)
	}
	if ok {
		t.Error("User should have lost permission after role deletion")
	}
}
