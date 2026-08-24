//go:build !wasm

package tests

import (
	"testing"

	"github.com/tinywasm/json"
	"github.com/tinywasm/model"
	"github.com/tinywasm/router/mock"
	"github.com/tinywasm/auth"
	"github.com/tinywasm/auth/authority"
	"github.com/tinywasm/auth/session/jwt"
)

func TestTools_Me(t *testing.T) {
	db := newTestDB(t)
	m, _ := authority.New(db, auth.Config{IDs: testIDs})

	userCRUD := getHandler(m, "users")
	res, err := userCRUD.Create(auth.User{Email: "me@test.com", Name: "Me User"})
	if err != nil {
		t.Fatal(err)
	}
	u := res.(auth.User)

	t.Run("Authenticated me returns profile", func(t *testing.T) {
		reg := &mockOpRegistry{ops: make(map[string]*mockRoute)}
		m.MountOps(reg)

		route := reg.ops[auth.OpMe]
		if route == nil {
			t.Fatal("me op not registered")
		}
		if !route.authenticated {
			t.Error("me op should be authenticated")
		}

		ctx := &mock.Context{}
		ctx.SetUserID(u.Id)

		route.handler(ctx)

		if ctx.Status != 0 && ctx.Status != 200 {
			t.Fatalf("handler returned status: %d", ctx.Status)
		}

		var profile auth.ProfileDTO
		if err := json.Decode(ctx.ResponseBody(), &profile); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if profile.Id != u.Id || profile.Email != u.Email {
			t.Errorf("mismatch: got %v, want %v", profile, u)
		}
	})

	t.Run("Anonymous me returns error", func(t *testing.T) {
		reg := &mockOpRegistry{ops: make(map[string]*mockRoute)}
		m.MountOps(reg)

		route := reg.ops[auth.OpMe]
		ctx := &mock.Context{}
		// No userID set
		route.handler(ctx)
		if ctx.Status != 401 {
			t.Errorf("expected 401, got %d", ctx.Status)
		}
	})
}

func TestAdminOps(t *testing.T) {
	db := newTestDB(t)
	m, _ := authority.New(db, auth.Config{IDs: testIDs})

	// 1. Verify MountOps registration and Gates
	reg := &mockOpRegistry{ops: make(map[string]*mockRoute)}
	m.MountOps(reg)

	listRoute := reg.ops[auth.OpListUsers]
	if listRoute == nil {
		t.Fatal("list_users op not registered")
	}
	if listRoute.requiredRes != "users" || listRoute.requiredAct != model.Read {
		t.Errorf("list_users has wrong gating: res=%s act=%v", listRoute.requiredRes, listRoute.requiredAct)
	}

	upsertRoute := reg.ops[auth.OpUpsertUser]
	if upsertRoute == nil {
		t.Fatal("upsert_user op not registered")
	}
	if upsertRoute.requiredRes != "users" || upsertRoute.requiredAct != (model.Create|model.Update) {
		t.Errorf("upsert_user has wrong gating: res=%s act=%v", upsertRoute.requiredRes, upsertRoute.requiredAct)
	}

	deleteRoute := reg.ops[auth.OpDeleteUser]
	if deleteRoute == nil {
		t.Fatal("delete_user op not registered")
	}
	if deleteRoute.requiredRes != "users" || deleteRoute.requiredAct != model.Delete {
		t.Errorf("delete_user has wrong gating: res=%s act=%v", deleteRoute.requiredRes, deleteRoute.requiredAct)
	}

	// 2. Exercise handlers
	t.Run("list_users handler", func(t *testing.T) {
		ctx := &mock.Context{}
		listRoute.handler(ctx)

		if ctx.Status != 0 && ctx.Status != 200 {
			t.Fatalf("list_users handler failed: %d", ctx.Status)
		}

		var list auth.UserList
		if err := json.Decode(ctx.ResponseBody(), &list); err != nil {
			t.Fatalf("failed to decode list: %v", err)
		}
	})

	t.Run("upsert_user create handler", func(t *testing.T) {
		u := &auth.User{
			Email: "created_op@test.com",
			Name:  "Op Created",
			Phone: "12345",
		}
		ctx := &mock.Context{}
		var body string
		if err := json.Encode(u, &body); err != nil {
			t.Fatal(err)
		}
		ctx.InBody = []byte(body)

		upsertRoute.handler(ctx)

		// Verify user got created in DB
		saved, err := m.GetUserByEmail("created_op@test.com")
		if err != nil {
			t.Fatalf("user was not created: %v", err)
		}
		if saved.Name != "Op Created" {
			t.Errorf("wrong user name: %s", saved.Name)
		}

		t.Run("upsert_user update handler", func(t *testing.T) {
			saved.Name = "Op Updated"
			ctxUpdate := &mock.Context{}
			var bodyUpdate string
			if err := json.Encode(&saved, &bodyUpdate); err != nil {
				t.Fatal(err)
			}
			ctxUpdate.InBody = []byte(bodyUpdate)

			upsertRoute.handler(ctxUpdate)

			// Verify user got updated in DB
			updated, err := m.GetUser(saved.Id)
			if err != nil {
				t.Fatalf("failed to retrieve updated user: %v", err)
			}
			if updated.Name != "Op Updated" {
				t.Errorf("user name not updated: %s", updated.Name)
			}

			t.Run("delete_user handler", func(t *testing.T) {
				ctxDel := &mock.Context{}
				var bodyDel string
				if err := json.Encode(&updated, &bodyDel); err != nil {
					t.Fatal(err)
				}
				ctxDel.InBody = []byte(bodyDel)

				deleteRoute.handler(ctxDel)

				// Verify user got deleted from DB
				_, err := m.GetUser(updated.Id)
				if err != auth.ErrNotFound {
					t.Errorf("expected ErrNotFound after deletion, got %v", err)
				}
			})
		})
	})
}

func TestNew_Validation(t *testing.T) {
	db := newTestDB(t)

	t.Run("JWT strategy requires a secret", func(t *testing.T) {
		m, _ := authority.New(db, auth.Config{IDs: testIDs})
		_, err := jwt.New(nil, 0, m, m)
		if err == nil {
			t.Error("expected error when secret is empty")
		}
	})

	t.Run("Cookie strategy (default) needs no secret", func(t *testing.T) {
		_, err := authority.New(db, auth.Config{IDs: testIDs})
		if err != nil {
			t.Fatal(err)
		}
	})
}
