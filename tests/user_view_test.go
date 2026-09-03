//go:build !wasm

package tests

import (
	"testing"

	"github.com/tinywasm/model"
	"github.com/tinywasm/auth"
	"github.com/tinywasm/view"
)

type fakeCaller struct {
	lastOp   string
	lastArgs model.Encodable
}

func (c *fakeCaller) Call(op string, args model.Encodable, out model.Decodable, cb func(error)) {
	c.lastOp = op
	c.lastArgs = args
	if op == auth.OpListUsers {
		if l, ok := out.(*auth.UserList); ok {
			u1 := l.Append().(*auth.User)
			u1.Id = "u1"
			u1.Name = "User One"
			u1.Email = "u1@test.com"

			u2 := l.Append().(*auth.User)
			u2.Id = "u2"
			u2.Name = "User Two"
			u2.Email = "u2@test.com"
		}
		if cb != nil {
			cb(nil)
		}
	} else if op == auth.OpUpsertUser || op == auth.OpDeleteUser {
		if cb != nil {
			cb(nil)
		}
	}
}

func (c *fakeCaller) Dispatch(s string, e model.Encodable) {}

func TestNewView(t *testing.T) {
	fc := &fakeCaller{}
	v := auth.NewView(fc)
	if v == nil {
		t.Fatal("expected view to not be nil")
	}

	// 1. Verify Title
	if v.Title() != "Usuarios" {
		t.Errorf("expected title 'Usuarios', got %s", v.Title())
	}

	// 2. Reload to load items
	v.Reload()

	// 3. Verify items projection
	items := v.Items()
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
	if items[0].ID != "u1" || items[0].Label != "User One" || items[0].Description != "u1@test.com" {
		t.Errorf("wrong item projection at 0: %+v", items[0])
	}
	if items[1].ID != "u2" || items[1].Label != "User Two" || items[1].Description != "u2@test.com" {
		t.Errorf("wrong item projection at 1: %+v", items[1])
	}

	// 4. Select Item and verify return value of Select()
	rec := v.Select("u1")
	if rec == nil {
		t.Fatal("expected selected record to not be nil")
	}
	u, ok := rec.(*auth.User)
	if !ok {
		t.Fatalf("expected record of type *auth.User, got %T", rec)
	}
	if u.Id != "u1" || u.Name != "User One" {
		t.Errorf("wrong record selected: %+v", u)
	}

	// 5. Test Deselect
	if v.Selected() != "u1" {
		t.Errorf("expected selected to be 'u1', got %s", v.Selected())
	}
	v.Deselect()
	if v.Selected() != "" {
		t.Errorf("expected selected to be empty after Deselect, got %s", v.Selected())
	}

	// 6. Test Filter
	filtered := v.Filter("One")
	if len(filtered) != 1 {
		t.Errorf("expected 1 item after filtering for 'One', got %d", len(filtered))
	}
	all := v.Filter("")
	if len(all) != 2 {
		t.Errorf("expected 2 items after clearing filter, got %d", len(all))
	}

	// 7. Save record and verify caller payload via view.Saver capability
	u.Name = "Updated Via Presenter"
	s, ok := v.(view.Saver)
	if !ok {
		t.Fatal("expected view to implement view.Saver")
	}
	s.Save(u)
	if fc.lastOp != auth.OpUpsertUser {
		t.Errorf("expected %s op on save, got %s", auth.OpUpsertUser, fc.lastOp)
	}
	recs := savedRecords(fc.lastArgs)
	savedUser, ok := recs[0].(*auth.User)
	if len(recs) != 1 || !ok || savedUser.Name != "Updated Via Presenter" {
		t.Errorf("wrong payload saved: %+v", fc.lastArgs)
	}

	// 8. Delete record and verify caller payload via view.Deleter capability
	d, ok := v.(view.Deleter)
	if !ok {
		t.Fatal("expected view to implement view.Deleter")
	}
	d.Delete("u2")
	if fc.lastOp != auth.OpDeleteUser {
		t.Errorf("expected %s op on delete, got %s", auth.OpDeleteUser, fc.lastOp)
	}
	ids := deletedIDs(fc.lastArgs)
	if len(ids) != 1 || ids[0] != "u2" {
		t.Errorf("wrong payload deleted: %+v", fc.lastArgs)
	}
}
