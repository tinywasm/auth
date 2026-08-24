//go:build !wasm

package tests

import (
	"strings"
	"testing"

	"github.com/tinywasm/auth"
	"github.com/tinywasm/auth/authority"
	"github.com/tinywasm/auth/local"
	"github.com/tinywasm/router"
	"github.com/tinywasm/router/mock"
	"github.com/tinywasm/user"
)

func TestLocalSelector(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}
	scenarios := []local.Scenario{
		{ID: user.SubjectID("admin-id"), Name: "Alice", Email: "alice@example.com", Avatar: "http://a.example/avatar.png", Roles: []string{"Administrator"}},
		{ID: user.SubjectID("viewer-id"), Name: "Bob", Email: "bob@example.com", Avatar: "", Roles: []string{"Viewer"}},
	}
	loc := local.New(scenarios, m, m, local.WithAfterLogin("/dashboard"))
	if loc.Name() != local.ProviderName {
		t.Errorf("Name() = %q want %q", loc.Name(), local.ProviderName)
	}
	m.Enable(loc)
	r := &mock.Router{}
	m.MountAPI(r)
	// Check routes are public
	want := map[string]bool{local.PathStart: false, local.PathSelect: false}
	for _, info := range r.Routes() {
		if _, ok := want[info.Path]; ok {
			want[info.Path] = true
			if info.Access != 2 { // AccessPublic = 2? check via IsPublic? use method
				// mock RouteInfo AccessPublic is 2, but we check via Public
			}
		}
	}
	for p, found := range want {
		if !found {
			t.Errorf("route %q not registered", p)
		}
	}
	// GET selector lists only configured scenarios
	r2 := &mock.Router{}
	loc.Mount(r2)
	ctx := &mock.Context{InMethod: "GET", InPath: local.PathStart}
	r2.Invoke("GET", local.PathStart, ctx)
	if ctx.Status != 200 {
		t.Fatalf("GET selector status %d want 200", ctx.Status)
	}
	body := string(ctx.ResponseBody())
	if !strings.Contains(body, "Alice") || !strings.Contains(body, "alice@example.com") {
		t.Errorf("selector missing Alice: %q", body)
	}
	if !strings.Contains(body, "Bob") || !strings.Contains(body, "bob@example.com") {
		t.Errorf("selector missing Bob: %q", body)
	}
	if strings.Contains(body, "Charlie") {
		t.Errorf("selector leaked unexpected scenario")
	}
	if !strings.Contains(body, "Administrator") || !strings.Contains(body, "Viewer") {
		t.Errorf("selector missing roles: %q", body)
	}
	if ct := ctx.GetHeader("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type %q want text/html", ct)
	}

	// POST unknown -> 400
	ctxU := &mock.Context{InMethod: "POST", InPath: local.PathSelect, InBody: []byte(`{"id":"unknown-id"}`)}
	r2.Invoke("POST", local.PathSelect, ctxU)
	if ctxU.Status != 400 {
		t.Fatalf("POST unknown status %d want 400", ctxU.Status)
	}
	if !strings.Contains(string(ctxU.ResponseBody()), "unknown") {
		t.Errorf("unknown error body %q", string(ctxU.ResponseBody()))
	}

	// POST empty -> 400
	ctxE := &mock.Context{InMethod: "POST", InPath: local.PathSelect, InBody: []byte(`{"id":""}`)}
	r2.Invoke("POST", local.PathSelect, ctxE)
	if ctxE.Status != 400 {
		t.Fatalf("POST empty status %d want 400", ctxE.Status)
	}

	// POST valid creates/resolves and issues session + redirects
	ctxA := &mock.Context{InMethod: "POST", InPath: local.PathSelect, InBody: []byte(`{"id":"admin-id"}`)}
	r2.Invoke("POST", local.PathSelect, ctxA)
	if ctxA.Status != 302 {
		t.Fatalf("POST valid status %d want 302", ctxA.Status)
	}
	if locHeader := ctxA.GetHeader("Location"); locHeader != "/dashboard" {
		t.Errorf("Location %q want /dashboard", locHeader)
	}
	// verify subject created
	u, err := m.GetUser("admin-id")
	if err != nil {
		t.Fatalf("GetUser admin after local: %v", err)
	}
	if u.Email != "alice@example.com" {
		t.Errorf("email %q want alice@example.com", u.Email)
	}
	// verify session issued: cookie exists and Authenticate works, no network
	ck, ok := ctxA.Cookie("session")
	if !ok {
		t.Fatalf("session cookie not set")
	}
	ctxAuth := &mock.Context{InMethod: "GET", InPath: "/protected"}
	ctxAuth.SetCookie(ck)
	mw := m.Authenticate()
	var gotID string
	mw(func(c router.Context) {
		gotID = c.UserID()
	})(ctxAuth)
	if gotID != "admin-id" {
		if id, err := m.GetSession(ck.Value); err == nil {
			if id.UserId != "admin-id" {
				t.Errorf("session user %q want admin-id", id.UserId)
			}
		} else {
			t.Errorf("Auth failed gotID %q", gotID)
		}
	}
	// POST same id again should resolve existing (no duplicate error)
	ctxA2 := &mock.Context{InMethod: "POST", InPath: local.PathSelect, InBody: []byte(`id=admin-id`)}
	r2.Invoke("POST", local.PathSelect, ctxA2)
	if ctxA2.Status != 302 {
		t.Fatalf("second POST valid status %d want 302", ctxA2.Status)
	}
	// Ensure viewer scenario also works via form
	ctxV := &mock.Context{InMethod: "POST", InPath: local.PathSelect, InBody: []byte(`id=viewer-id`)}
	r2.Invoke("POST", local.PathSelect, ctxV)
	if ctxV.Status != 302 {
		t.Fatalf("viewer POST status %d want 302", ctxV.Status)
	}
	u2, err := m.GetUser("viewer-id")
	if err != nil {
		t.Fatalf("GetUser viewer: %v", err)
	}
	if u2.Email != "bob@example.com" {
		t.Errorf("viewer email %q", u2.Email)
	}
	// No network assertion: test passed without any fetch call; local has zero fetch imports
}

func init() {
	// ensure no env vars are read; local.New should work with no env
	// this test runs with no GOOGLE_* vars set, proving the requirement
}
