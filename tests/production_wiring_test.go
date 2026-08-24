//go:build !wasm

package tests

import (
	"strings"
	"testing"

	"github.com/tinywasm/crypto/bcrypt"
	"github.com/tinywasm/form"
	"github.com/tinywasm/json"
	"github.com/tinywasm/model"
	"github.com/tinywasm/router"
	"github.com/tinywasm/router/mock"
	"github.com/tinywasm/auth"
	"github.com/tinywasm/auth/authority"
	emailpassword "github.com/tinywasm/auth/email_password"
)

func TestProductionWiring(t *testing.T) {
	emailpassword.DefaultHashCost = bcrypt.MinCost

	t.Run("Widgets", testWidgets)
	t.Run("ConsumerViewSSR", testConsumerViewSSR)
	t.Run("MountAPI", testMountAPI)
	t.Run("MeTool", testMeTool)
}

// testConsumerViewSSR plays the role of a consumer app building its own
// login page over auth.LoginData and posting to auth.PathLogin: the
// rendered HTML must expose the field names the handler expects.
func testConsumerViewSSR(t *testing.T) {
	f, err := form.New("login", &auth.LoginData{}, testIDs)
	if err != nil {
		t.Fatalf("form.New failed: %v", err)
	}
	f.SetSSR(true)

	html := f.String()

	if !strings.Contains(html, "name='email'") {
		t.Errorf("consumer-view HTML missing email field: %s", html)
	}
	if !strings.Contains(html, "name='password'") {
		t.Errorf("consumer-view HTML missing password field: %s", html)
	}
}

func testWidgets(t *testing.T) {
	cases := []struct {
		name     string
		data     model.Fielder
		expected int
	}{
		{"LoginData", &auth.LoginData{}, 2},
		{"RegisterData", &auth.RegisterData{}, 4},
		{"ProfileData", &auth.ProfileData{}, 2},
		{"PasswordData", &auth.PasswordData{}, 3},
	}

	for _, tc := range cases {
		_, err := form.New("test", tc.data, testIDs)
		if err != nil {
			t.Fatalf("%s: form.New failed: %v", tc.name, err)
		}
		schema := tc.data.Schema()
		count := len(schema)
		if count != tc.expected {
			t.Errorf("%s: expected %d widgets, got %d", tc.name, tc.expected, count)
		}
	}
}

func testMountAPI(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{
		IDs:        testIDs,
		CookieName: "test_session",
	})
	if err != nil {
		t.Fatal(err)
	}
	m.Enable(emailpassword.New(m, m, m))

	email := "user@test.com"
	pass := "password123"
	admin, err := m.CreateUser(email, "Admin", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetPassword(admin.Id, pass); err != nil {
		t.Fatal(err)
	}

	r := &mock.Router{}
	m.MountAPI(r)

	// Verify that all routes registered by MountAPI are public.
	// This module only provides pre-identity flows (login, logout, oauth).
	for _, info := range r.Routes() {
		if !info.IsPublic() {
			t.Errorf("Route %s %s must be .Public()", info.Method, info.Path)
		}
	}

	// 1. POST /login (success) - JSON
	ctxJson := &mock.Context{
		InMethod: "POST",
		InPath:   auth.PathLogin,
	}
	ctxJson.SetHeader("Content-Type", "application/json")
	loginData := &auth.LoginData{Email: email, Password: pass}
	var postBody string
	json.Encode(loginData, &postBody)
	ctxJson.InBody = []byte(postBody)

	r.Invoke("POST", auth.PathLogin, ctxJson)
	if ctxJson.Status != 302 {
		t.Errorf("POST /login (JSON) status: %d", ctxJson.Status)
	}
	c, ok := ctxJson.Cookie("test_session")
	if !ok || c.Value == "" {
		t.Errorf("POST /login (JSON) cookie missing or empty")
	}

	// 2. POST /login (failure) - JSON
	ctxFailJson := &mock.Context{
		InMethod: "POST",
		InPath:   auth.PathLogin,
	}
	ctxFailJson.SetHeader("Content-Type", "application/json")
	loginDataFail := &auth.LoginData{Email: email, Password: "wrong_password"}
	var postBodyFail string
	json.Encode(loginDataFail, &postBodyFail)
	ctxFailJson.InBody = []byte(postBodyFail)

	r.Invoke("POST", auth.PathLogin, ctxFailJson)
	if ctxFailJson.Status != 401 {
		t.Errorf("POST /login (JSON failure) status expected 401, got: %d", ctxFailJson.Status)
	}

	// 4. POST /logout
	sessID := c.Value

	ctxLogout := &mock.Context{InMethod: "POST", InPath: auth.PathLogout}
	ctxLogout.SetCookie(router.Cookie{Name: "test_session", Value: sessID})
	r.Invoke("POST", auth.PathLogout, ctxLogout)
	if ctxLogout.Status != 302 {
		t.Errorf("POST /logout status: %d", ctxLogout.Status)
	}
	if ctxLogout.GetHeader("Location") != auth.PathLogin {
		t.Errorf("POST /logout redirect: %s", ctxLogout.GetHeader("Location"))
	}
	logoutCookie, ok := ctxLogout.Cookie("test_session")
	if !ok || logoutCookie.Value != "" {
		t.Errorf("POST /logout cookie not cleared: %+v", logoutCookie)
	}
}

// testMeTool verifies the "me" op returns the identity fields authority
// owns. Permissions/Roles are intentionally absent: authority never
// resolves RBAC (see ARCHITECTURE.md) — a consumer that needs them in the
// same response composes this with rbac.Service in its own handler.
func testMeTool(t *testing.T) {
	db := newTestDB(t)
	m, _ := authority.New(db, auth.Config{IDs: testIDs})

	email := "tools@test.com"
	uObj, err := m.CreateUser(email, "Tools", "")
	if err != nil {
		t.Fatal(err)
	}

	reg := &mockOpRegistry{ops: make(map[string]*mockRoute)}
	m.MountOps(reg)

	route := reg.ops[auth.OpMe]
	if route == nil {
		t.Fatal("me op not registered")
	}

	ctx := &mock.Context{}
	ctx.SetUserID(uObj.Id)

	route.handler(ctx)

	var profile auth.ProfileDTO
	if err := json.Decode(ctx.ResponseBody(), &profile); err != nil {
		t.Fatalf("failed to decode profile: %v", err)
	}

	if profile.Id != uObj.Id || profile.Email != email {
		t.Errorf("expected profile for %s, got %+v", email, profile)
	}
	if len(profile.Permissions) != 0 {
		t.Errorf("expected no permissions from authority alone, got %v", profile.Permissions)
	}
}
