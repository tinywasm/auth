//go:build !wasm

package tests

import (
	"github.com/tinywasm/model"
	"github.com/tinywasm/orm"
	"github.com/tinywasm/router"
	"github.com/tinywasm/server/httpd"
	"github.com/tinywasm/sqlite"
	"github.com/tinywasm/unixid"
	"github.com/tinywasm/auth"
	"github.com/tinywasm/auth/authority"
	emailpassword "github.com/tinywasm/auth/email_password"
	"github.com/tinywasm/auth/session/jwt"
	trustedip "github.com/tinywasm/auth/trusted_ip"
)

func Example_mustCompile() {
	// 1. Establish database connection and wrap in ORM
	conn, err := sqlite.Open("app.db")
	if err != nil {
		panic(err)
	}
	db := orm.New(conn)

	// 2. Generate required ID Generator (e.g. tinywasm/unixid)
	ids, err := unixid.NewUnixID()
	if err != nil {
		panic(err)
	}

	// 3. Initialize the pure authority orchestrator
	m, err := authority.New(db, auth.Config{
		IDs:        ids,
		CookieName: "session",
		TokenTTL:   86400, // 24 hours
		TrustProxy: true,
	})
	if err != nil {
		panic(err)
	}

	// 4. Opt into a stateless JWT strategy (replacing default cookie session)
	secret := []byte("your-secret-key-must-be-32-bytes")
	strategy, err := jwt.New(secret, 86400, m, m)
	if err != nil {
		panic(err)
	}
	m.SetStrategy(strategy)

	// 5. Construct and configure authentication modes.
	// We inject Module 'm' which implements the narrow ports.
	epAuth := emailpassword.New(m, m, m, emailpassword.WithTrustProxy(true))
	tiAuth := trustedip.New(m, m, m, m, true)

	// 6. Enable the authenticators in the authority orchestrator
	m.Enable(epAuth, tiAuth)

	// 7. Monta las rutas de user y arranca el servidor. El Router concreto lo crea
	//    httpd, no el paquete router. Authn corre el middleware de identidad de forma
	//    global; Authorize es el gate RBAC de las rutas que declaran .Requires(...).
	srv := httpd.New(httpd.Config{
		Port:      "8080",
		Authn:     m.Authenticate(), // router.Middleware: identifica al usuario, inyecta su ID en el ctx
		Authorize: m.Can,            // model.Authorizer: RBAC
	}).Mount(m) // m es un router.APIModule → monta POST /login, /logout, /login/rut

	// 8. Ruta propia protegida: se registra en el Router del server y declara su
	//    permiso; el Authorize lo hace cumplir (o se chequea m.Can a mano dentro).
	srv.Router().Get("/api/dashboard", func(ctx router.Context) {
		if !m.Can(ctx.UserID(), "reports", model.Read) {
			ctx.WriteStatus(403)
			return
		}
		ctx.Write([]byte("Welcome to reports dashboard"))
	}).Requires("reports", model.Read)

	// 9. Bootstrap / Seed first administrator user
	err = m.Bootstrap(authority.Seed{
		Email:    "admin@company.com",
		Password: "super-secure-admin-password",
		Name:     "Administrator",
		Role:     "admin",
		Grants: []model.Grant{
			{Resource: model.Wildcard, Actions: model.AllActions}, // full permissions
		},
	})
	if err != nil {
		panic(err)
	}
}
