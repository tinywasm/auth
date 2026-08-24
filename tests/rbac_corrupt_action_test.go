//go:build !wasm

package tests

import (
	"testing"

	"github.com/tinywasm/model"
	"github.com/tinywasm/orm"
	"github.com/tinywasm/auth"
	"github.com/tinywasm/auth/authority"
)

// seedCorruptPermission da al usuario un rol cuyo único permiso tiene una acción ilegible.
// Una fila así solo puede llegar desde la BD: la escritura está cerrada por el tipo
// (CreatePermission recibe model.Action). Llega de una edición a mano, una migración, o una
// versión vieja de la librería.
func seedCorruptPermission(t *testing.T, db *orm.DB, m *authority.Module) string {
	t.Helper()

	userCRUD := getHandler(m, "users")
	res, err := userCRUD.Create(auth.User{Email: "corrupt@test.com", Name: "Corrupt"})
	if err != nil {
		t.Fatal(err)
	}
	u := res.(auth.User)

	if err := m.CreateRole("r_corrupt", "editor", "Editor", ""); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&auth.Permission{
		Id:       "p_corrupt",
		Name:     "corrupt",
		Resource: "docs",
		Action:   "raed", // no es CRUD: ParseAction debe fallar
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.AssignPermission("r_corrupt", "p_corrupt"); err != nil {
		t.Fatal(err)
	}
	if err := m.AssignRole(u.Id, "r_corrupt"); err != nil {
		t.Fatal(err)
	}
	return u.Id
}

// Tragarse una acción ilegible es el fallo que el plan prohíbe explícitamente ("No te la
// tragues"): el permiso REAL desaparece —el usuario deja de poder leer `docs`— y la fila
// corrupta sigue ahí para siempre, sin que nadie vea un error. Denegar está bien;
// denegar EN SILENCIO no.
func TestHasPermission_CorruptActionFailsLoudly(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}
	uid := seedCorruptPermission(t, db, m)

	ok, err := m.HasPermission(uid, "docs", model.Read)
	if ok {
		t.Error("una fila corrupta concedió permiso")
	}
	if err == nil {
		t.Fatal("HasPermission se tragó una acción ilegible: devolvió (false, nil), " +
			"indistinguible de «este usuario no tiene ese permiso»")
	}
}

// Can es la costura model.Authorizer: solo puede devolver bool. El error no cabe en la
// firma, así que la corrupción tiene que salir por el canal de observabilidad, o no sale.
func TestCan_CorruptActionDeniesAndNotifies(t *testing.T) {
	pub := &mockPublisher{}
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{
		IDs:    testIDs,
		Events: pub,
	})
	if err != nil {
		t.Fatal(err)
	}
	uid := seedCorruptPermission(t, db, m)

	if m.Can(uid, "docs", model.Read) {
		t.Error("Can concedió permiso sobre una fila corrupta")
	}

	for _, e := range pub.SecurityEvents() {
		if e.Type == auth.EventPermissionCorrupt {
			return
		}
	}
	t.Error("Can denegó por corrupción sin emitir EventPermissionCorrupt: la fila corrupta " +
		"queda invisible y el permiso real desaparecido")
}
