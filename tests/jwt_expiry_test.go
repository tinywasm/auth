//go:build !wasm

package tests

import (
	"testing"

	"github.com/tinywasm/jwt"
	"github.com/tinywasm/router"
	"github.com/tinywasm/router/mock"
	"github.com/tinywasm/auth"
	"github.com/tinywasm/auth/authority"
	jwtstrategy "github.com/tinywasm/auth/session/jwt"
)

// Un token caducado es el evento más rutinario que existe: una sesión que se acaba.
// Reportarlo como EventJWTTampered dispara la alarma más ruidosa del sistema en su caso
// más tranquilo, y entierra las falsificaciones reales bajo el ruido.
//
// El bug era `if err != nil { tampered }`. La frontera vieja de tinywasm/jwt devolvía
// (Claims, error) y PERMITÍA colapsar caducidad y falsificación en una sola rama; eso no
// es un descuido del call site, es una API que admite un estado ilegal. Ahora el
// desenlace es un jwt.Outcome cerrado y el compilador obliga a separarlos.
func TestExpiredTokenIsNotReportedAsTampering(t *testing.T) {
	secret := []byte("test-secret-32-bytes-long-000000")
	pub := &mockPublisher{}

	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{
		IDs:    testIDs,
		Events: pub,
	})
	if err != nil {
		t.Fatal(err)
	}

	strategy, err := jwtstrategy.New(secret, 0, m, m)
	if err != nil {
		t.Fatal(err)
	}
	strategy.AsBearer()
	m.SetStrategy(strategy)

	userCRUD := getHandler(m, "users")
	res, err := userCRUD.Create(auth.User{Email: "exp@test.com", Name: "Exp"})
	if err != nil {
		t.Fatal(err)
	}
	u := res.(auth.User)

	// Firmado con el secreto BUENO: es auténtico, solo que caducó hace años. Se construyen
	// los Claims a mano porque NewClaims trata ttl<=0 como «usa el valor por defecto» — un
	// ttl negativo daría un token VÁLIDO de 24h, no uno caducado.
	expired, err := jwt.Sign(secret, jwt.Claims{Sub: u.Id, Iat: 1, Exp: 2})
	if err != nil {
		t.Fatal(err)
	}

	ctx := &mock.Context{}
	ctx.SetHeader("Authorization", "Bearer "+expired)
	m.Authenticate()(func(c router.Context) {
		if c.UserID() != "" {
			t.Errorf("un token caducado autenticó a %q", c.UserID())
		}
	})(ctx)

	for _, e := range pub.SecurityEvents() {
		if e.Type == auth.EventJWTTampered {
			t.Fatal("una sesión caducada se reportó como manipulación (EventJWTTampered): " +
				"la alarma de falsificación salta en el caso más rutinario del sistema")
		}
	}
}

// La contraparte: una falsificación de verdad SÍ tiene que sonar. Sin este test, "no
// notifiques nunca" pasaría el test de arriba.
func TestForgedTokenIsReportedAsTampering(t *testing.T) {
	secret := []byte("test-secret-32-bytes-long-000000")
	pub := &mockPublisher{}

	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{
		IDs:    testIDs,
		Events: pub,
	})
	if err != nil {
		t.Fatal(err)
	}

	strategy, err := jwtstrategy.New(secret, 0, m, m)
	if err != nil {
		t.Fatal(err)
	}
	strategy.AsBearer()
	m.SetStrategy(strategy)

	// Firmado con OTRO secreto: no es auténtico.
	forged, err := jwt.Sign([]byte("a-completely-different-secret-00"), jwt.NewClaims("u1", 3600))
	if err != nil {
		t.Fatal(err)
	}

	ctx := &mock.Context{}
	ctx.SetHeader("Authorization", "Bearer "+forged)
	m.Authenticate()(func(c router.Context) {
		if c.UserID() != "" {
			t.Errorf("un token falsificado autenticó a %q", c.UserID())
		}
	})(ctx)

	for _, e := range pub.SecurityEvents() {
		if e.Type == auth.EventJWTTampered {
			return
		}
	}
	t.Fatal("una falsificación no emitió EventJWTTampered: la alarma quedó muda")
}
