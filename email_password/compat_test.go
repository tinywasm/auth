package emailpassword

import "testing"

// TestLegacyHashStillVerifies comprueba que un hash de bcrypt guardado por la
// implementación anterior —golang.org/x/crypto/bcrypt— sigue verificando
// correctamente contra tinywasm/crypto/bcrypt. Es el único criterio no
// negociable del cambio de bcrypt: si esto falla, todas las contraseñas
// guardadas en producción quedan inservibles y nadie lo nota hasta que un
// cliente no puede entrar a su cuenta.
//
// Hash de "correcthorsebatterystaple" con coste 10, producido por
// golang.org/x/crypto/bcrypt v0.55.0 antes de este cambio.
func TestLegacyHashStillVerifies(t *testing.T) {
	const legacyHash = "$2a$10$6nq4sbXLJ.qUES28xiWxP.ysUu4kfoP3uCqgb4MXtINMU8dmmL1Ou"
	if err := VerifyPassword(legacyHash, "correcthorsebatterystaple"); err != nil {
		t.Fatalf("un hash generado por golang.org/x/crypto/bcrypt ya no verifica: %v", err)
	}
}
