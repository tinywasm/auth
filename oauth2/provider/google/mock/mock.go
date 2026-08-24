package mock

import (
	"github.com/tinywasm/auth"
	"github.com/tinywasm/auth/oauth2/provider/google"
)

// MockProvider simula Google OAuth sin red, manteniendo el mismo flujo y rutas
// que producción (/oauth/google → /oauth/callback/google). Es idéntico visualmente
// al login real (mismo botón, misma URL) pero sin secretos ni Google.
//
// Toda la identidad (ID, Email, Name, Avatar) debe ser configurada por el
// consumidor (ej. misitio/config/auth_local.go). No hay valores harcodeados.
type MockProvider struct {
	// User es la identidad simulada que se devolverá en GetUserInfo.
	// Requerido: el consumidor debe fijarlo explícitamente.
	User auth.OAuthUserInfo
}

func (m *MockProvider) Name() string {
	return google.ProviderName
}

// AuthCodeURL devuelve directamente la URL de callback con state y code mock.
// El navegador sigue el 302 de /oauth/google y cae inmediatamente en
// /oauth/callback/google?state=...&code=mockcode, sin salir a Google.
func (m *MockProvider) AuthCodeURL(state string) string {
	return auth.PathOAuthCallback(google.ProviderName) + "?state=" + state + "&code=mockcode"
}

func (m *MockProvider) ExchangeCode(code string) (auth.OAuthToken, error) {
	return auth.OAuthToken{
		AccessToken: "mock_access_" + code,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}, nil
}

func (m *MockProvider) GetUserInfo(token auth.OAuthToken) (auth.OAuthUserInfo, error) {
	// El consumidor debe configurar User explícitamente; no hay fallback harcodeado.
	return m.User, nil
}

var _ auth.OAuthProvider = (*MockProvider)(nil)
