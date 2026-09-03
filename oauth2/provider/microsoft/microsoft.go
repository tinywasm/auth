package microsoft

import (
	"github.com/tinywasm/fetch"
	"github.com/tinywasm/json"
	"github.com/tinywasm/model"
	"github.com/tinywasm/auth"
	"github.com/tinywasm/auth/oauth2/provider/google"
)

const (
	msAuthURL  = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
	msTokenURL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
)

// ProviderName identifica a este proveedor en las rutas y en el almacen de
// estado. Un consumidor lo usa con auth.PathOAuthStart / PathOAuthCallback.
const ProviderName = "microsoft"

type MicrosoftProvider struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

func (p *MicrosoftProvider) Name() string {
	return ProviderName
}

func (p *MicrosoftProvider) config() auth.OAuthConfig {
	return auth.OAuthConfig{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		RedirectURL:  p.RedirectURL,
		Scopes:       []string{"User.Read"},
		AuthURL:      msAuthURL,
		TokenURL:     msTokenURL,
	}
}

func (p *MicrosoftProvider) AuthCodeURL(state string) string {
	return google.AuthCodeURLHelper(p.config(), state)
}

func (p *MicrosoftProvider) ExchangeCode(code string) (auth.OAuthToken, error) {
	return google.ExchangeCodeHelper(p.config(), code)
}

type msData struct {
	ID                string
	Email             string
	UserPrincipalName string
	Name              string
}

func (d *msData) EncodeFields(w model.FieldWriter) {}
func (d *msData) IsNil() bool                      { return false }
func (d *msData) DecodeFields(r model.FieldReader) {
	d.ID, _ = r.String("id")
	d.Email, _ = r.String("mail")
	d.UserPrincipalName, _ = r.String("userPrincipalName")
	d.Name, _ = r.String("displayName")
}

func (p *MicrosoftProvider) GetUserInfo(token auth.OAuthToken) (auth.OAuthUserInfo, error) {
	var res auth.OAuthUserInfo
	var errOut error
	done := make(chan bool)

	fetch.Get("https://graph.microsoft.com/v1.0/me").
		Header("Authorization", "Bearer "+token.AccessToken).
		Send(func(resp *fetch.Response, err error) {
			defer func() { done <- true }()
			if err != nil {
				errOut = err
				return
			}
			if resp.Status != 200 {
				errOut = auth.ErrInvalidCredentials
				return
			}
			var data msData
			if err := json.Decode(resp.Text(), &data); err != nil {
				errOut = err
				return
			}
			email := data.Email
			if email == "" {
				email = data.UserPrincipalName
			}
			// Note: Microsoft Graph /v1.0/me API does not expose a verified email
			// field, so EmailVerified remains false by default. This closed default
			// prevents unverified account linking.
			res = auth.OAuthUserInfo{
				ID:            data.ID,
				Email:         email,
				EmailVerified: false,
				Name:          data.Name,
			}
		})

	<-done
	return res, errOut
}
