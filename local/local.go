// Package local implements the development authenticator described in the
// Local Simulator Contract. It never contacts Google, never uses fetch, and
// has no environment variables or implicit dev-mode switches.
package local

import (
	"github.com/tinywasm/auth"
	"github.com/tinywasm/fmt"
	"github.com/tinywasm/model"
	"github.com/tinywasm/router"
	"github.com/tinywasm/user"
)

// ProviderName is the stable name exposed to logs and security events.
const ProviderName = "local"

// PathStart is the GET route that serves the scenario selector.
const PathStart = "/local"

// PathSelect is the POST route that consumes the selected scenario identifier.
const PathSelect = "/local/select"

// Scenario is an immutable development identity. RoleLabels are only a
// transparent description of the already-seeded authorization state; this
// package never assigns roles.
type Scenario struct {
	ID    user.SubjectID
	Name  string
	Email string
	Avatar string
	Roles []string
}

// Authenticator is a development Authenticator that presents a selector of
// preconfigured scenarios and issues a normal session for the chosen one.
type Authenticator struct {
	scenarios  []Scenario
	store      auth.SubjectStore
	issuer     auth.SessionIssuer
	afterLogin string
}

// Option configures the authenticator.
type Option func(*Authenticator)

// WithAfterLogin sets the redirect target after a successful selection.
func WithAfterLogin(path string) Option {
	return func(a *Authenticator) { a.afterLogin = path }
}

// New creates a local authenticator. scenarios is copied, the slice must not be
// mutated after construction. store and issuer are required.
func New(scenarios []Scenario, store auth.SubjectStore, issuer auth.SessionIssuer, opts ...Option) *Authenticator {
	copied := make([]Scenario, len(scenarios))
	for i, s := range scenarios {
		roles := make([]string, len(s.Roles))
		for j, r := range s.Roles {
			roles[j] = r
		}
		copied[i] = Scenario{
			ID:    s.ID,
			Name:  s.Name,
			Email: s.Email,
			Avatar: s.Avatar,
			Roles: roles,
		}
	}
	a := &Authenticator{
		scenarios: copied,
		store:     store,
		issuer:    issuer,
	}
	for _, o := range opts {
		o(a)
	}
	return a
}

// Name implements auth.Authenticator.
func (a *Authenticator) Name() string { return ProviderName }

// Mount implements auth.Authenticator.
func (a *Authenticator) Mount(r router.Router) {
	afterLogin := a.afterLogin
	if afterLogin == "" {
		afterLogin = auth.PathAfterLogin
	}
	r.Get(PathStart, func(ctx router.Context) {
		ctx.SetHeader("Content-Type", "text/html; charset=utf-8")
		ctx.WriteStatus(200)
		html := buildSelector(a.scenarios)
		_, _ = ctx.Write([]byte(html))
	}).Public()
	r.Post(PathSelect, func(ctx router.Context) {
		id := parseScenarioID(ctx)
		if id == "" {
			ctx.WriteStatus(400)
			_, _ = ctx.Write([]byte("scenario id is required"))
			return
		}
		sc := findScenario(a.scenarios, user.SubjectID(id))
		if sc == nil {
			ctx.WriteStatus(400)
			_, _ = ctx.Write([]byte("unknown scenario"))
			return
		}
		subj, err := a.store.GetOrCreateSubject(sc.ID, sc.Email, sc.Name, sc.Avatar)
		if err != nil {
			ctx.WriteStatus(500)
			_, _ = ctx.Write([]byte(err.Error()))
			return
		}
		if err := a.issuer.IssueSession(ctx, string(subj.ID)); err != nil {
			ctx.WriteStatus(500)
			_, _ = ctx.Write([]byte(err.Error()))
			return
		}
		ctx.SetHeader("Location", afterLogin)
		ctx.WriteStatus(302)
	}).Public()
}

func findScenario(scenarios []Scenario, id user.SubjectID) *Scenario {
	for i := range scenarios {
		if scenarios[i].ID == id {
			return &scenarios[i]
		}
	}
	return nil
}

func parseScenarioID(ctx router.Context) string {
	payload := &selectPayload{}
	if err := ctx.Decode(payload); err == nil && payload.ID != "" {
		return payload.ID
	}
	body := string(ctx.Body())
	if body != "" {
		// Try JSON-like extraction without map/reflect
		if fmt.Contains(body, "\"id\"") || fmt.Contains(body, "\"scenario") {
			// crude JSON parse for "id": "value"
			parts := fmt.Split(body, "\"")
			for i := 0; i < len(parts)-1; i++ {
				key := parts[i]
				if key == "id" || key == "scenario" || key == "scenario_id" {
					// look ahead for colon then value
					if i+2 < len(parts) {
						val := parts[i+2]
						val = fmt.Convert(val).TrimSpace().String()
						// strip colon and spaces already by split on quotes
						return val
					}
				}
			}
		}
		// form-urlencoded: id=xxx&...
		for _, part := range fmt.Split(body, "&") {
			kv := fmt.Split(part, "=")
			if len(kv) == 2 {
				k := fmt.Convert(kv[0]).TrimSpace().String()
				if k == "id" || k == "scenario" || k == "scenario_id" {
					return fmt.Convert(kv[1]).TrimSpace().String()
				}
			}
		}
		trimmed := fmt.Convert(body).TrimSpace().String()
		if trimmed != "" && !fmt.Contains(trimmed, "=") && !fmt.Contains(trimmed, "{") {
			return trimmed
		}
	}
	// also try query string in Path
	path := ctx.Path()
	if fmt.Contains(path, "?") {
		qs := fmt.Split(path, "?")[1]
		for _, part := range fmt.Split(qs, "&") {
			kv := fmt.Split(part, "=")
			if len(kv) == 2 && (kv[0] == "id" || kv[0] == "scenario") {
				return kv[1]
			}
		}
	}
	return ""
}

type selectPayload struct {
	ID string
}

func (p *selectPayload) DecodeFields(r model.FieldReader) {
	p.ID, _ = r.String("id")
	if p.ID == "" {
		p.ID, _ = r.String("scenario")
	}
	if p.ID == "" {
		p.ID, _ = r.String("scenario_id")
	}
	if p.ID == "" {
		p.ID, _ = r.String("ID")
	}
}
func (p *selectPayload) IsNil() bool { return p == nil }

func buildSelector(scenarios []Scenario) string {
	out := "<!doctype html><html><head><meta charset=\"utf-8\"><title>Select identity</title></head><body><h1>Select development identity</h1><ul>"
	for _, s := range scenarios {
		roles := ""
		for i, r := range s.Roles {
			if i > 0 {
				roles += ", "
			}
			roles += escapeHTML(r)
		}
		if roles == "" {
			roles = "no roles"
		}
		out += "<li><form method=\"POST\" action=\"" + PathSelect + "\"><input type=\"hidden\" name=\"id\" value=\"" + escapeHTML(string(s.ID)) + "\">"
		out += "<strong>" + escapeHTML(s.Name) + "</strong> (" + escapeHTML(s.Email) + ") — " + roles
		out += " <button type=\"submit\">Login as " + escapeHTML(s.Name) + "</button></form></li>"
	}
	out += "</ul></body></html>"
	return out
}

func escapeHTML(s string) string {
	s = fmt.Convert(s).Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;").Replace("'", "&#39;").String()
	return s
}

var _ auth.Authenticator = (*Authenticator)(nil)
