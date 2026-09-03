---
PLAN: "fix(security): unguessable session ids and OAuth state, browser-bound state, verified-email account linking"
EXECUTOR: jules
REVIEWER: none
---

> Este plan se despacha con el flujo CodeJob. Ver skill: `agents-workflow`.
> No ejecutes `gopush` ni `codejob` — son herramientas del desarrollador local.

# PLAN — `tinywasm/auth`: credenciales impredecibles y OAuth ligado al navegador

## Contexto

Auditoría de seguridad de `veltylabs/iam` (2026-09-02). Este repo es el motor
de identidad de todo el ecosistema; `veltylabs/iam` lo monta como servicio SSO
central. Los hallazgos de abajo son de este repo, no del consumidor.

Doctrina obligatoria: [CONSTRUCTION_HARNESS.md](https://github.com/tinywasm/app-releases/blob/main/docs/CONSTRUCTION_HARNESS.md).
Los principios que gobiernan este plan:

- **8 · Cerrado por defecto.** *"A resource left reachable because nobody said
  otherwise is a silent failure."* La estrategia de sesión **por defecto** es
  hoy la insegura — eso es exactamente lo que este principio prohíbe.
- **6 · Nunca fallo silencioso.**
- **9 · Piezas lego.** La aleatoriedad la posee `tinywasm/crypto`; acá se
  consume, no se reimplementa.

## Compuertas (versiones ya publicadas antes de empezar)

| Dependencia | Símbolo que este plan usa | Para qué |
|---|---|---|
| `github.com/tinywasm/crypto` | `rand.Secret()`, `rand.SecretN(n)`, `rand.ErrNoCSPRNG` | Etapas 1 y 2 |
| `github.com/tinywasm/router` | `router.QueryParam(path, key)` | Etapa 5 |

`go get` a la última versión publicada de ambas antes de escribir código. Si
alguno de esos símbolos no existe todavía, **detenete y reportalo** — no lo
recrees acá (doctrina §"Lego pieces": *a consumer never re-creates a missing
symbol locally*).

---

## Hallazgo A-1 (Crítico) · El id de sesión es un timestamp

`session/cookie/cookie.go` es la estrategia que `authority.New` instala **por
defecto**:

```go
m.strategy = cookie.New(m, cfg.CookieName, cfg.TokenTTL, cfg.TrustProxy)
```

Su `Issue` guarda `sess.Id` como valor del cookie, y `authority.CreateSession`
lo genera con `m.ids.NewID()` — `tinywasm/unixid`, que devuelve el timestamp
unix en nanosegundos más un correlativo:

```
1788392853935184556
1788392853935211536
1788392853935214064
```

En wasm es peor: `tinywasm/time` implementa `Now()` como
`Date.getTime() * 1000000`, o sea **milisegundos rellenados con seis ceros**,
y en un Cloudflare Worker `Date.now()` está congelado durante la ejecución de
un request. El valor del cookie de sesión queda con la forma
`<milisegundos>00000<correlativo>`: enumerable.

Cualquier consumidor que use la configuración por defecto tiene **bypass total
de autenticación**. `veltylabs/iam` se salva sólo porque llama
`SetStrategy(sessionjwt.New(...))` — la excepción, no la regla.

## Hallazgo A-2 (Alto) · El `state` de OAuth es un timestamp

`authority/ports.go`:

```go
func (m *Module) CreateState(provider string) (string, error) {
	state := m.ids.NewID()      // <- mismo timestamp predecible
	...
}
```

El `state` es el token anti-CSRF del intercambio OAuth2. Predecible = ausente.

## Hallazgo A-3 (Alto) · El `state` no está ligado al navegador

`consumeState` valida contra una fila global de la tabla `oauth_state`: no hay
nada que ate ese `state` al navegador que inició el login. Un atacante inicia
`/oauth/google`, obtiene su `code`, y fuerza al navegador de la víctima a
visitar el callback → **la víctima queda con la sesión del atacante**
(login-CSRF), y a partir de ahí todo lo que haga queda en la cuenta del
atacante.

## Hallazgo A-4 (Alto) · Vinculación de cuentas por email sin verificar

`oauth2/oauth.go`, en el callback:

```go
} else if existing, err := a.store.UserByEmail(info.Email); err == nil {
	u = existing
	_ = a.store.UpsertIdentity(u.Id, providerName, info.ID, info.Email)
}
```

Se enlaza una identidad nueva a una cuenta existente **sólo por coincidencia
de email**, y `oauth2/provider/google/google.go` ni siquiera lee el campo
`verified_email` que devuelve `googleapis.com/oauth2/v2/userinfo`. Un
proveedor que permita registrar un email ajeno sin verificarlo se lleva la
cuenta.

## Hallazgo A-5 (Medio) · Fuga de información en el callback

```go
token, err := prov.ExchangeCode(code)
if err != nil {
	ctx.WriteStatus(401)
	ctx.Write([]byte(err.Error()))   // <- error del proveedor al navegador
	return
}
```

Tres sitios así en el callback (`ExchangeCode`, `GetUserInfo`,
`ConsumeState`). El propio repo ya tiene la doctrina correcta escrita en
`session/jwt/jwt.go`: *"errInvalidToken stays deliberately vague: telling a
caller WHY a token failed tells an attacker where they stand."* El callback la
contradice.

## Hallazgo A-6 (Medio) · `queryParam` local roto

`oauth2/oauth.go` tiene su propio parser de query string que exige
`len(kv) == 2` y no percent-decodifica. Consecuencia: un `redirect_uri`
correctamente codificado o un `state` con `=` **se pierden en silencio** — el
validador no rechaza, no ve. Se reemplaza por `router.QueryParam`.

## Hallazgo A-7 (Medio) · `sessionCache` sin cota

`authority/sessions.go`: `sessionCache.set` hace `append` sin límite.
`authority/cache_users.go` sí tiene `maxCacheUsers = 1000` con desalojo FIFO.
El de sesiones no: en un isolate de larga vida crece hasta agotar memoria.

## Hallazgo A-8 (Bajo) · Eventos de seguridad declarados y nunca emitidos

`user.go` declara `EventOAuthReplay`, `EventOAuthExpiredState` y
`EventOAuthCrossProvider` con comentarios que dicen que `consumeState` los
emite. `consumeState` no llama a `Notify` nunca. Un evento declarado que no se
emite es peor que no declararlo: hace creer que hay monitoreo donde no hay.

---

## Etapa 1 · Credenciales impredecibles (A-1, A-2)

### 1.1 · `CreateSession` deja de usar `ids`

`authority/sessions.go`. El id de sesión **es una credencial portadora**: quien
lo tiene, es el usuario. No puede salir del mismo generador que produce claves
primarias legibles.

```go
// sessionIDBytes: 32 bytes = 256 bits de entropía para el id de sesión. Un id
// de sesión NO es una clave primaria más: es la credencial que viaja en el
// cookie, así que se genera con el CSPRNG y no con el generador de ids
// correlativos del módulo — ese produce timestamps enumerables.
const sessionIDBytes = 32
```

`CreateSession` pasa a:

```go
id, err := rand.SecretN(sessionIDBytes)
if err != nil {
	return auth.Session{}, err
}
```

(import `"github.com/tinywasm/crypto/rand"`). **Propagá el error** — nunca
degrades a `ids.NewID()` como respaldo: un respaldo silencioso a una fuente
débil es exactamente el fallo que este plan cierra.

`m.ids` sigue usándose para `User.Id`, `Identity.Id` y `LANIP.Id`, que no son
credenciales. No los toques.

### 1.2 · `CreateState` deja de usar `ids`

`authority/ports.go`:

```go
// oauthStateBytes: 32 bytes. El state es el token anti-CSRF del intercambio
// OAuth2 — su único trabajo es ser impredecible.
const oauthStateBytes = 32
```

```go
state, err := rand.SecretN(oauthStateBytes)
if err != nil {
	return "", err
}
```

### 1.3 · Prueba de que no se puede volver atrás

En `tests/`, un test que falle si alguien reintroduce `ids.NewID()` en
cualquiera de los dos caminos:

```
TestSessionIDIsNotDerivedFromTime
TestOAuthStateIsNotDerivedFromTime
```

Cada uno crea 200 sesiones (o states) seguidas y afirma que:
- ningún valor es prefijo de otro,
- ningún par consecutivo difiere en menos de 16 bytes (comparación byte a
  byte sobre un slice; **no uses `map`**),
- ningún valor es sólo dígitos decimales (un timestamp de unixid lo es).

Esa última condición es la que ata el test al defecto real.

## Etapa 2 · `state` ligado al navegador (A-3)

El `state` deja de ser suficiente por sí solo: se acompaña de un **nonce en
cookie** que el navegador tiene que devolver.

### 2.1 · Columna nueva

`models.go`, `OAuthStateModel`, campo nuevo:

```go
{Name: "nonce_hash", Type: model.Text()},
```

Se guarda el **hash** del nonce, no el nonce: la tabla `oauth_state` es del
mismo nivel de confianza que cualquier otra fila de la base, y un volcado de
esa tabla no debe entregar el segundo factor. Usá
`hmac.HMACSHA256([]byte(state), []byte(nonce))` y guardá su `base64.URLEncode`
— el `state` mismo hace de sal, así que dos logins nunca comparten hash.

Regenerá el ORM con `ormc` si el repo lo usa (`//go:generate ormc` en
`models.go`).

### 2.2 · Contrato

`user.go`, en la interfaz `StateStore`, las firmas cambian:

```go
// CreateState devuelve el state (viaja en la URL del proveedor) y el nonce
// (viaja en una cookie del navegador). Los dos hacen falta para consumirlo:
// el state solo prueba que ALGUIEN inició un login, el nonce prueba que fue
// ESTE navegador. Sin el segundo, un atacante inicia el login, se queda con
// su propio code y empuja a la víctima al callback — la víctima termina con
// la sesión del atacante.
CreateState(provider string) (state, nonce string, err error)

// ConsumeState valida state+nonce y borra la fila. Single-use.
ConsumeState(state, nonce, provider string) error
```

### 2.3 · Cookie del nonce

`oauth2/oauth.go`. Constantes nuevas junto a `oauthRedirectCookie`:

```go
// oauthNonceCookie lleva el nonce del state desde /oauth/<provider> hasta su
// callback. SameSite=Lax como el cookie de redirect: el callback llega como
// navegación top-level desde el sitio del proveedor, y Strict la descartaría.
const oauthNonceCookie = "oauth_nonce"

// oauthCookieMaxAge: 300 s. Un intercambio OAuth que tarda más de cinco
// minutos ya no es un usuario, es un replay.
const oauthCookieMaxAge = 300
```

En el handler de `/oauth/<provider>`: tras `CreateState`, además del cookie de
redirect, escribí

```go
ctx.SetCookie(router.Cookie{
	Name: oauthNonceCookie, Value: nonce, HttpOnly: true, Secure: true,
	SameSite: router.SameSiteLax, MaxAge: oauthCookieMaxAge, Path: "/",
})
```

En el callback: leé el cookie, pasalo a `ConsumeState(state, nonce, provider)`
y **borralo siempre** (`MaxAge: -1`), tanto en el camino feliz como en el de
error — un nonce que sobrevive es un nonce reutilizable. Si el cookie no está,
`ConsumeState` recibe `""` y debe fallar.

### 2.4 · `consumeState`

`authority/ports.go`. Orden obligatorio, y este orden es el punto:

1. Buscar la fila por `state`. Si no hay → `Notify(EventOAuthReplay)` y
   `ErrInvalidOAuthState`.
2. **Borrar la fila.** Antes de cualquier otra validación: single-use es
   single-use aunque el intento sea inválido; si el borrado va después de una
   validación que falla, el `state` sigue vivo para el siguiente intento.
3. Comparar `provider`. Distinto → `Notify(EventOAuthCrossProvider)` y error.
4. Comparar el nonce en **tiempo constante**:
   `hmac.HMACEqual([]byte(stored.NonceHash), []byte(computed))`. **Nunca `==`.**
   Distinto → `Notify(EventOAuthReplay)` y error.
5. Comparar `ExpiresAt`. Vencido → `Notify(EventOAuthExpiredState)` y error.

Eso cierra también A-8: los tres eventos declarados pasan a emitirse.

Todos los caminos devuelven **el mismo** `auth.ErrInvalidOAuthState` — el
evento es para el operador, el error para el atacante, y el atacante no
aprende cuál de las cinco condiciones falló.

## Etapa 3 · Email verificado (A-4)

### 3.1 · El proveedor reporta la verificación

`user.go`, en `OAuthUserInfo`, campo nuevo:

```go
// EmailVerified: el proveedor afirma haber verificado que este email
// pertenece a quien inició sesión. El valor por defecto (false) es el
// seguro: un proveedor que no lo reporta NO habilita la vinculación por
// email.
EmailVerified bool
```

`oauth2/provider/google/google.go`: `googleData` gana

```go
VerifiedEmail bool
```

y `DecodeFields` lee `r.Bool("verified_email")` (ése es el nombre exacto del
campo en `https://www.googleapis.com/oauth2/v2/userinfo`). `GetUserInfo` lo
propaga a `OAuthUserInfo.EmailVerified`.

Hacé lo mismo en `oauth2/provider/microsoft/microsoft.go`: si esa API no
expone un campo de verificación, dejá `EmailVerified` en `false` y **agregá un
comentario diciendo exactamente eso** — el default cerrado es la respuesta
correcta, no un olvido.

`oauth2/provider/google/mock` debe exponer el campo para que los tests puedan
simular ambos casos.

### 3.2 · El callback exige verificación para vincular

`oauth2/oauth.go`, en la rama de vinculación por email:

```go
} else if info.EmailVerified {
	if existing, err := a.store.UserByEmail(info.Email); err == nil {
		u = existing
		_ = a.store.UpsertIdentity(u.Id, providerName, info.ID, info.Email)
	} else {
		// crear usuario nuevo
	}
} else {
	// email no verificado: NUNCA se enlaza a una cuenta existente.
}
```

Cuando el email **no** está verificado y **ya existe** un usuario con ese
email, el login se rechaza: 401 con el mismo cuerpo genérico de la Etapa 4 y
`Notify(auth.SecurityEvent{Type: auth.EventUnauthorizedAccess, Provider: providerName})`.
Crear un segundo usuario con el mismo email tampoco sirve: la columna `email`
de `UserModel` es `Unique: true` y el `Create` fallaría igual, pero con un
error de base de datos en vez de una decisión de seguridad explícita.

## Etapa 4 · El callback deja de filtrar errores (A-5)

`oauth2/oauth.go`. Constante nueva:

```go
// bodyOAuthFailed es lo ÚNICO que el callback devuelve ante cualquier fallo.
// Distinguir "state inválido" de "el proveedor rechazó el code" le dice al
// atacante en qué paso está. Ver la misma doctrina en session/jwt/jwt.go
// (errInvalidToken).
const bodyOAuthFailed = "authentication failed"
```

Los cuatro `ctx.Write([]byte(err.Error()))` del callback pasan a
`ctx.Write([]byte(bodyOAuthFailed))`. Criterio verificable:
`grep -rn "err.Error()" oauth2/` → vacío.

Hacé lo mismo en `local/local.go`, que escribe `err.Error()` en dos sitios de
`/local/select`. Ese paquete es sólo de desarrollo, pero no tiene build tag
que lo impida compilar en producción, así que se endurece igual.

## Etapa 5 · `router.QueryParam` (A-6)

`oauth2/oauth.go`: **borrá** la función `queryParam` local completa y usá
`router.QueryParam(ctx.Path(), "state")`, `"code"`, `"redirect_uri"`. La firma
es la misma (`(string, bool)`), así que los call sites no cambian.

Criterio verificable: `grep -rn "func queryParam" .` → vacío.

## Etapa 6 · Cota del caché de sesiones (A-7)

`authority/sessions.go`:

```go
// maxCacheSessions acota el caché de sesiones igual que maxCacheUsers acota
// el de usuarios: un isolate de larga vida no puede crecer sin techo. El
// desalojo FIFO sólo cuesta una lectura de base en el próximo GetSession —
// el caché es de lectura-a-través, no la fuente de verdad.
const maxCacheSessions = 1000
```

En `sessionCache.set`, antes del `append`, replicá el desalojo FIFO de
`cache_users.go`:

```go
if len(c.items) >= maxCacheSessions {
	c.items = c.items[1:]
}
```

## Etapa 7 · Tests

Todos bajo `tests/`, consumiendo los paquetes reales. Fronteras externas con
fakes en memoria: `orm.New(mem.New())`, ya usado por `tests/helper_test.go`.

### Mocks a crear o extender

| Mock | Dónde | Para qué |
|---|---|---|
| `googlemock.MockProvider` | `oauth2/provider/google/mock` (existe) | Agregarle el campo `EmailVerified` configurable, para simular proveedor honesto y proveedor que no verifica. |
| `failingRand` | `tests/` (nuevo) | No se puede inyectar `rand`; en su lugar, el test de fallo del CSPRNG verifica que `CreateSession` **propaga** el error comparando contra `rand.ErrNoCSPRNG` cuando el entorno no lo provee. Si eso no es alcanzable en `!wasm`, omitilo y dejá el caso cubierto sólo por el test de entropía. |
| `mock.Router` / `mock.Context` | `github.com/tinywasm/router/mock` (existe) | Manejar el flujo OAuth completo sin red, como ya hace `tests/oauth_routes_test.go`. |

### Tests obligatorios

| Test | Archivo | Fija |
|---|---|---|
| `TestSessionIDIsNotDerivedFromTime` | `tests/session_entropy_test.go` | A-1 |
| `TestOAuthStateIsNotDerivedFromTime` | `tests/session_entropy_test.go` | A-2 |
| `TestSessionIDIsNotGuessableFromNeighbour` | `tests/session_entropy_test.go` | A-1: dos sesiones creadas en el mismo milisegundo no comparten prefijo |
| `TestOAuthCallbackRequiresNonceCookie` | `tests/oauth_state_test.go` | A-3: callback sin cookie `oauth_nonce` → 401, no se emite sesión |
| `TestOAuthCallbackRejectsForeignNonce` | `tests/oauth_state_test.go` | A-3: nonce de OTRO login → 401 |
| `TestOAuthStateIsSingleUse` | `tests/oauth_state_test.go` | El segundo consumo del mismo state+nonce → 401 |
| `TestOAuthStateConsumedEvenOnProviderMismatch` | `tests/oauth_state_test.go` | La fila se borra antes de validar: un state con provider equivocado no queda vivo |
| `TestOAuthStateEmitsReplayEvent` | `tests/oauth_state_test.go` | A-8: `EventOAuthReplay` se publica |
| `TestOAuthStateEmitsExpiredEvent` | `tests/oauth_state_test.go` | A-8 |
| `TestOAuthStateEmitsCrossProviderEvent` | `tests/oauth_state_test.go` | A-8 |
| `TestUnverifiedEmailDoesNotLinkExistingAccount` | `tests/oauth_linking_test.go` | A-4: usuario preexistente + proveedor con `EmailVerified:false` → 401 y la identidad NO se enlaza |
| `TestVerifiedEmailLinksExistingAccount` | `tests/oauth_linking_test.go` | A-4: el camino feliz sigue funcionando |
| `TestCallbackNeverLeaksProviderError` | `tests/oauth_hardening_test.go` | A-5: el body es exactamente `authentication failed` en los cuatro caminos de error |
| `TestOAuthReadsEncodedRedirectURI` | `tests/oauth_redirect_test.go` (extender) | A-6: `?redirect_uri=https%3A%2F%2Fx.velty.cl%2Fp` llega decodificado |
| `TestOAuthReadsStateWithPadding` | `tests/oauth_redirect_test.go` | A-6: un state con `=` ya no se pierde |
| `TestSessionCacheIsBounded` | `tests/session_cache_test.go` | A-7: crear `maxCacheSessions + 50` sesiones deja el caché en `maxCacheSessions` y la sesión más nueva sigue resolviendo |

### Test consumer-shaped obligatorio

Regla de oro del harness: *an API is not published until a consumer-shaped
test, inside the library itself, proves it*. En `tests/sso_flow_test.go`:

```
TestSSOLoginFlow_EndToEndWithJWTStrategy
```

Debe recorrer el stack real que monta `veltylabs/iam`: `authority.New` +
`oauth2.New` con el mock de Google + `sessionjwt.New(...).WithDomain(".velty.cl")`
+ `SetStrategy`, y llevar un `mock.Context` desde `/oauth/google` hasta el
callback, verificando que sale una cookie de sesión válida y que
`strategy.Identify` la resuelve al usuario correcto. Si ese test es incómodo
de escribir, la API es incómoda de usar y encontraste el defecto antes de
publicarlo.

Y su contraparte, en el mismo archivo:

```
TestDefaultStrategyIssuesAnUnguessableCookie
```

`authority.New` **sin** `SetStrategy` (la configuración por defecto, la que
tenía A-1) debe emitir un valor de cookie que no sea sólo dígitos y que no
comparta prefijo con el de otra sesión creada en el mismo milisegundo.

## Restricciones de código (leer antes de escribir)

| Regla | Detalle |
|---|---|
| **Sin mapas** | Prohibido `map[K]V` en código de librería y en tests. Slices + búsqueda lineal. TinyGo compila mapas mal e infla el binario. |
| **Sin stdlib pesada** | Nada de `fmt`, `errors`, `strconv`, `strings`, `log`, `os`, `net/url`, `encoding/json`. Usa `github.com/tinywasm/fmt` y `github.com/tinywasm/json`. |
| **`context` de tinywasm** | `github.com/tinywasm/context`, no el de la stdlib. |
| **`error` sí, `errors` no** | Devolver `error` está bien; construirlo con `errors.New` no. Usa `fmt.Err(...)`. |
| **Sin `reflect`** | En ninguna forma, ni transitiva. |
| **Sin literales repetidos** | Todo string repetido (nombre de cookie, mensaje, nombre de campo JSON) es una constante nombrada. |
| **Sin `internal/`** | No crees carpetas `internal/`. |
| **Nunca compares MACs con `==`** | `hmac.HMACEqual` siempre. |
| **Nunca degrades a una fuente débil** | Si `rand` falla, se propaga el error. Prohibido cualquier respaldo a `ids.NewID()` o a `time.Now()`. |
| **`tests/` compila con Go estándar** | No está sujeto a las reglas de TinyGo. No le "arregles" los imports. |

Idioma: **código e identificadores en inglés**; **comentarios de prosa y
documentación en español**.

## Etapa 8 · Documentación

- `docs/ARCHITECTURE.md`: sección **"Credenciales portadoras"** — qué valor
  del sistema es una credencial (id de sesión, `state`, nonce) y por qué esos
  salen del CSPRNG y no del generador de ids. Tabla explícita: `User.Id`,
  `Identity.Id`, `LANIP.Id` → `ids`; `Session.Id`, `OAuthState.State`, nonce →
  `rand`.
- `docs/ARCHITECTURE.md`: sección **"El intercambio OAuth"** con el diagrama
  del flujo state+nonce y por qué el `state` solo no alcanza.
- `README.md`: si el ejemplo de uso muestra `authority.New` sin
  `SetStrategy`, aclarar que la estrategia por defecto ya es segura tras este
  cambio (antes no lo era).
- **BREAKING CHANGE**, documentado arriba de todo en el README y en el cuerpo
  del PR: `StateStore.CreateState` y `StateStore.ConsumeState` cambian de
  firma. Listá los consumidores conocidos que hay que actualizar:
  `oauth2/oauth.go` (en este repo) y cualquier implementación externa de
  `auth.StateStore`.

## Criterios de aceptación

1. `go vet ./...` y `go test ./...` verdes.
2. `GOOS=js GOARCH=wasm go build ./...` compila.
3. `grep -rn "ids.NewID()" authority/sessions.go authority/ports.go` → sólo
   aparece para ids que **no** son credenciales; ninguna ocurrencia en
   `CreateSession` ni en `CreateState`.
4. `grep -rn "func queryParam" .` → vacío.
5. `grep -rn "err.Error()" oauth2/ local/` → vacío.
6. `grep -rn "map\[" authority/ oauth2/ session/ local/` → vacío.
7. `OAuthUserInfo.EmailVerified` existe y `google.GetUserInfo` lo puebla desde
   `verified_email`.
8. `maxCacheSessions` existe y `sessionCache.set` desaloja.
9. Los 16 tests de la tabla, más los dos consumer-shaped, existen y pasan.
10. El PR describe el breaking change de `StateStore` en su cuerpo.

## Etapas

| # | Archivos | Entrega |
|---|---|---|
| 1 | `authority/sessions.go`, `authority/ports.go` | Credenciales desde `rand` (A-1, A-2) |
| 2 | `models.go`, `models_orm.go`, `user.go`, `oauth2/oauth.go`, `authority/ports.go` | `state` + nonce ligado al navegador (A-3, A-8) |
| 3 | `user.go`, `oauth2/provider/*`, `oauth2/oauth.go` | Email verificado (A-4) |
| 4 | `oauth2/oauth.go`, `local/local.go` | Errores opacos (A-5) |
| 5 | `oauth2/oauth.go` | `router.QueryParam` (A-6) |
| 6 | `authority/sessions.go` | Cota del caché (A-7) |
| 7 | `tests/*`, `oauth2/provider/google/mock` | Tests y mocks |
| 8 | `docs/ARCHITECTURE.md`, `README.md` | Credenciales portadoras, flujo OAuth, breaking change |
