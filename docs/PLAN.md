---
PLAN: "perf!: authority.New deja de escanear la tabla de sesiones en cada arranque"
EXECUTOR: jules
REVIEWER: none
STATUS: review
SESSION: 11500381658416316312
PR: https://github.com/tinywasm/auth/pull/2
---

> This plan is dispatched via the CodeJob workflow. See skill: agents-workflow.

# PLAN — borrar `warmUp`

## El problema, en dos archivos

[`authority/module.go`](../authority/module.go) línea 52, dentro de `New`:

```go
	if err := m.cache.warmUp(db); err != nil {
		return nil, err
	}
```

[`authority/sessions.go`](../authority/sessions.go) línea 28:

```go
func (c *sessionCache) warmUp(db *orm.DB) error {
	qb := db.Query(&auth.Session{}).Where(auth.Session_.ExpiresAt).Gt(time.Now() / 1e9)
	sessions, err := auth.ReadAllSession(qb)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, s := range sessions {
		c.items = append(c.items, sessionItem{key: s.Id, val: *s})
	}
	return nil
}
```

Eso es `SELECT * FROM session WHERE expires_at > now`, **sin `LIMIT`**, en cada
construcción del módulo.

## Por qué borrarlo no cambia ningún comportamiento

`GetSession` (mismo archivo, línea 118) **ya tiene el camino perezoso completo**:

```go
func (m *Module) GetSession(id string) (auth.Session, error) {
	if s, ok := m.cache.get(id); ok {
		if s.ExpiresAt < time.Now()/1e9 {
			m.cache.delete(id)
			return auth.Session{}, auth.ErrSessionExpired
		}
		return s, nil
	}

	qb := m.db.Query(&auth.Session{}).Where(auth.Session_.Id).Eq(id)
	results, err := auth.ReadAllSession(qb)
	...
	m.cache.set(s.Id, s)
	return s, nil
}
```

Un fallo de caché consulta esa sesión por id y la cachea. El caché es de
lectura-a-través desde el primer día. `warmUp` no aporta corrección: solo
adelanta trabajo que el camino perezoso ya sabe hacer bajo demanda, y lo hace
para **todas** las sesiones en vez de para la que se pide.

## Por qué duele especialmente en un Worker

Este módulo corre dentro de un isolate de Cloudflare. Los isolates son
efímeros y hay muchos: cada uno construye su propio `Module` y calienta su
propio caché, que se descarta minutos después. El precalentamiento nunca llega a
amortizarse. Es un patrón de un proceso único y longevo aplicado donde no
corresponde.

Y crece sin techo: con 10.000 sesiones activas, **cada isolate frío arrastra
10.000 filas** antes de atender su primera petición.

## Cambios exactos

### 1. `authority/sessions.go`

Borra **entera** la función `warmUp` (líneas 28-41 en la versión actual).

Después de borrarla, revisa los imports del archivo: si `github.com/tinywasm/time`
o `github.com/tinywasm/orm` dejaron de usarse en él, quítalos. **No los quites
sin comprobar** — otras funciones del archivo los usan.

### 2. `authority/module.go`

Borra el bloque de la línea 52:

```go
	if err := m.cache.warmUp(db); err != nil {
		return nil, err
	}
```

`New` queda terminando en `return m, nil`.

### 3. El comentario de `New` — actualízalo, hoy miente

El doc comment dice:

```go
// New initializes the schema, warms the session cache, and wires the default
// session strategy (an opaque cookie over this Module's own session table).
```

`New` **ya no inicializa el esquema** (eso se movió a `Migrate` en v0.0.10) y
ahora tampoco calienta el caché. Reescríbelo para que describa lo que hace de
verdad, y deja constancia de por qué no calienta:

```go
// New conecta la estrategia de sesion por defecto (una cookie opaca sobre la
// tabla de sesiones de este Module) y devuelve el modulo listo para usar.
//
// A proposito NO consulta la base. El esquema lo aplica Migrate, una vez en
// tiempo de despliegue, y el cache de sesiones es de lectura-a-traves:
// GetSession resuelve un fallo consultando esa sesion por id. Precalentarlo
// costaria un escaneo completo de la tabla en cada arranque de isolate, que en
// un Worker se paga muchas veces y no se amortiza nunca.
```

### 4. Mantén la firma de `New`

Sigue devolviendo `(*Module, error)` aunque las rutas de error que quedan sean
solo las validaciones de `cfg`. **No cambies la firma**: rompería a todos los
llamadores sin ganancia alguna.

## Criterios de aceptación

- `grep -rn "warmUp" .` → **vacío** en todo el repo, incluidos tests y docs.
- `grep -rn "warms the session cache\|calienta" authority/module.go` → vacío.
- `go build ./...`, `go vet ./...` y `GOOS=js GOARCH=wasm go build ./...` limpios.
- `gotest ./...` en verde. Si algún test dependía de que el caché viniera
  precargado, **es exactamente el bug que este plan elimina**: arregla el test
  para que consulte vía `GetSession`, no restaures `warmUp`.

## Test nuevo — en `tests/`

```go
// TestNewDoesNotQueryOnConstruction prueba que construir el modulo no toca la
// base: es la regresion que este plan cierra, y en un Worker cada isolate la
// pagaba entera.
func TestNewDoesNotQueryOnConstruction(t *testing.T)
```

Constrúyelo sobre una conexión que **cuente** las consultas (un envoltorio sobre
la conexión en memoria que ya usan los tests, incrementando un contador en
`Query`). Después de `Migrate` + `authority.New`, el contador debe estar en
**0**. Después de un `GetSession` de un id inexistente, en **1**.

Si el envoltorio contador resulta difícil de encajar con el `newTestDB` que
comparten los tests, la alternativa aceptable es un test que llame a
`authority.New` sobre una base **sin la tabla `session`** (sin correr `Migrate`)
y compruebe que no devuelve error: hoy fallaría, porque `warmUp` consultaría una
tabla inexistente.

## Documentación

- `docs/ARCHITECTURE.md`: en la sección del caché de sesiones, describe el caché
  como **de lectura-a-través** y di por qué no se precalienta.
- `README.md`: si algún ejemplo menciona el precalentamiento, quítalo.
- **No** referencies este plan desde ningún documento permanente: `codejob`
  borra `docs/PLAN.md` al publicar y la referencia queda muerta.

## Lo que NO hay que hacer

- **No** toques `userCache` ([`authority/cache_users.go`](../authority/cache_users.go)).
  Ya es perezoso y está acotado por `maxCacheUsers`. Está bien como está.
- **No** cambies la firma de `New` ni la de `Migrate`.
- **No** añadas un flag de configuración para elegir si se calienta. La opción
  correcta es una sola, y añadir un interruptor solo deja el código muerto
  detrás de un `if`.
