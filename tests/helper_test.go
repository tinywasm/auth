package tests

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/tinywasm/events"
	"github.com/tinywasm/model"
	"github.com/tinywasm/router"
	"github.com/tinywasm/auth"
)

type testIDGenerator struct {
	mu  sync.Mutex
	seq int64
}

func (g *testIDGenerator) NewID() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.seq++
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("id_%d_%s", g.seq, hex.EncodeToString(b))
}

var testIDs = &testIDGenerator{}

type mockPublisher struct {
	mu     sync.Mutex
	events []events.Event
}

func (p *mockPublisher) Publish(e events.Event) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, e)
}

func (p *mockPublisher) SecurityEvents() []auth.SecurityEvent {
	p.mu.Lock()
	defer p.mu.Unlock()
	var list []auth.SecurityEvent
	for _, e := range p.events {
		if e.Topic == auth.TopicSecurity {
			if se, ok := e.Payload.(*auth.SecurityEvent); ok {
				list = append(list, *se)
			}
		}
	}
	return list
}

type mockRoute struct {
	authenticated bool
	requiredRes   model.Resource
	requiredAct   model.Action
	acceptedArg   any
	handler       router.HandlerFunc
}

func (r *mockRoute) Authenticated() router.Route {
	r.authenticated = true
	return r
}

func (r *mockRoute) Requires(res model.Resource, action model.Action) router.Route {
	r.requiredRes = res
	r.requiredAct = action
	return r
}

func (r *mockRoute) Accepts(arg model.Fielder) router.Route {
	r.acceptedArg = arg
	return r
}

func (r *mockRoute) Public() router.Route {
	return r
}

type mockOpRegistry struct {
	ops map[string]*mockRoute
}

func (reg *mockOpRegistry) Op(name string, h router.HandlerFunc) router.Route {
	r := &mockRoute{handler: h}
	reg.ops[name] = r
	return r
}
