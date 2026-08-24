package authority

import (
	"sync"

	"github.com/tinywasm/auth"
)

const maxCacheUsers = 1000

type userCacheItem struct {
	key string
	val *auth.User
}

type userCache struct {
	mu    sync.RWMutex
	items []userCacheItem
}

func newUserCache() *userCache {
	return &userCache{
		items: make([]userCacheItem, 0, maxCacheUsers),
	}
}

func (c *userCache) Get(id string) (*auth.User, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, item := range c.items {
		if item.key == id {
			return item.val, true
		}
	}
	return nil, false
}

func (c *userCache) Set(id string, u *auth.User) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i, item := range c.items {
		if item.key == id {
			c.items[i].val = u
			return
		}
	}

	if len(c.items) >= maxCacheUsers {
		// Evict oldest (FIFO)
		c.items = c.items[1:]
	}
	c.items = append(c.items, userCacheItem{key: id, val: u})
}

func (c *userCache) Delete(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i, item := range c.items {
		if item.key == id {
			c.items = append(c.items[:i], c.items[i+1:]...)
			return
		}
	}
}

func (c *userCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make([]userCacheItem, 0, maxCacheUsers)
}
