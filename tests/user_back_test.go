//go:build !wasm

package tests

import (
	"testing"

	_ "modernc.org/sqlite"
)

func TestUserBackend(t *testing.T) {
	RunUserTests(t)
}
