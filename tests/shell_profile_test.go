package tests

import (
	"testing"

	"github.com/tinywasm/auth"
)

// platformdIdentity represents the read contract declared by platformd/platformd.go.
// Defined here to prevent the backend package from importing a UI package.
type platformdIdentity interface {
	UserName() string    // who is logged in
	UserAvatar() string  // URL of their picture; empty is normal
	UserRoles() []string // display names, not authorization codes
}

// Assert compile-time contract compatibility with platformdIdentity.
var _ platformdIdentity = auth.ShellProfile{}

func TestShellProfileRoundTrip(t *testing.T) {
	dto := auth.ProfileDTO{
		Id:        "user-123",
		Name:      "John Doe",
		Email:     "john@example.com",
		Avatar:    "https://example.com/avatar.png",
		Roles:     []string{"admin_code"},
		RoleNames: []string{"Administrator"},
	}

	shell := dto.Shell()

	if shell.UserName() != "John Doe" {
		t.Errorf("expected UserName 'John Doe', got '%s'", shell.UserName())
	}

	if shell.UserAvatar() != "https://example.com/avatar.png" {
		t.Errorf("expected UserAvatar 'https://example.com/avatar.png', got '%s'", shell.UserAvatar())
	}

	roles := shell.UserRoles()
	if len(roles) != 1 || roles[0] != "Administrator" {
		t.Errorf("expected UserRoles ['Administrator'], got %v", roles)
	}

	// Verify Roles (the codes) is left untouched
	if len(dto.Roles) != 1 || dto.Roles[0] != "admin_code" {
		t.Errorf("expected original Roles 'admin_code' to be untouched, got %v", dto.Roles)
	}
}
