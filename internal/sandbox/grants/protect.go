package grants

import (
	"fmt"
	"os"

	"wuserbox/internal/policy/config"
	"wuserbox/internal/policy/preset"
	"wuserbox/internal/policy/state"
	"wuserbox/internal/win/acl"
)

// ProtectSettings locks the files a sandbox must never change: wuserbox's own
// rules and bookkeeping, and the shell and credential files in the profile
// root. Their permissions are replaced with a fixed list and inheritance is
// switched off, so a permission granted on a parent cannot reach them later.
func ProtectSettings(s *state.State) error {
	targets := append([]string{config.Path(), state.Path(s.Group)}, preset.Sensitive()...)
	var failures []string
	for _, path := range targets {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		if err := acl.Protect(path); err != nil {
			failures = append(failures, err.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("could not protect settings: %v", failures)
	}
	return nil
}
