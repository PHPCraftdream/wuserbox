package grants

import (
	"fmt"
	"os"

	"github.com/PHPCraftdream/wuserbox/internal/lock"
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"github.com/PHPCraftdream/wuserbox/internal/policy/preset"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
)

// ProtectSettings locks the files a sandbox must never change: wuserbox's own
// rules and bookkeeping, and the shell and credential files in the profile
// root. Their permissions are replaced with a fixed list and inheritance is
// switched off, so a permission granted on a parent cannot reach them later.
//
// The rules file is created first if it is missing. Otherwise a sandbox that
// may write in the profile root could create it, and the next ordinary run
// would read its own rules and hand itself more directories.
func ProtectSettings(s *state.State) error {
	if err := ensureRules(); err != nil {
		return err
	}
	// The copy kept behind the record says the same things about the same
	// directories, so it is protected on the same terms: a sandbox that could
	// rewrite it could describe itself as holding whatever it liked to the one
	// command that reads it.
	own := []string{config.Path(), state.Path(s.Group), state.PreviousPath(s.Group)}
	targets := append(own, preset.Sensitive()...)
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

// ensureRules writes an empty rules file when there is none. It is held while
// doing so, like every other change to that file, so it cannot overwrite a rule
// another command is writing at the same moment.
func ensureRules() error {
	if _, err := os.Stat(config.Path()); err == nil {
		return nil
	}
	return lock.Hold(lock.Rules, func() error {
		// Asked again inside the lock: whoever held it may have been creating
		// the very file this was about to create.
		if _, err := os.Stat(config.Path()); err == nil {
			return nil
		}
		rules, err := config.Load()
		if err != nil {
			return err
		}
		return rules.Save()
	})
}
