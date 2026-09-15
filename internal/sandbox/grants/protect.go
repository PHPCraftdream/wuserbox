// Keeping a sandbox out of what it must never change: pinning the files that
// decide what it is allowed, taking the sensitive names first so it cannot
// create them itself, and refusing the credentials in the profile root
// whatever a directory above them allows.

package grants

import (
	"fmt"
	"os"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/base/lock"
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
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

// ReserveSensitiveNames takes the sensitive entries of the profile root that
// do not exist yet, as empty placeholders under locked permissions, so a
// sandbox allowed to create files there cannot get to those names first.
//
// A name is taken as whatever it is meant to be. Leaving an empty file where
// a tool expects a directory would break that tool everywhere, sandbox or not,
// which is a worse outcome than the one being prevented.
//
// It returns the names that had to be left alone because an empty one would
// hide a startup file the shell reads today, so the caller can say so out
// loud. Reserving is only needed when the profile root was handed over on
// purpose.
func ReserveSensitiveNames() ([]string, error) {
	for _, entry := range preset.Missing() {
		if err := reserve(entry); err != nil {
			return nil, err
		}
	}
	return preset.Shadowable(), nil
}

func reserve(entry preset.Entry) error {
	if entry.IsDirectory {
		if err := os.Mkdir(entry.Path, 0o700); err != nil {
			if os.IsExist(err) {
				return nil
			}
			return fmt.Errorf("reserving the directory %s: %w", entry.Path, err)
		}
		return acl.Protect(entry.Path)
	}
	file, err := os.OpenFile(entry.Path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		if os.IsExist(err) {
			return nil
		}
		return fmt.Errorf("reserving %s: %w", entry.Path, err)
	}
	file.Close()
	return acl.Protect(entry.Path)
}

// RefuseHomeFiles blocks the sandbox from changing the files already sitting
// in the profile root. It is only needed when the profile root was handed over
// on purpose, since that permission reaches those files as well.
//
// Files the sandbox was granted on purpose are left alone, together with the
// temporary files an agent writes beside them.
func RefuseHomeFiles(s *state.State) error {
	allowed := s.WritablePaths()
	for _, path := range preset.HomeFiles() {
		if isAllowed(path, allowed) {
			continue
		}
		if err := grant.Refuse(s.SID, path); err != nil {
			return err
		}
	}
	return nil
}

// isAllowed matches a granted file and the temporary names written beside it,
// such as the ".tmp.1234" companion of a config file being replaced.
func isAllowed(path string, allowed []string) bool {
	for _, a := range allowed {
		if strings.EqualFold(path, a) || strings.HasPrefix(strings.ToLower(path), strings.ToLower(a)+".") {
			return true
		}
	}
	return false
}
