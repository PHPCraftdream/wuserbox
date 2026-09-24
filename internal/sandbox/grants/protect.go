// Keeping a sandbox out of what it must never change: pinning the files that
// decide what it is allowed, taking the sensitive names first so it cannot
// create them itself, and refusing the credentials in the profile root
// whatever a directory above them allows.

package grants

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/base/lock"
	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/base/trace"
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
func ProtectSettings(s *state.State) (err error) {
	done := trace.Current().Phase("protect_settings")
	defer func() { done(err) }()
	if err := EnsureRules(); err != nil {
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
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		} else if err != nil {
			failures = append(failures, fmt.Errorf("checking %s: %w", path, err).Error())
			continue
		}
		protected, err := acl.IsProtected(path)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		if protected {
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

// EnsureRules writes a rules file when there is none, its profile section
// pre-filled from the agent preset, so the common agents' credentials,
// settings and instructions are copied into a sandbox without anybody
// composing that list by hand. It is held while doing so, like every other
// change to that file, so it cannot overwrite a rule another command is
// writing at the same moment.
func EnsureRules() error {
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
		rules.Profile = preset.Profile()
		return rules.Save()
	})
}

// RetireWholeDirectoryProfileRules replaces the whole agent directories an
// older default wrote into a rules file with the entries that default names
// now, and answers with what it took out so the caller can say so.
//
// A narrower default only reaches a machine that has never run wuserbox. The
// rules file is written once and kept, so everywhere it has run, the profile
// section still names whole state directories and a run still copies them --
// all of them, every time. Nothing else would ever have fixed that: no later
// version writes that file again.
//
// Only what that default produced is touched. Anything else in the section
// was put there by somebody on purpose and is left exactly as it is,
// including a directory they added themselves. This cannot tell a person who
// wants a whole tree copied from a default that wanted it on their behalf,
// so it removes only what it can recognize as its own doing.
//
// It happens once and never again. Somebody who deliberately puts a whole
// directory back into that section means it, and a migration that ran on
// every --init would take it out again every time: an edit that never sticks
// and never says why. The marker is written whether or not there was anything
// to take out, so a machine that never carried the old list is left alone
// from then on too.
func RetireWholeDirectoryProfileRules() ([]string, error) {
	var retired []string
	err := lock.Hold(lock.Rules, func() (err error) {
		done := alreadyRetired()
		if _, statErr := os.Stat(done); statErr == nil {
			return nil
		}
		rules, err := config.Load()
		if err != nil {
			return err
		}
		defer func() {
			// Only once the migration actually finished -- either by finding
			// nothing of its own to retire, or by saving the trimmed rules.
			// A migration that ran and changed nothing is as finished as one
			// that changed everything, and still writes the marker. But a
			// Save that failed leaves the rules file exactly as it was, and
			// writing the marker anyway would tell every later --init the
			// migration is done when the machine is still copying whole
			// agent directories into every sandbox on every run -- the
			// 72,320-file, 19,436 MB behavior this migration exists to end.
			if err != nil {
				return
			}
			if mkErr := os.MkdirAll(filepath.Dir(done), 0o755); mkErr == nil {
				_ = os.WriteFile(done, nil, 0o644)
			}
		}()
		old := make(map[string]bool)
		for _, entry := range preset.RetiredProfileEntries() {
			old[folded(entry)] = true
		}
		kept := make([]config.Entry, 0, len(rules.Profile))
		have := make(map[string]bool, len(rules.Profile))
		for _, entry := range rules.Profile {
			// Bare entries only. An entry carrying limits names the same
			// directory the old default named and means something the old
			// default could not say -- that shape did not exist when it was
			// written -- so it is somebody's own, and taking it out would be
			// the migration undoing a deliberate edit again.
			if entry.Bare() && old[folded(entry.Path)] {
				retired = append(retired, entry.Path)
				continue
			}
			kept = append(kept, entry)
			have[folded(entry.Path)] = true
		}
		if len(retired) == 0 {
			return nil
		}
		// What the narrow default would have written into a fresh file, minus
		// anything already named. Added rather than substituted wholesale, so
		// a section somebody has edited keeps its own shape.
		for _, entry := range preset.Profile() {
			if !have[folded(entry.Path)] {
				kept = append(kept, entry)
			}
		}
		rules.Profile = kept
		return rules.Save()
	})
	if err != nil {
		return nil, err
	}
	return retired, nil
}

// alreadyRetired is where it is written down that this has been done, beside
// the rest of the bookkeeping rather than inside the rules file: the rules
// file belongs to whoever is using the tool, and a field they did not ask for
// would be one more thing to explain in it.
func alreadyRetired() string {
	return filepath.Join(paths.StateDir(), "profile-rules-retired")
}

// folded is how two spellings of the same entry are compared: Windows does
// not care about case, and a rules file may be written with either separator.
func folded(entry string) string {
	return asciiFold(filepath.ToSlash(entry))
}

func asciiFold(path string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, path)
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
	allowed := s.WritableSpecs()
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
// such as the ".tmp.1234" companion of a config file being replaced. The dot
// comparison is only made against grants of the file kind: a directory whose
// name merely prefixes a home file with a dot -- a granted "notes" beside a
// "notes.txt" -- has nothing to do with that file's companions, and the file
// keeps its refusal.
func isAllowed(path string, allowed []grant.Spec) bool {
	folded := asciiFold(path)
	for _, a := range allowed {
		if folded == asciiFold(a.Path) {
			return true
		}
		if a.Kind == grant.File && strings.HasPrefix(folded, asciiFold(a.Path)+".") {
			return true
		}
	}
	return false
}
