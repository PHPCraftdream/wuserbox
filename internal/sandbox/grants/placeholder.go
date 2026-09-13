package grants

import (
	"fmt"
	"os"

	"github.com/PHPCraftdream/wuserbox/internal/policy/preset"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
)

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
