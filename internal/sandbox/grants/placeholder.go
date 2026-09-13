package grants

import (
	"fmt"
	"os"

	"github.com/PHPCraftdream/wuserbox/internal/policy/preset"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
)

// ReserveSensitiveFiles creates the sensitive files of the profile root that
// do not exist yet, as empty placeholders under locked permissions, so a
// sandbox allowed to create files there cannot get to those names first. A
// shell or tool reading an empty file of its own behaves as it did when the
// file was absent.
//
// It returns the names that had to be left alone because an empty one would
// hide a startup file the shell reads today, so the caller can say so out
// loud. Reserving is only needed when the profile root was handed over on
// purpose.
func ReserveSensitiveFiles() ([]string, error) {
	for _, path := range preset.Missing() {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			if os.IsExist(err) {
				continue
			}
			return nil, fmt.Errorf("reserving %s: %v", path, err)
		}
		file.Close()
		if err := acl.Protect(path); err != nil {
			return nil, err
		}
	}
	return preset.Shadowable(), nil
}
