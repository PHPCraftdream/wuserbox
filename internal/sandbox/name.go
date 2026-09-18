// Package sandbox ties identity, permissions and process launch together.
package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/win/group"
	"github.com/PHPCraftdream/wuserbox/internal/win/pathid"
)

// Name maps a directory to its sandbox group name and returns the normalized
// directory it was derived from. The folder name keeps the group readable; the
// hash keeps it unique, since Windows group names are limited to 256 characters
// and paths are not.
func Name(dir string) (string, string, error) {
	// The same parser as every other path the commands take, so the project
	// directory can be written the same ways: a Windows path, the shell form,
	// a tilde or a variable all have to land on one sandbox.
	norm, err := paths.Resolve(dir)
	if err != nil {
		return "", "", err
	}
	// A Go Unicode fold is not the filesystem's case table: NTFS can keep
	// names such as K and the Kelvin sign apart. Existing paths therefore use
	// the spelling resolved by Windows itself; a missing path uses the
	// fail-safe ASCII-only fallback in pathid.Key.
	key, err := pathid.Key(norm)
	if err != nil {
		return "", "", err
	}
	digest := sha256.Sum256([]byte(key))
	name := fmt.Sprintf("%s%s-%s", group.Prefix, slug(filepath.Base(norm)), hex.EncodeToString(digest[:4]))
	return name, norm, nil
}

// ProfileDir is where a sandbox's own thin profile lives, beside its temp
// directory under the state directory. A pure function of the group name,
// the same as Temp's own construction in build, so removal can compute it
// even from a record that is missing or damaged.
func ProfileDir(name string) string {
	return filepath.Join(paths.StateDir(), "profile", name)
}

// slug keeps a folder name to characters that are safe in a group name.
func slug(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := strings.Trim(b.String(), "._-")
	if len(out) > 32 {
		out = out[:32]
	}
	if out == "" {
		out = "root"
	}
	return out
}
