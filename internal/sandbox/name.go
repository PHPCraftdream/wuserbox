// Package sandbox ties identity, permissions and process launch together.
package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/paths"
	"github.com/PHPCraftdream/wuserbox/internal/win/group"
)

// Name maps a directory to its sandbox group name and returns the normalized
// directory it was derived from. The folder name keeps the group readable; the
// hash keeps it unique, since Windows group names are limited to 256 characters
// and paths are not.
func Name(dir string) (string, string, error) {
	norm, err := paths.Normalize(dir)
	if err != nil {
		return "", "", err
	}
	digest := sha256.Sum256([]byte(strings.ToLower(norm)))
	name := fmt.Sprintf("%s%s-%s", group.Prefix, slug(filepath.Base(norm)), hex.EncodeToString(digest[:4]))
	return name, norm, nil
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
