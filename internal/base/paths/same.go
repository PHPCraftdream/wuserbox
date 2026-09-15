package paths

import (
	"path/filepath"
	"strings"
)

// Same reports whether two paths name the same place, allowing for slash
// direction, case and a trailing separator. It does not touch the disk.
func Same(a, b string) bool {
	return strings.EqualFold(clean(a), clean(b))
}

func clean(p string) string {
	return filepath.Clean(filepath.FromSlash(strings.TrimSpace(p)))
}
