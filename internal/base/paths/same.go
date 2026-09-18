package paths

import (
	"path/filepath"
	"strings"
)

// Same reports whether two paths name the same place, allowing for slash
// direction, case and a trailing separator. It does not touch the disk.
func Same(a, b string) bool {
	return asciiFold(clean(a)) == asciiFold(clean(b))
}

func asciiFold(path string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, path)
}

func clean(p string) string {
	return filepath.Clean(filepath.FromSlash(strings.TrimSpace(p)))
}
