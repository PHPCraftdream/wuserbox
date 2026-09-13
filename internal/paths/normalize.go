// Package paths resolves the filesystem locations wuserbox works with.
package paths

import "path/filepath"

// Normalize returns an absolute, symlink-free, cleaned path. Sandbox identity
// is derived from it, so two spellings of one directory must collapse here.
func Normalize(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	return filepath.Clean(abs), nil
}
