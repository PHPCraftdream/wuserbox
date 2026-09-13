package state

import (
	"path/filepath"

	"wuserbox/internal/paths"
)

// Path is the state file for a sandbox group.
func Path(group string) string {
	return filepath.Join(paths.StateDir(), group+".json")
}
