package paths

import (
	"os"
	"path/filepath"
)

// StateDir is where per-sandbox records and temporary directories live.
// Asking where something belongs does not create it: a command that only looks
// at a sandbox, or shows what another command would do, should leave the disk
// as it found it.
func StateDir() string {
	return filepath.Join(os.Getenv("LOCALAPPDATA"), "wuserbox")
}
