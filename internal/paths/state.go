package paths

import (
	"os"
	"path/filepath"
)

// StateDir holds per-sandbox state files and temp directories.
func StateDir() string {
	dir := filepath.Join(os.Getenv("LOCALAPPDATA"), "wuserbox")
	os.MkdirAll(dir, 0o755)
	return dir
}
