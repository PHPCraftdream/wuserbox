package lock

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
)

// ForPath is the name to hold while one directory's permissions are changed.
//
// Permissions are changed by reading the whole access list, altering a copy and
// writing it back, so two sandboxes handed the same shared directory can each
// publish a list built before the other's change, and one of the two
// permissions disappears while its record still claims it. The sandbox locks do
// not help there: the directory belongs to neither of them.
//
// The name is derived from the path rather than being the path, because a lock
// is a file and a path is not a file name. Spelling and case are reduced first,
// so two commands naming the same directory differently still meet here.
func ForPath(path string) string {
	reduced := strings.ToLower(filepath.Clean(path))
	sum := sha256.Sum256([]byte(reduced))
	return "path-" + hex.EncodeToString(sum[:8])
}
