package lock

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/win/pathid"
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
// Aliases a string cannot see through -- a SUBST drive, a mapped drive, a
// junction -- are resolved before the name is derived: identity hands the tree
// layer one spelling per real directory, and this fold is the last mile, not
// the whole distance.
func ForPath(path string) string {
	reduced := strings.ToLower(filepath.Clean(path))
	sum := sha256.Sum256([]byte(reduced))
	return "path-" + hex.EncodeToString(sum[:8])
}

// identity returns the path whose lock a hold on root must be taken under:
// the spelling Windows itself resolves for an existing root, or the root's
// own cleaned spelling when nothing exists to ask. A SUBST drive, a mapped
// drive and a junction all reach the lock layer as different strings for one
// real tree, and two strings hashing to two lock files would let two
// commands read, decide and write one access list at once -- the loss
// ForPath exists to prevent, one floor up. So an existing root is asked of
// Windows through the same directory-entry resolution pathid applies
// wherever the project refuses to be fooled by an alias, and a root that
// exists but cannot be identified refuses the hold: falling back to its
// string would hand out exactly the independent lock the alias class makes
// dangerous. A missing root has no directory entry to identify and stands on
// its own spelling, as pathid.Key falls back for missing entries.
func identity(root string) (string, error) {
	cleaned := filepath.Clean(root)
	canonical, err := pathid.Canonical(cleaned)
	if err == nil {
		return canonical, nil
	}
	if _, statErr := os.Stat(cleaned); statErr == nil {
		return "", fmt.Errorf("identifying the existing root %s for its tree lock: %w", root, err)
	} else if !os.IsNotExist(statErr) {
		return "", fmt.Errorf("checking %s for its tree lock identity: %w", root, statErr)
	}
	return cleaned, nil
}
