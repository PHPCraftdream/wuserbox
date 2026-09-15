package state

import (
	"path/filepath"

	"github.com/PHPCraftdream/wuserbox/internal/paths"
)

// Path is the state file for a sandbox group.
func Path(group string) string {
	return filepath.Join(paths.StateDir(), group+".json")
}

// PreviousPath is the record as it stood before the last save.
//
// The record is the only list of what a sandbox was handed, and a sandbox
// outlives the file: entries naming it sit on directories all over the disk,
// and nothing else says where. If the file stops being readable, those
// directories can no longer be found by anything, so a copy of the last
// readable one is kept beside it. It is a second chance, not a second
// authority: it is read only when the record itself will not parse.
func PreviousPath(group string) string {
	return Path(group) + ".previous"
}
