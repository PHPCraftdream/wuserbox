// Package sandbox ties identity, permissions and process launch together.
package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/win/group"
)

// Name maps a directory to its sandbox group name and returns the normalized
// directory it was derived from. The folder name keeps the group readable; the
// hash keeps it unique, since Windows group names are limited to 256 characters
// and paths are not.
func Name(dir string) (string, string, error) {
	// The same parser as every other path the commands take, so the project
	// directory can be written the same ways: a Windows path, the shell form,
	// a tilde or a variable all have to land on one sandbox.
	norm, err := paths.Resolve(dir)
	if err != nil {
		return "", "", err
	}
	digest := sha256.Sum256([]byte(strings.ToLower(norm)))
	name := fmt.Sprintf("%s%s-%s", group.Prefix, slug(filepath.Base(norm)), hex.EncodeToString(digest[:4]))
	return name, norm, nil
}

// ProfileDir is where a sandbox's own thin profile lives, beside its temp
// directory under the state directory. A pure function of the group name,
// the same as Temp's own construction in build, so removal can compute it
// even from a record that is missing or damaged.
func ProfileDir(name string) string {
	return filepath.Join(paths.StateDir(), "profile", name)
}

// UsedMarker is the empty file whose own two timestamps are the whole of
// what wuserbox knows about a sandbox's life: made when the marker was
// created, last used when it was last touched.
//
// It sits beside the temp directory rather than inside it, which is what
// keeps the sandbox from writing its own history: the sandbox is given the
// temp directory, never the directory holding it, so it can neither touch
// this file nor delete it.
func UsedMarker(name string) string {
	return filepath.Join(paths.StateDir(), "tmp", name+".used")
}

// Life is when a sandbox was made and when it was last used.
type Life struct {
	Made time.Time
	Used time.Time
}

// MarkUsed says a sandbox is being used now, creating its marker the first
// time -- which is what fixes the moment it was made.
//
// The record would have been the obvious place for both moments and is the
// wrong one: it is protected, published whole and written under the
// sandbox's lock, so stamping it on every run would put each run in line
// behind every other command touching that sandbox, to save two numbers
// the filesystem already keeps. This costs one timestamp write.
//
// Called before the program starts rather than after it ends, so a run
// killed outright, or one that takes a week, still counts as a use.
func MarkUsed(name string) error {
	path := UsedMarker(name)
	now := time.Now()
	err := os.Chtimes(path, now, now)
	if err == nil || !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	return file.Close()
}

// Times reads back what MarkUsed recorded. A sandbox made by a version
// that kept no marker has nothing to read, and that is not an error: it
// answers nil, and what shows it is expected to say so rather than put a
// moment there that was never observed.
func Times(name string) (*Life, error) {
	info, err := os.Stat(UsedMarker(name))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	life := &Life{Used: info.ModTime()}
	// Windows keeps a creation time and Go's portable interface does not
	// expose it, so it is read from the platform data os.Stat already
	// carries. Anything else there would leave Made empty rather than
	// guess from the modification time, which is the moment of the last
	// use and would read as a sandbox made and never used since.
	if data, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
		life.Made = time.Unix(0, data.CreationTime.Nanoseconds())
	}
	return life, nil
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
