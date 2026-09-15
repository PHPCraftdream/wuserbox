// Package facts is what is true about a sandbox on disk right now: when it
// was made, when it was last used, and what it takes up. None of it lives in
// the sandbox's record. The record is protected, published whole and written
// under the sandbox's own lock, so every run and every listing would queue
// behind every other command touching that sandbox to keep four numbers the
// filesystem is already willing to keep for free.
//
// This is its own package rather than more files under internal/sandbox
// because that directory is already at the seven entries the layout rules
// ask for, and because the three tasks that read this -- when, how big, and
// the listing that shows both -- want one place to look. Nothing here may
// import internal/sandbox: internal/sandbox builds a sandbox and marks it
// here, so the arrow only points this way.
package facts

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
)

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
// time -- which is what fixes the moment it was made. It costs one timestamp
// write.
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

// Times reads back what MarkUsed recorded. A sandbox made by a version that
// kept no marker has nothing to read, and that is not an error: it answers
// nil, and what shows it is expected to say so rather than put a moment
// there that was never observed.
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
	// carries. Anything else there would leave Made empty rather than guess
	// from the modification time, which is the moment of the last use and
	// would read as a sandbox made and never used since.
	if data, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
		life.Made = time.Unix(0, data.CreationTime.Nanoseconds())
	}
	return life, nil
}

// CopiedList is where the last list of what was copied into a sandbox's own
// profile is kept.
//
// Beside the temp directory, like the rest of what is recorded here, and
// deliberately not inside the profile it describes. That list is read back as
// a list of things to delete, and the sandbox may write its own profile: kept
// in there, it would be an instruction the sandbox could edit.
func CopiedList(name string) string {
	return filepath.Join(paths.StateDir(), "tmp", name+".copied")
}

// Copied reads that list. A sandbox whose profile has never been filled has
// none, which is not an error -- it means nothing was put there, so there is
// nothing to take away.
func Copied(name string) ([]string, error) {
	raw, err := os.ReadFile(CopiedList(name))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var entries []string
	for _, line := range strings.Split(string(raw), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			entries = append(entries, line)
		}
	}
	return entries, nil
}

// RecordCopied writes it back, one entry to a line.
func RecordCopied(name string, entries []string) error {
	path := CopiedList(name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strings.Join(entries, "\n")+"\n"), 0o644)
}
