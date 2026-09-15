package facts

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
)

// Size is what a sandbox takes on disk and when that was found out.
//
// Taken is not decoration. Measuring is not free -- see Measure -- so what
// is shown is usually a number from some earlier moment, and a size printed
// without saying when it was taken is a number that quietly stops being
// true. Anything displaying this is expected to display Taken with it.
type Size struct {
	Bytes int64
	Files int
	// Partial says something under one of the directories could not be
	// read, so Bytes is a floor rather than the answer. Reporting the
	// smaller number silently would be the one failure mode worth avoiding
	// here: a sandbox that looks small because its biggest directory
	// refused to open.
	Partial bool
	Taken   time.Time
}

// SizeCache is where the last measurement is kept: beside the temp
// directory, like the used marker and for the same reason -- the sandbox is
// given the temp directory itself and nothing around it, so it cannot
// rewrite what is recorded about it.
func SizeCache(name string) string {
	return filepath.Join(paths.StateDir(), "tmp", name+".size")
}

// Measure walks dirs, adds up what is in them and writes the answer down.
//
// Measured before choosing to keep the answer rather than recompute it on
// demand, on this machine, with a warm cache: 25,023 files under the state
// directory took 2.4s, 45,091 files under a real agent profile took 2.7s,
// 13,287 files under the user's temp directory took 0.8s. Seconds, not
// milliseconds -- which settles it. A listing that walked every sandbox's
// trees before printing would take a visible pause per sandbox, every time,
// to produce a number that had not changed since the last look.
//
// A directory that is not there contributes nothing and is not an error: a
// sandbox that has never run has no temp directory, and one built before
// profiles existed has no profile.
func Measure(name string, dirs ...string) (*Size, error) {
	size := &Size{Taken: time.Now()}
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		walk := func(_ string, entry fs.DirEntry, err error) error {
			size.add(entry, err)
			return nil // nothing here stops the walk; see add
		}
		if err := filepath.WalkDir(dir, walk); err != nil {
			return nil, fmt.Errorf("measuring %s: %w", dir, err)
		}
	}
	if err := writeSize(name, size); err != nil {
		return nil, err
	}
	return size, nil
}

// add takes one entry the walk offered, whether or not it could be read.
//
// Nothing here stops the walk. Giving up at the first refusal would report
// the smallest number for exactly the sandbox worth looking at -- one whose
// biggest directory will not open -- so what cannot be read makes the answer
// a floor instead, which is what Partial says.
func (s *Size) add(entry fs.DirEntry, err error) {
	switch {
	case entry == nil:
		// The root itself. Not being there is a sandbox that has not run
		// yet, not one hiding anything, and is the ordinary case.
		if err != nil && !os.IsNotExist(err) {
			s.Partial = true
		}
	case err != nil:
		s.Partial = true
	case entry.IsDir():
	default:
		info, infoErr := entry.Info()
		if infoErr != nil {
			s.Partial = true
			return
		}
		s.Files++
		s.Bytes += info.Size()
	}
}

// Known reads the last measurement without walking anything. A sandbox
// never measured answers nil rather than zero, so what shows it can say "not
// measured" instead of "empty" -- two different things, and a sandbox
// holding gigabytes would otherwise be reported as holding none.
func Known(name string) (*Size, error) {
	path := SizeCache(name)
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	size := &Size{Taken: info.ModTime()}
	var partial string
	// A record that does not read back as all three fields is not a record.
	// Answering nil sends the caller down the same path as a sandbox never
	// measured, which is the truthful one: nothing is known about its size.
	if read, _ := fmt.Sscan(strings.TrimSpace(string(raw)), &size.Bytes, &size.Files, &partial); read != 3 {
		return nil, nil
	}
	size.Partial = partial == "partial"
	return size, nil
}

// writeSize publishes the measurement. Its own modification time is the
// moment it was taken, so nothing has to be written down twice.
func writeSize(name string, size *Size) error {
	path := SizeCache(name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	whole := "whole"
	if size.Partial {
		whole = "partial"
	}
	return os.WriteFile(path, fmt.Appendf(nil, "%d %d %s\n", size.Bytes, size.Files, whole), 0o644)
}
