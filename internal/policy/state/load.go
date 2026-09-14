package state

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"syscall"
	"time"
)

// Load reads the state for a group, returning nil when the sandbox has never
// been initialized.
func Load(group string) (*State, error) {
	data, err := readRecord(Path(group))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	adopt(&s)
	return &s, nil
}

// readRecord reads the file, waiting out the instant in which it is being
// replaced.
//
// The record is published by renaming a finished copy over it, and for the
// moment that takes, Windows refuses to open the file at all: the reader is
// told it is in use by another process. That is not a failure worth passing on
// to somebody asking what a sandbox may touch, and waiting is short and
// bounded, because a rename does not linger.
func readRecord(path string) ([]byte, error) {
	const attempts = 50
	for attempt := 0; ; attempt++ {
		data, err := os.ReadFile(path)
		if err == nil || attempt == attempts-1 || !beingReplaced(err) {
			return data, err
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// beingReplaced reports whether the file could not be opened because something
// else holds it for the moment it takes to publish a new one.
func beingReplaced(err error) bool {
	const sharingViolation = syscall.Errno(32)
	const lockViolation = syscall.Errno(33)
	return errors.Is(err, sharingViolation) || errors.Is(err, lockViolation) ||
		errors.Is(err, fs.ErrPermission)
}

// adopt brings a record written by an earlier build up to date.
//
// Its entries predate the mark that tells a request apart from an offer, and
// nothing in the file says which they were. They are taken as requests: a
// directory somebody narrowed by hand keeps its narrowing across the upgrade,
// and a directory the preset would have handed over anyway is unaffected,
// because the preset asks for the same access it already holds.
func adopt(s *State) {
	if s.Marked {
		return
	}
	for i := range s.Grants {
		s.Grants[i].Explicit = true
	}
	s.Marked = true
}
