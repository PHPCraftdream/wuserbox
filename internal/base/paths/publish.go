package paths

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Publish writes content to path so that anyone reading it sees either the old
// file or the new one.
//
// Writing into the file itself empties it first, and a reader arriving at that
// moment gets half a document. So the content is written beside the path and
// renamed over it. Whatever prepare is given runs on the finished copy before
// it is published: that is where permissions belong, so they travel with the
// file rather than being applied to a file already in place.
//
// ReadWhole is the other half of this and lives beside it: the two agree about
// the moment a rename takes, which on Windows neither side can simply ignore.
func Publish(path string, content []byte, prepare func(string) error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	written, err := writeBeside(path, content)
	if err != nil {
		return err
	}
	// Removing it matters only where the rename below never happens.
	defer func() { _ = os.Remove(written) }()

	if prepare != nil {
		if err := prepare(written); err != nil {
			return err
		}
	}
	return patiently(func() error { return os.Rename(written, path) })
}

// ReadWhole reads a file that something else may be publishing at this moment.
//
// Windows refuses to open a file for the instant a rename over it takes, and
// tells the reader it is in use. That is not a failure worth passing on, and
// the wait is short and bounded, because a rename does not linger.
func ReadWhole(path string) ([]byte, error) {
	var content []byte
	err := patiently(func() error {
		var err error
		content, err = os.ReadFile(path)
		return err
	})
	return content, err
}

// writeBeside writes content to a new file in the directory that holds path.
func writeBeside(path string, content []byte) (string, error) {
	file, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*")
	if err != nil {
		return "", err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return "", err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(file.Name())
		return "", err
	}
	return file.Name(), nil
}

// patiently repeats an attempt that failed only because the file was being
// published or read at that moment.
func patiently(attempt func() error) error {
	const attempts = 50
	for round := 0; ; round++ {
		err := attempt()
		if err == nil || round == attempts-1 || !inTheMiddleOfAPublication(err) {
			return err
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// inTheMiddleOfAPublication reports whether the file could not be reached
// because somebody else held it for the moment a publication takes.
func inTheMiddleOfAPublication(err error) bool {
	const sharingViolation = syscall.Errno(32)
	const lockViolation = syscall.Errno(33)
	return errors.Is(err, sharingViolation) || errors.Is(err, lockViolation) ||
		errors.Is(err, fs.ErrPermission)
}
