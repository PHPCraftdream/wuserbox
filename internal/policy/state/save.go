package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
)

// Save writes the state file, creating the directory it belongs in. Asking
// where that directory is does not create it, so the making happens here,
// where something is actually written.
//
// The record is published whole: it is written beside its own path and renamed
// over it. Writing into the file itself empties it first, and a command reading
// the record at that moment got half a document and failed with "unexpected end
// of JSON input". Readers do not take the writer's lock, and should not have to.
func (s *State) Save() error {
	// Anything written now carries the mark, so it is never adopted again.
	s.Marked = true
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	final := Path(s.Group)
	if err := os.MkdirAll(filepath.Dir(final), 0o755); err != nil {
		return err
	}
	written, err := writeBeside(final, append(data, '\n'))
	if err != nil {
		return err
	}
	// Removing it matters only where the rename below never happens.
	defer func() { _ = os.Remove(written) }()

	// Protected before it is published, not after: the permissions travel with
	// the file through the rename, so there is no moment where the record is in
	// place and still open to the code the sandbox runs.
	if err := acl.Protect(written); err != nil {
		return err
	}
	return publish(written, final)
}

// writeBeside writes content to a new file in the directory that holds path,
// and returns its name.
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

// publish renames the finished copy over the record, waiting out a reader that
// holds the old one for the instant it takes to read it.
//
// Windows will not replace a file somebody has open, and the readers here are
// other wuserbox commands answering a question about the sandbox. Both sides
// wait a little rather than failing: reading is short, renaming is shorter, and
// the alternative is a command that fails because another was looking.
func publish(written, final string) error {
	const attempts = 50
	for attempt := 0; ; attempt++ {
		err := os.Rename(written, final)
		if err == nil || attempt == attempts-1 || !beingReplaced(err) {
			return err
		}
		time.Sleep(2 * time.Millisecond)
	}
}
