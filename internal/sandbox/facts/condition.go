package facts

import (
	"fmt"
	"os"

	"github.com/PHPCraftdream/wuserbox/internal/account"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
)

// Trouble is a way a sandbox can fail to be whole.
//
// The words live here, once, because two places need them and they must not
// drift apart: the run path, which meets one of these and has to decide what
// to do, and the listing, which meets one and has to say what it is. Two
// vocabularies for the same four states would leave somebody reading a
// listing unable to tell it was describing what the last run complained
// about.
type Trouble string

const (
	// Whole: nothing is wrong.
	Whole Trouble = ""
	// GroupGone: a record naming a group this machine no longer has. Every
	// permission it was given names that group, so they name nothing now.
	GroupGone Trouble = "its group is gone"
	// RecordUnreadable: the record exists and will not parse. What the
	// sandbox was given is written down there and nowhere else.
	RecordUnreadable Trouble = "its record cannot be read"
	// RecordMissing: the group is there and the record is not, so nothing
	// says what this sandbox was ever handed.
	RecordMissing Trouble = "its record is missing"
	// NoAccount: made before a sandbox had an account of its own. It still
	// runs, and a shell will not start in it.
	NoAccount Trouble = "it has no account of its own"
	// PasswordLost: the account is there and the sealed password that opens
	// it went with the record. Nothing can recover it; the account has to be
	// replaced.
	PasswordLost Trouble = "the password to its account went missing"
	// ProjectGone: the directory this sandbox belongs to is not there any
	// more, renamed or deleted. The sandbox is not broken, it is orphaned.
	ProjectGone Trouble = "the project directory it belongs to is gone"
)

// Fix is the command that puts this right, or "" where none does.
func (t Trouble) Fix(dir string) string {
	switch t {
	case ProjectGone:
		return fmt.Sprintf("wuserbox --rm --dir %s", dir)
	case Whole:
		return ""
	default:
		// Everything else is repaired the same way, which is the point of
		// init applying every permission afresh rather than trusting the
		// record: group, account, profile and entries are all rebuilt.
		return fmt.Sprintf("wuserbox --init --dir %s", dir)
	}
}

// Judge says what is wrong with a sandbox, from its group name, the project
// directory its group remembers, and the record as it was read -- nil where
// there is none, with readErr set where reading it failed.
//
// The order is what a reader would check in: there is no point reporting a
// missing account for a sandbox whose group is gone, because the account is
// named after the group.
func Judge(name, dir string, s *state.State, readErr error) Trouble {
	switch {
	case !resolves(name):
		return GroupGone
	case readErr != nil:
		return RecordUnreadable
	case s == nil:
		return RecordMissing
	case !resolves(account.NameFor(name)):
		return NoAccount
	case s.Secret == "":
		return PasswordLost
	case dir != "" && !isDirectory(dir):
		return ProjectGone
	}
	return Whole
}

func resolves(name string) bool {
	_, err := sid.Lookup(name)
	return err == nil
}

func isDirectory(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
