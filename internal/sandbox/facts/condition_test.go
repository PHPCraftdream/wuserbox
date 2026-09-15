package facts

import (
	"errors"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
)

// A sandbox whose group is gone is judged on that and nothing else: the
// account is named after the group, so reporting a missing account for it
// would be reporting a consequence as if it were the cause.
func TestTheFirstThingWrongIsWhatIsReported(t *testing.T) {
	const gone = "wub-nothing-by-this-name-00000000"
	whole := &state.State{Group: gone, Secret: "sealed"}

	if wrong := Judge(gone, "", whole, nil); wrong != GroupGone {
		t.Errorf("a sandbox with no group was judged %q, want %q", wrong, GroupGone)
	}
	// Even with a record that will not read, and no record at all: the group
	// is checked first because everything else is named after it.
	if wrong := Judge(gone, "", nil, errors.New("unparseable")); wrong != GroupGone {
		t.Errorf("got %q, want %q", wrong, GroupGone)
	}
}

// Every state a sandbox can be in must name the command that puts it right,
// or the listing tells somebody they have a problem and leaves them there.
func TestEveryTroubleNamesTheCommandThatFixesIt(t *testing.T) {
	const dir = `C:\projects\app`
	for _, wrong := range []Trouble{
		GroupGone, RecordUnreadable, RecordMissing, NoAccount, PasswordLost, ProjectGone,
		SharesTheOldReadGroup,
	} {
		fix := wrong.Fix(dir)
		if fix == "" {
			t.Errorf("%q names no way out", wrong)
			continue
		}
		if !strings.Contains(fix, dir) {
			t.Errorf("the fix for %q does not say which project: %q", wrong, fix)
		}
		if !strings.HasPrefix(fix, "wuserbox ") {
			t.Errorf("the fix for %q is not a command: %q", wrong, fix)
		}
	}
	// An orphaned sandbox is removed, not rebuilt: rebuilding it would put
	// back permissions on a project that is not there any more.
	if fix := ProjectGone.Fix(dir); !strings.Contains(fix, "--rm") {
		t.Errorf("a sandbox whose project is gone is told to %q", fix)
	}
	if fix := Whole.Fix(dir); fix != "" {
		t.Errorf("a sandbox with nothing wrong was told to run %q", fix)
	}
}

// Every Trouble reads as a sentence about the sandbox, because both places
// that use these put a name in front of one: "sandbox wub-x: <trouble>".
func TestEveryTroubleReadsAsSomethingSaidAboutASandbox(t *testing.T) {
	for _, wrong := range []Trouble{
		GroupGone, RecordUnreadable, RecordMissing, NoAccount, PasswordLost, ProjectGone,
		SharesTheOldReadGroup,
	} {
		text := string(wrong)
		if text == "" {
			t.Errorf("a trouble with no words at all")
		}
		if strings.HasSuffix(text, ".") || strings.ToLower(text) != text {
			t.Errorf("%q does not read as a clause inside a sentence", text)
		}
	}
}
