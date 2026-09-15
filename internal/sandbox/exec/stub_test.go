package exec

import (
	"strings"
	"syscall"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/win/group"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
)

// What these cover is the shape of the line: which arguments, in what order,
// and that the program is escaped into one of them instead of being glued on
// as the several words it usually is. What they cannot cover is the other end
// -- that Windows takes the line apart again into exactly those arguments --
// because taking a command line apart is CommandLineToArgvW's job and reading
// its answer means converting a returned address into a pointer, which go vet
// refuses on sight and rightly.
//
// That end is measured where it is real: TestAShellStartsUnderTheAccountsOwn
// RestrictedToken in internal/e2e runs `"C:\Program Files\Git\bin\bash.exe"
// --version` through the stub for real. A program that arrived as four words
// instead of one does not start.

func readGroupHere(t *testing.T) string {
	t.Helper()
	owner, err := sid.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	return group.ReadGroupFor(owner)
}

// TestTheStubLineNamesTheSandboxAndThenTheProgram is the order the stub reads
// its arguments in, held from the other side.
func TestTheStubLineNamesTheSandboxAndThenTheProgram(t *testing.T) {
	const program = `"C:\Program Files\Git\bin\bash.exe" -c "echo a b"`
	const self = `C:\Program Files\wuserbox\wuserbox.exe`
	line, err := StubLine(self, "S-1-5-21-1-2-3-1004", program)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{
		syscall.EscapeArg(self), StubFlag, "S-1-5-21-1-2-3-1004",
		syscall.EscapeArg(readGroupHere(t)), syscall.EscapeArg(program),
	}, " ")
	if line != want {
		t.Errorf("the stub line is\n  %s\nwant\n  %s", line, want)
	}
}

// TestTheProgramIsNotGluedOnAsSeveralWords is the mistake worth guarding: a
// command line handed to a sandbox is itself a command line, with spaces and
// quotes of its own, and joining it in raw would turn one argument into
// however many words it happens to contain.
func TestTheProgramIsNotGluedOnAsSeveralWords(t *testing.T) {
	const program = `"C:\Program Files\Git\bin\bash.exe" --version`
	line, err := StubLine(`C:\tools\wuserbox.exe`, "S-1-5-21-1-2-3-1004", program)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(line, " "+program) {
		t.Errorf("the program was joined on as it stands: %s", line)
	}
	if !strings.HasSuffix(line, " "+syscall.EscapeArg(program)) {
		t.Errorf("the program is not the last argument of %s", line)
	}
}

// TestAStubLineWithNoProgramStopsAtTheToken covers what --init asks for: the
// same line without the last argument, which is the shape Stub answers by
// building the token and stopping there.
func TestAStubLineWithNoProgramStopsAtTheToken(t *testing.T) {
	line, err := StubLine(`C:\tools\wuserbox.exe`, "S-1-5-21-1-2-3-1004", "")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{
		`C:\tools\wuserbox.exe`, StubFlag, "S-1-5-21-1-2-3-1004",
		syscall.EscapeArg(readGroupHere(t)),
	}, " ")
	if line != want {
		t.Errorf("the stub line is %q, want %q", line, want)
	}
}

// TestTheStubRefusesAnIncompleteRequest keeps the two shapes it accepts from
// quietly becoming three. It is reached from a command line, so its arguments
// are whatever somebody typed, and a missing one has to be said rather than
// indexed past.
func TestTheStubRefusesAnIncompleteRequest(t *testing.T) {
	for _, args := range [][]string{nil, {"S-1-5-21-1-2-3-1004"}, {"a", "b", "c", "d"}} {
		if err := Stub(args); err == nil {
			t.Errorf("%q was accepted", args)
		}
	}
}
