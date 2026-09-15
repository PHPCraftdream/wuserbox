// The stub: wuserbox starting itself inside the account a sandbox runs as.
//
// A sandbox is two things at once, and only one of them can be arranged from
// outside. Being the account is arranged here, by CreateProcessWithLogonW.
// Restricting the token cannot be: NtCreateUserProcess, handed an explicit
// token by a caller without SeAssignPrimaryTokenPrivilege, accepts only a
// child or a sibling of the caller's own token, and a token logged on for
// another account is neither. So the filtering has to be done from inside, by
// a process already running as that account.
//
// That process is wuserbox again. The account starts this binary with
// StubFlag, it cuts its own token down to the sandbox's identities, and the
// program runs under that. Every run is one process deeper than it looks, and
// the one in the middle exists for a single call.

package exec

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/PHPCraftdream/wuserbox/internal/account"
	"github.com/PHPCraftdream/wuserbox/internal/base/exit"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/win/group"
	"github.com/PHPCraftdream/wuserbox/internal/win/proc"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
)

// StubFlag is how wuserbox tells this apart from a program it was asked to
// run. One dash, deliberately: a command carries two and is listed in the
// help, and this is neither of those things. Nobody types it, and nothing
// that does carry two dashes can ever collide with it.
const StubFlag = "-sandbox-stub"

// Stub restricts this process's own token to the sandbox's identities and
// starts the program under it. It is what runs as the sandbox's account.
//
// Reaching it from anywhere is safe, which matters because a sandboxed
// process can reach it: restricting hands out nothing. A restricted token is
// still checked twice, and the first check uses the memberships the process
// already had, so naming another sandbox's group here names a group this
// account is not in and reaches nothing through it.
//
// With no command line it stops once the token is built. That is what --init
// runs to prove a sandbox can start at all; see ProveItStarts.
func Stub(args []string) error {
	if len(args) != 2 && len(args) != 3 {
		return exit.Errorf(exit.Usage,
			"%s takes a group, a read group and a command line", StubFlag)
	}
	restricted, err := token.AsSandbox(args[0], args[1])
	if err != nil {
		return err
	}
	defer restricted.Close()
	if len(args) == 2 {
		return nil
	}
	here, err := os.Getwd()
	if err != nil {
		return err
	}
	code, err := proc.Run(restricted, args[2], here)
	if err != nil {
		return err
	}
	// The program's own exit code, carried out of this process as its own, the
	// same way a run carries it out of wuserbox. Nothing after this line runs,
	// including the deferred close above, which Windows does anyway.
	os.Exit(code)
	return nil
}

// StubLine is the command line that reaches commandLine by way of the stub:
// the binary, the flag, what the sandbox is, and the program as one argument.
// An empty commandLine asks the stub to stop at the token.
//
// self is passed in rather than read here, because the binary that has to
// start is not always this process's own: a test stands another one in its
// place, and the point of the exercise is to stand it somewhere the account
// can reach.
//
// The read group is worked out here and handed over, for the same reason
// token.AsSandbox takes it rather than looking it up: inside the account the
// current user is the sandbox, so asking which read group belongs to "the
// caller" in there would name a group for the wrong person.
func StubLine(self, groupSID, commandLine string) (string, error) {
	owner, err := sid.CurrentUser()
	if err != nil {
		return "", err
	}
	parts := []string{self, StubFlag, groupSID, group.ReadGroupFor(owner)}
	if commandLine != "" {
		parts = append(parts, commandLine)
	}
	quoted := make([]string, len(parts))
	for i, part := range parts {
		quoted[i] = syscall.EscapeArg(part)
	}
	return strings.Join(quoted, " "), nil
}

// ProveItStarts measures the one thing about a newly built sandbox that
// nothing here can work out by reasoning: whether its account can start
// wuserbox at all.
//
// The account is not the person who installed wuserbox, and a binary sitting
// in that person's own profile is unreadable to it. CreateProcessWithLogonW
// then refuses with "access is denied", about a file it does not name, before
// any of the sandbox has had a chance to be wrong -- measured on CI, the
// first time the account tests ran, and the same thing would happen to a run.
//
// So it is measured by making the run's own call, with no program at the end
// of it. What passes here is the chain a run depends on rather than a model
// of it.
func ProveItStarts(s *state.State) error {
	if s.Account == "" {
		return nil // an older sandbox, which runs the old way and needs no stub
	}
	self, err := whereIAm()
	if err != nil {
		return err
	}
	password, err := account.Unprotect(s.Secret)
	if err != nil {
		return err
	}
	line, err := StubLine(self, s.SID, "")
	if err != nil {
		return err
	}
	code, err := proc.RunAsAccount(s.Account, password, line, s.Dir, childEnv(s, profileOf(s)))
	if err != nil {
		return fmt.Errorf("%s cannot start %s: %w", s.Account, self, err)
	}
	if code != 0 {
		return fmt.Errorf("%s started %s, which stopped with exit code %d", s.Account, self, code)
	}
	return nil
}

// cannotStart says what an unreadable wuserbox looks like from a run.
//
// Windows answers a binary the account may not read with "access is denied"
// and names nothing, which points at the program the person asked for rather
// than at the one in the middle they never knew about. A wrong password is
// not this: that comes back as a logon failure.
func cannotStart(s *state.State, self string, cause error) error {
	if !errors.Is(cause, syscall.ERROR_ACCESS_DENIED) {
		return cause
	}
	return fmt.Errorf("%s cannot read %s, and every run starts it as the sandbox before "+
		"the program: put wuserbox somewhere every account can read and execute, "+
		"then run `wuserbox --init --dir %s` again: %w",
		s.Account, self, s.Dir, cause)
}

// whereIAm is the wuserbox that is running: the binary a sandbox has to be
// able to start.
func whereIAm() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("finding wuserbox itself: %w", err)
	}
	return path, nil
}
