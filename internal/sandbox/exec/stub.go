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
	"time"

	"github.com/PHPCraftdream/wuserbox/internal/account"
	"github.com/PHPCraftdream/wuserbox/internal/base/exit"
	"github.com/PHPCraftdream/wuserbox/internal/base/lock"
	"github.com/PHPCraftdream/wuserbox/internal/base/trace"
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

// relayFlushGrace is the bounded window the relay's output pump gets
// after the program has ended, before this process exits and closes
// everything it names.
const relayFlushGrace = 250 * time.Millisecond

// Stub restricts this process's own token to the sandbox's identities and
// starts the program under it. It is what runs as the sandbox's account.
//
// Reaching it from anywhere is safe, which matters because a sandboxed
// process can reach it: restricting hands out nothing. A restricted token is
// still checked twice, and the first check uses the memberships the process
// already had, so naming another sandbox's group here names a group this
// account is not in and reaches nothing through it.
//
// With no command line it stops once the token is built and Shield has run
// over it. That is what --init runs to prove a sandbox can start at all and
// can shut itself in once started; see ProveItStarts. Both have to be
// proven there rather than assumed: Shield used to run only once a real run
// reached it, which meant --init could report a sandbox built and working
// on a machine where Shield itself would fail at the first real run --
// nothing here exercised the call until a program was already waiting on it.
//
// When the run asked --own-console, the stub takes a console of its own
// before starting the program, because a raw-mode terminal program refuses
// to start unless its input is a real console, and the account cannot share
// the caller's: a different account cannot attach to it, for input any more
// than for output. AllocConsole gives the account a real one instead, and
// the program starts against that.
//
// EnvConsoleRelay is the second answer to the same problem: a pseudo console
// with no window at all, taken in the same pre-Shield window for the same
// measured reason, and the program started attached to it through
// proc.RunWithConsole. The two are refused together: they are two different
// consoles for one program, not two halves of one. In relay mode the stub
// also pumps: rendered bytes out of the relay's output onto its own standard
// streams, forwarded keystrokes from its stdin into the relay's input, the
// two bridges the run built across the account line doing the carrying. The
// relay's third pipe carries only the operator console's size as it changes,
// and this process answers each message with ResizePseudoConsole on the
// console itself.
//
// Before any of that, the stub settles its own birth console's host. The
// stub is born with a console -- CREATE_NO_WINDOW is one, a console with no
// window -- and that console's conhost is the third console host of a relay
// run and the only one of a plain run: born before any of this code runs,
// under the unrestricted token, shielded by nothing. shutBirthConsoleHost
// shuts it here, at entry, before any console is taken and long before the
// program exists -- the one who would make a door of it is not running yet,
// and nothing that runs before it needs the host to stay open.
func Stub(args []string) error {
	if len(args) != 2 && len(args) != 3 {
		return exit.Errorf(exit.Usage,
			"%s takes a group, a read group and a command line", StubFlag)
	}
	// The outer command duplicates its write lease into this suspended stub
	// before resuming it. Adopt that handle and hold it here: the stub is
	// the holder the guarantee rests on, and the program is handed nothing.
	// The slot can be granted before the chain's last process object signals
	// -- a process releases its handles before its object signals, so that
	// ordering is a tautology of handle release, not a defect (measured; see
	// TestTheProgramCannotRunWhenTheSlotIsGranted) -- and what the guarantee
	// buys is that at the grant the program is down to its exit's reaper
	// thread, which never returns to user mode, measured 8 runs out of 8.
	// Direct unit probes omit the variable because they do not model the
	// command-layer lease.
	if handoff := os.Getenv(lock.TransferEnv); handoff != "" {
		value, err := os.ReadFile(handoff)
		if err != nil {
			return fmt.Errorf("reading the slot handoff: %w", err)
		}
		release, err := lock.Adopt(string(value))
		if err != nil {
			return err
		}
		defer release()
		// The program must not learn the path. It only needs the inherited
		// handle, and keeping the path in its environment would disclose a
		// protected state location to code inside the sandbox.
		_ = os.Unsetenv(lock.TransferEnv)
	}
	// The relay's resize pipe, adopted in the same pre-Shield window as the
	// slot handoff above: the handoff file is readable to this account
	// through its read group, which is not a promise Shield's restricted
	// token renews; and the handle value is only meaningful in this
	// process, which is what makes a stolen path useless everywhere else.
	var resizeRead *os.File
	if path := os.Getenv(proc.EnvResizeTransfer); path != "" {
		// Read and dropped at once, the way the slot handoff above is: the
		// program must not learn the path.
		_ = os.Unsetenv(proc.EnvResizeTransfer)
		handle, release, err := lock.AdoptTransfer(path)
		if err != nil {
			return err
		}
		// os.Exit skips deferred calls, so on the success path this never
		// runs; the stub's own death closes what it names -- the documented
		// pattern here.
		defer release()
		resizeRead = os.NewFile(uintptr(handle), "relay-resize")
	}
	// Read and dropped at once, the way the slot handoff above is: the env
	// vars that ask for a console are the caller's business, and the program
	// would inherit either as plain environment if it stayed. Whether a
	// console is wanted is decided here, and the console itself is taken just
	// before Shield.
	ownConsole := os.Getenv(proc.EnvOwnConsole) != ""
	_ = os.Unsetenv(proc.EnvOwnConsole)
	relayWanted := os.Getenv(proc.EnvConsoleRelay) != ""
	_ = os.Unsetenv(proc.EnvConsoleRelay)
	// Two answers to one question -- a real console in a window of its own,
	// or a windowless one relayed as bytes -- and only one of them can be
	// given. Refused rather than resolved: whoever set both asked for a
	// contradiction, and silently honoring one half of it would hide that.
	if ownConsole && relayWanted {
		return exit.Errorf(exit.Usage,
			"%s and %s name two different consoles for the program; set only one",
			proc.EnvOwnConsole, proc.EnvConsoleRelay)
	}
	// The birth console's host is shut before the token is built and before
	// any console is taken: the console exists already, and this is the
	// earliest moment to close what hosts it. In own-console mode this
	// shield is wasted -- FreeConsole below takes the birth console and its
	// host with it -- and the waste is one small call, bought for not making
	// the shield conditional on which console is about to be taken.
	account, err := sid.CurrentUser()
	if err != nil {
		return err
	}
	if err := shutBirthConsoleHost(account); err != nil {
		return err
	}
	restricted, err := token.AsSandbox(args[0], args[1])
	if err != nil {
		return err
	}
	defer restricted.Close()
	// Here rather than after Shield, and that order is measured, not guessed:
	// AllocConsole under the restricted token is refused with access denied --
	// the console's access checks see only the restricting identities, and
	// those name the group and the account, not the interactive logon the
	// window station is willing to serve -- while the unrestricted account
	// token is granted. So the console's handles are opened before the token
	// narrows, and keep the access they were opened with: a handle holds the
	// access it was granted at open, the same fact the design doc records for
	// the stub's own birth window. Everything the stub still has to say after
	// this point -- Shield refusing, the program failing to start -- goes
	// back to the caller's bridge pipes by the deferred restore below, so the
	// move costs the error path nothing.
	if ownConsole {
		restore, err := takeOwnConsole()
		if err != nil {
			return err
		}
		defer restore()
	}
	var relay *consoleRelay
	if relayWanted {
		r, err := takeConsoleRelay()
		if err != nil {
			return err
		}
		relay = r
		// The same blind spot the own-console restore above sits in:
		// os.Exit skips deferred calls, so on the success path this close
		// never runs, and the stub's death closes what it names.
		defer relay.close()
	}
	// Before the program exists, and not after -- and before the two-argument
	// return below, not conditioned on it. What is about to start, when there
	// is something to start, is the same account as this process, holding a
	// token restricted from this one's -- and a permission list cannot tell
	// two processes apart by who they are when they are the same who.
	// Measured: without this, the program opened this process with every
	// access there is and duplicated its token, which is the whole boundary
	// undone from inside. Running it even with nothing to start is what lets
	// --init's own probe answer for it too, rather than only for the token.
	if err := proc.Shield(); err != nil {
		return err
	}
	if len(args) == 2 {
		return nil
	}
	here, err := os.Getwd()
	if err != nil {
		return err
	}
	// When the relay's console exists it is the program's, handles and all;
	// when it does not, the streams this process holds are duplicated into
	// the program the way they always were.
	var code int
	if relay != nil {
		// The relay crosses the account line on this process's own
		// standard streams: rendered bytes out through the stdout the
		// caller's output bridge is already draining, keystrokes in from
		// the stdin its input bridge already fills. RunWithConsole passes
		// the program no standard handles and starts it with
		// bInheritHandles false, so nothing under the program -- a
		// backgrounded child included -- ever holds a copy of either pipe:
		// the leftover-holder shape P1-2 was about cannot form here, and
		// the pipes' last holders are this process and the console's own
		// conhost, both of which go away below.
		pumpRelay(relay, os.Stdout, os.Stdin)
		if resizeRead != nil {
			// The third leg of the relay: the operator's console changes
			// size, and this process is the only one that can answer,
			// because the hpc lives here.
			pumpRelayResizes(relay, resizeRead)
		}
		code, err = proc.RunWithConsole(restricted, args[2], here, relay.hpc)
	} else {
		code, err = proc.Run(restricted, args[2], here)
	}
	if err != nil {
		return err
	}
	if relay != nil {
		// conhost renders on a timer of its own and holds the last write
		// end of the relay's output pipe: ending the console the instant
		// the program exits can drop the last rendered bytes on the floor
		// -- the shape TestTheConsoleRelayCarriesTheChildsRenderedOutput
		// measured. The pump gets this long to carry the tail across.
		// Then the console is closed here, explicitly, because os.Exit
		// skips the deferred close and a conhost outliving this process
		// is exactly the kind of handle holder the run's caller is
		// draining against; close is safe to call twice.
		time.Sleep(relayFlushGrace)
		relay.close()
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

// ProveItStarts measures what a newly built sandbox cannot be reasoned about
// from outside: whether its account can start wuserbox at all, and whether
// the stub that account starts can shut itself in once it has.
//
// The account is not the person who installed wuserbox, and a binary sitting
// in that person's own profile is unreadable to it. CreateProcessWithLogonW
// then refuses with "access is denied", about a file it does not name, before
// any of the sandbox has had a chance to be wrong -- measured on CI, the
// first time the account tests ran, and the same thing would happen to a run.
//
// So it is measured by making the run's own call, with no program at the end
// of it -- and, since Stub always runs Shield now rather than only when there
// is a program to start next, that call is what stands behind Shield here
// too. What passes here is the chain a run depends on rather than a model of
// it.
func ProveItStarts(s *state.State) (err error) {
	done := trace.Current().Phase("prove_it_starts", trace.Field{Key: "sandbox", Value: s.Group})
	defer func() { done(err) }()
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
	code, err := proc.RunAsAccountWithLease(s.Account, password, line, s.Dir,
		childEnv(s, profileOf(s)), lock.SlotPath(s.Group))
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
