// Building a sandbox: the command that asks for one, the work of bringing
// one in line with what was asked, and starting wuserbox again with
// administrator rights where the work needs them.

package setup

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	acct "github.com/PHPCraftdream/wuserbox/internal/account"
	"github.com/PHPCraftdream/wuserbox/internal/base/exit"
	"github.com/PHPCraftdream/wuserbox/internal/base/lock"
	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/base/trace"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/exec"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/facts"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/grants"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/plan"
	"github.com/PHPCraftdream/wuserbox/internal/win/proc"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
)

// adjustment is what bringing an existing sandbox in line with the flags came
// to. Rebuilding is reported rather than done, because it starts a second
// wuserbox with administrator rights and that one waits for the same lock.
type adjustment struct {
	state *state.State
	// rebuild says the sandbox has to be created again by an elevated run.
	rebuild bool
	// dropPreset says --no-ai still has to reach the rebuilt sandbox.
	dropPreset bool
}

// prepare loads the sandbox, building or repairing it with administrator
// rights when the group is missing or a permission cannot be applied as the
// plain user.
func prepare(options sandbox.Options) (*state.State, error) {
	done := trace.Current().Phase("prepare")
	s, err := prepareImpl(options)
	done(err)
	return s, err
}

func prepareImpl(options sandbox.Options) (*state.State, error) {
	name, _, err := sandbox.Name(options.Dir)
	if err != nil {
		return nil, err
	}
	var made adjustment
	// Reading the record and changing permissions is one operation, so it is
	// done with the record held. Elevation is deliberately left outside.
	if err := lock.Hold(name, func() error {
		var err error
		made, err = adjust(options, name)
		return err
	}); err != nil {
		return nil, err
	}
	if !made.rebuild {
		return made.state, nil
	}
	if path := trace.Current().Path(); path != "" {
		report(options, "bootstrap trace: %s", path)
	}
	repaired, err := rebuild(options, name)
	if err != nil {
		return nil, err
	}
	if !made.dropPreset {
		return repaired, nil
	}
	return repaired, lock.Hold(name, func() error {
		if err := grants.DropPreset(repaired); err != nil {
			return fmt.Errorf("--no-ai could not take back the agent directories: %w", err)
		}
		return nil
	})
}

// missing says what has to be built with administrator rights before
// anything can be adjusted, in the words to show whoever is watching, and an
// empty string when nothing is. None of these is an error to pass on; all of
// them are a reason to build the sandbox again.
//
// They are told apart rather than lumped together because they are not the
// same event. One of them is a sandbox from before sandboxes had accounts of
// their own being brought forward, and a line saying "creating sandbox" for
// a sandbox that has existed for months, and keeps everything it was given,
// tells the reader something untrue about what is about to happen.
func missing(name string, s *state.State) string {
	// Nothing recorded and no group either is the ordinary first run, not a
	// sandbox in trouble, so it is said before asking what is wrong.
	if s == nil && !resolves(name) {
		return fmt.Sprintf("creating sandbox %s", name)
	}
	// The project directory is deliberately not passed: a run happening in a
	// directory is proof enough that it is there, and judging it here would
	// only ever answer a question the listing asks.
	switch wrong := facts.Judge(name, "", s, nil); wrong {
	case facts.Whole:
		return ""
	case facts.NoAccount:
		// Worth more than the one line the others get. This is every sandbox
		// on a machine that had them before accounts existed, it happens once
		// per sandbox, and what it does not do is as important as what it does.
		return fmt.Sprintf("sandbox %s %s: giving it one, which needs administrator "+
			"rights. Everything it already holds stays, because its permissions name "+
			"its group and the account joins that group", name, wrong)
	default:
		return fmt.Sprintf("sandbox %s: %s; building it again", name, wrong)
	}
}

// resolves says whether a group or account name is one this machine knows.
func resolves(name string) bool {
	_, err := sid.Lookup(name)
	return err == nil
}

// adjust brings an existing sandbox in line with the flags, with the record
// already held. It changes permissions and never starts another process.
func adjust(options sandbox.Options, name string) (adjustment, error) {
	s, err := state.Load(name)
	if err != nil {
		return adjustment{}, err
	}
	if lacking := missing(name, s); lacking != "" {
		report(options, "%s", lacking)
		return adjustment{rebuild: true}, nil
	}
	// A command that was stopped between writing a change down and applying it
	// left the record ahead of the file system. Nothing else here would notice,
	// because everything else trusts the record.
	if err := s.FinishPending(); err != nil {
		report(options, "%v", err)
		return adjustment{rebuild: true}, nil
	}
	if err := reconcilePreset(s, options); err != nil {
		report(options, "%v", err)
		return adjustment{rebuild: true, dropPreset: s.NoAI}, nil
	}
	if err := grants.FromConfig(s, false); err != nil {
		report(options, "%v", err)
		return adjustment{rebuild: true}, nil
	}
	if err := grants.Extra(s, options.RW, options.RO, false); err != nil {
		report(options, "%v", err)
		return adjustment{rebuild: true}, nil
	}
	return adjustment{state: s}, nil
}

// reconcilePreset brings the agent preset in line with the sandbox's own
// standing decision, not with the flags on this particular command line.
//
// A run never carries --no-ai: onlyRunning refuses it before options reaches
// here. What decides this is s.NoAI, set once by an explicit `init --no-ai`
// and read from every run after, so the decision means the same thing until
// something explicitly changes it, rather than lapsing the moment the flag
// stops being typed.
func reconcilePreset(s *state.State, options sandbox.Options) error {
	if s.NoAI {
		return grants.DropPreset(s)
	}
	// The sandbox is brought in line with the preset on every start, so a
	// directory the preset gained since the sandbox was built is reached, and
	// --home-writes reaches a sandbox that was built without it.
	return grants.ApplyPreset(s, options.HomeWrites)
}

func rebuild(options sandbox.Options, name string) (*state.State, error) {
	existing, err := state.Load(name)
	if err != nil {
		return nil, err
	}
	done := trace.Current().Phase("elevation_request", trace.Field{Key: "sandbox", Value: name})
	if err := Elevate(rebuildOptions(options, existing).Args()); err != nil {
		done(err)
		return nil, err
	}
	done(nil)
	s, err := state.Load(name)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, elevatedRunWentElsewhere(name, options.Dir)
	}
	return s, nil
}

// elevatedRunWentElsewhere explains an elevated init that reported success
// and left nothing where this process looks.
//
// The elevated process gets its own environment rather than this one's:
// ShellExecuteEx with "runas" has nowhere to put an environment block, and
// the service that starts it builds one from the account that answered the
// consent prompt. Where that is the same person -- an administrator clicking
// Yes -- %LOCALAPPDATA% is the same directory and everything lands where
// this process will look. Where it is somebody else -- a standard user's
// prompt asks for an administrator's credentials, and the process then runs
// as that administrator -- the group, the account and the profile are made
// on the machine, and the record naming them is written into that
// administrator's profile, which this account never reads.
//
// Retrying walks the same path: the group and account are found, the record
// is not, and init is asked for again. So this refuses rather than
// returning something that looks like a reason to try once more, and says
// what is actually on the machine, because a sandbox half-built this way
// leaves an account behind that this person cannot use.
func elevatedRunWentElsewhere(name, dir string) error {
	if !resolves(name) {
		// Elevation came back saying it worked and the group is not there.
		// Nothing more is known than that.
		return exit.Errorf(exit.Failed, "sandbox %s was not created", name)
	}
	return exit.Errorf(exit.Failed,
		"sandbox %s was created by a different administrator than the one running this, "+
			"so its record went to that account's profile and this one cannot read it.\n"+
			"  The group and the account exist on the machine and nothing here can use them: "+
			"remove them with `wuserbox --rm --dir %s`.\n"+
			"  wuserbox cannot yet build a sandbox for an account that is not itself an "+
			"administrator; open an elevated terminal as this account and run "+
			"`wuserbox --init --dir %s` there.",
		name, dir, dir)
}

// rebuildOptions is what actually goes into the elevated re-exec.
//
// A run can never carry --no-ai; onlyRunning refuses it before options
// reaches here. So when the group is missing or broken and has to be built
// again, a record already on disk is the only place that decision survives.
// Without folding it back in, the elevated init would read the run's own
// silence as "presets are wanted again" and hand the agent preset back to a
// sandbox it was explicitly taken from.
func rebuildOptions(options sandbox.Options, existing *state.State) sandbox.Options {
	if existing != nil && existing.NoAI {
		options.NoAI = true
	}
	return options
}

// report prints a progress message, unless the caller asked for quiet. These
// go to the error stream: the output stream belongs to the command being run.
func report(options sandbox.Options, format string, args ...any) {
	// Silent under --json as well as under --quiet. A command asked for JSON
	// answers with one document, and a line of prose before it leaves the
	// stream unparseable for exactly the reader that asked.
	if options.Quiet || options.JSON {
		return
	}
	fmt.Fprintf(os.Stderr, "wuserbox: "+format+"\n", args...)
}

// previewInput is what Preview works its plan out from. A sandbox that
// already exists decides its own NoAI and carries grants — a --grant given
// once, say — that nothing else on this command line would reproduce. Built
// only from this invocation's flags, a preview would show the agent preset a
// saved --no-ai withheld, and leave out what --grant recorded nowhere else.
func previewInput(options sandbox.Options, group, dir string, existing *state.State) plan.Input {
	in := plan.Input{
		Group: group, Dir: dir, Temp: filepath.Join(paths.StateDir(), "tmp", group),
		RW: options.RW, RO: options.RO,
		NoAI: options.NoAI, HomeWrites: options.HomeWrites,
	}
	if existing != nil {
		in.Temp = existing.Temp
		in.NoAI = existing.NoAI
		in.Existing = existing.Grants
	}
	return in
}

// Preview prints what a sandbox would be given, and changes nothing. It is
// what --dry-run reaches for on init and run.
func Preview(options sandbox.Options) error {
	group, dir, err := sandbox.Name(options.Dir)
	if err != nil {
		return err
	}
	existing, _ := state.Load(group)
	in := previewInput(options, group, dir, existing)
	prepared, err := plan.For(in)
	if err != nil {
		return err
	}
	// Filling the profile is a whole other question from the permissions
	// above, and asked separately for the reason AddProfilePreview's own
	// doc gives: it is a walk of the machine, and only --dry-run needs the
	// answer.
	if err := prepared.AddProfilePreview(group, in.NoAI); err != nil {
		return err
	}
	text, err := plan.Render(prepared, options.JSON)
	if err != nil {
		return err
	}
	_, _ = io.WriteString(os.Stdout, text)
	return nil
}

// Init creates the sandbox for a directory, asking for administrator rights
// first, because a local group cannot be created without them.
func Init(args []string) error {
	options, _, err := ParseOptions("init", args)
	if err != nil {
		return err
	}
	if options.DryRun {
		return Preview(options)
	}
	if !token.IsAdmin() {
		if path := trace.Current().Path(); path != "" {
			report(options, "bootstrap trace: %s", path)
		}
		done := trace.Current().Phase("elevation_request")
		err := Elevate(options.Args())
		done(err)
		if err != nil {
			return err
		}
		// The elevated copy answers in a console of its own: ShellExecuteEx
		// starts it in a new one, and nothing it writes reaches this
		// process's streams. The line an init prints on success is printed
		// here instead, worked out from the same --dir, so a script reading
		// this process's stdout gets the same answer whichever way the
		// rights were come by. Where this account cannot resolve the
		// directory -- which is what asking for another account's rights can
		// be for -- the line is not available to it, and the exit code
		// carries the success alone.
		if name, dir, nameErr := sandbox.Name(options.Dir); nameErr == nil {
			fmt.Printf("%s\t%s\n", name, dir)
		}
		return nil
	}
	name, _, err := sandbox.Name(options.Dir)
	if err != nil {
		return err
	}
	// Taken here rather than before the elevation check, because where this
	// process is not the administrator it hands the work to an elevated copy
	// of itself and waits, and that copy takes the slot of the same sandbox.
	// It is held across the whole command and not only around the probe:
	// the build is itself a change to state two runs share -- the account,
	// the profile -- and the probe at the end births a stub, which is what
	// the slot exists to arbitrate. Without the take here, the probe's own
	// birth is what waits and refuses -- a self-inflicted "another run is
	// already going" that would look like a flake.
	release, err := holdSlot(name)
	if err != nil {
		return err
	}
	defer release()
	done := trace.Current().Phase("elevated_init")
	s, err := sandbox.Init(options)
	done(err)
	if err != nil {
		return err
	}
	// The sandbox on the machine is kept: it is complete, it holds everything
	// it was given, and it will work the moment wuserbox is somewhere its
	// account can reach. Throwing that away would cost somebody their
	// permissions over a binary in the wrong place.
	//
	// It is still a failure, and it was reported as success until somebody
	// pointed at it. An init that says it worked and leaves a sandbox no
	// program will start in is a lie a script cannot see through -- and the
	// two flags a script is most likely to be using, --quiet and --json, were
	// exactly the ones that swallowed the warning this used to be.
	done = trace.Current().Phase("prove_it_starts")
	if err := exec.ProveItStarts(s); err != nil {
		done(err)
		return exit.Errorf(exit.Failed,
			"sandbox %s is built and kept, and no program will start in it: %v.\n"+
				"  Every run starts wuserbox again as the sandbox's own account, so that account "+
				"has to be able to read and execute it. Put wuserbox somewhere every account can "+
				"-- under Program Files, say -- and run `wuserbox --init --dir %s` again. "+
				"Nothing has to be built twice: what is already there is waiting for it.",
			s.Group, err, s.Dir)
	}
	done(nil)
	fmt.Printf("%s\t%s\n", s.Group, s.Dir)
	return nil
}

// EnvNonInteractive switches off consent prompts for this process. The
// command line sets it, and a script may set it itself, so a whole run of
// commands shares one setting instead of repeating the flag. It is read
// before administrator rights are asked for, and the ask is refused: an
// elevated copy does not inherit this process's environment, so nothing
// could carry the setting across, and refusing here rather than stopping at
// a dialog nobody can click is the whole point.
const EnvNonInteractive = "WUSERBOX_NON_INTERACTIVE"

// Elevate re-runs wuserbox with administrator rights and reports a non-zero
// exit as an error.
//
// A sandboxed process must never reach this: asking for administrator rights
// is exactly how it would escape, and the user would face a prompt they never
// asked for. Automation must not reach it either, for a duller reason: a
// consent dialog nobody can click stops the script until it is killed.
func Elevate(args []string) error {
	if acct.InsideSandbox() {
		return exit.Errorf(exit.Denied,
			"refusing to ask for administrator rights from inside a sandbox")
	}
	if os.Getenv(EnvNonInteractive) != "" {
		return exit.Errorf(exit.NeedsElevation,
			"`wuserbox %s` needs administrator rights, and prompts are switched off; "+
				"run it once in an elevated terminal, or drop --non-interactive", args[0])
	}
	code, err := proc.Elevate(args)
	if err != nil {
		return err
	}
	if code != 0 {
		return exit.Errorf(exit.Code(code),
			"`wuserbox %s` failed with exit code %d when run as administrator", args[0], code)
	}
	return nil
}
