package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	acct "github.com/PHPCraftdream/wuserbox/internal/account"
	"github.com/PHPCraftdream/wuserbox/internal/base/lock"
	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/base/trace"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/policy/preset"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/facts"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/grants"
	"github.com/PHPCraftdream/wuserbox/internal/win/group"
	"github.com/PHPCraftdream/wuserbox/internal/win/pathid"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
)

// Init creates the group if it is missing and applies every permission the
// sandbox should hold: its own temp directory, the project directory, the
// agent preset, the standing rules and the extra directories passed in.
// Creating a group needs administrator rights; changing permissions needs
// ownership of the target.
func Init(o Options) (result *state.State, err error) {
	done := trace.Current().Phase("sandbox_init")
	defer func() { done(err) }()
	name, dir, err := Name(o.Dir)
	if err != nil {
		return nil, err
	}
	// wub-read needs admin rights the same as a sandbox's own group, so this
	// piggybacks on the elevation init already needs rather than asking for a
	// separate one. Failing here does not stop the build: without it, only
	// the profile reads that depended on it are missing, the same as any
	// other grant an unprivileged run could not finish.
	readDone := trace.Current().Phase("read_group_provisioning")
	if err := grants.EnsureReadGroup(); err != nil {
		readDone(err)
		// Said in full, because the sandbox that comes out of this works and
		// is quietly less useful than the one that was asked for: reads under
		// the profile fail, and the program inside will report those as
		// permission errors with nothing pointing back at this line.
		note(o, "the sandbox will not be able to read anything under %s: setting up the group "+
			"that reads your profile failed (%v).\n"+
			"  Everything else is in place. Run `wuserbox --init` again as an administrator to finish it.",
			paths.Home(), err)
	} else {
		readDone(nil)
	}
	var built *state.State
	// Everything from reading the record to writing it back is one operation.
	// Another wuserbox working on the same sandbox waits here rather than
	// starting from a record this one is about to replace.
	if err := lock.Hold(name, func() error {
		built, err = build(name, dir, o)
		return err
	}); err != nil {
		return nil, err
	}
	if err := grants.ProtectSettings(built); err != nil {
		return built, err
	}
	// After the rules file is certain to exist, and said out loud: this edits
	// a file somebody may have opened themselves. A narrower default reaches
	// only a machine that has never run wuserbox, and this is the one place
	// that can reach the rest.
	retired, err := grants.RetireWholeDirectoryProfileRules()
	if err != nil {
		note(o, "could not bring the profile section of the rules file up to date: %v", err)
	} else if len(retired) > 0 {
		note(o, "the rules file named %d whole agent directories to copy into every sandbox, "+
			"which an older version put there and which carried their entire contents on every "+
			"run; they are now the credential and settings files inside them. Taken out: %s",
			len(retired), strings.Join(retired, ", "))
	}
	return built, nil
}

// build does the work of Init with the sandbox's record already held.
func build(name, dir string, o Options) (*state.State, error) {
	s, err := state.Load(name)
	if err != nil {
		return nil, err
	}
	// The name is derived from the filesystem-resolved directory entry. Do not
	// let a record from a stale or colliding identity steer this init into a
	// different directory: verify the entry before changing the group comment,
	// account, or any permissions.
	if s != nil && s.Dir != "" {
		same, err := pathid.Same(s.Dir, dir)
		if err != nil {
			return nil, fmt.Errorf("cannot verify that sandbox %s belongs to %s: %w", name, dir, err)
		}
		if !same {
			return nil, fmt.Errorf("sandbox %s belongs to %s, not %s", name, s.Dir, dir)
		}
		s.Dir = dir
	}
	if comment, exists, err := group.Comment(name); err != nil {
		return nil, err
	} else if !exists {
		if err := group.Add(name, dir); err != nil {
			return nil, err
		}
	} else if comment != dir {
		if !projectPathsMatch(comment, dir) {
			return nil, fmt.Errorf("sandbox group %s belongs to %s, not %s", name, comment, dir)
		}
		// A stale spelling is cosmetic: the group still works.
		if err := group.SetComment(name, dir); err != nil {
			return nil, err
		}
	}

	account, err := sid.Lookup(name)
	if err != nil {
		return nil, err
	}
	if s == nil {
		s = &state.State{Group: name, Dir: dir, Temp: filepath.Join(paths.StateDir(), "tmp", name)}
	}
	s.BeginInit()
	defer s.EndInit()
	s.SID = account.String()
	// Anything a stopped command left half done is finished before this one
	// builds on top of it.
	if err := s.FinishPending(); err != nil {
		return nil, err
	}

	if err := ensureAccount(s, name, dir); err != nil {
		return nil, err
	}

	if err := ensureProfile(s, name); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(s.Temp, 0o755); err != nil {
		return nil, err
	}
	if err := s.Ensure(s.Temp, grant.RW); err != nil {
		return nil, err
	}
	if err := s.Ensure(dir, grant.RW); err != nil {
		return nil, err
	}
	if err := applyPreset(s, o); err != nil {
		return nil, err
	}
	if err := grants.FromConfig(s, true); err != nil {
		return nil, err
	}
	if err := grants.Extra(s, o.RW, o.RO, true); err != nil {
		return nil, err
	}
	// Everything else the sandbox was ever given: a directory handed over
	// once with grant or --rw is in the record and nowhere else, and repair
	// has to reach it too, or the advice to run init again would only work
	// for some of the permissions.
	if err := grants.Reapply(s); err != nil {
		return nil, err
	}
	if err := s.Save(); err != nil {
		return nil, err
	}
	// This is where the moment a sandbox was made comes from, and the only
	// place it can: nothing later can tell when it began. Losing it costs a
	// listing that one moment and nothing else, so it is said rather than
	// raised -- refusing a sandbox that works over a timestamp would be the
	// worse trade.
	if err := facts.MarkUsed(name); err != nil {
		note(o, "could not record when %s was made: %v", name, err)
	}
	// Measured here because init is already the slow, deliberate command --
	// it rewrites the permissions of every file in whole trees -- and
	// because nothing that merely reports on a sandbox can afford to: a walk
	// of a real profile takes seconds, not milliseconds. Same trade as the
	// moment above, for the same reason.
	measureDone := trace.Current().Phase("measure", trace.Field{Key: "sandbox", Value: name})
	if _, err := facts.Measure(name, s.Profile, s.Temp); err != nil {
		measureDone(err)
		note(o, "could not measure what %s takes on disk: %v", name, err)
	} else {
		measureDone(nil)
	}
	return s, nil
}

// ensureAccount creates the sandbox's own local account when it is missing,
// generating and sealing its password at the same time so the two are never
// out of step, and makes sure it holds exactly the memberships that let it
// run at all: its own group, BUILTIN\Users -- measured to cover
// C:\Windows and C:\Program Files -- and group.ReadGroup, the machine-wide
// group the user's own profile grants read to. Requires administrator
// rights, the same as creating the group itself.
//
// The record is saved right after the account is created, before anything
// else here or later in build can fail: NetUserAdd has already committed
// that password to the account by then, and nothing regenerates it, so a
// later failure must not cost the only place it survives. Losing the
// record after this point still leaves an account whose password nobody
// remembers, but it is one this same run just made and is still in the
// middle of finishing, not one a save already promised was ready to use.
func ensureAccount(s *state.State, groupName, dir string) (err error) {
	done := trace.Current().Phase("account_creation_or_reuse",
		trace.Field{Key: "sandbox", Value: groupName})
	defer func() { done(err) }()
	name, err := accountName(s, groupName, dir)
	if err != nil {
		return err
	}
	if err := replaceUnopenableAccount(s, name, groupName, dir); err != nil {
		return err
	}
	if s.Account == "" && s.Secret != "" && resolves(name) {
		// A record from the short-lived account format may have kept the
		// sealed password without the account field. Once the candidate has
		// passed the ownership checks, preserve that mapping explicitly.
		s.Account = name
		if err := s.Save(); err != nil {
			return err
		}
	}
	if _, err := sid.Lookup(name); err != nil {
		password, err := acct.GeneratePassword()
		if err != nil {
			return err
		}
		if err := acct.Add(name, dir, password); err != nil {
			return err
		}
		sealed, err := acct.Protect(password)
		if err != nil {
			return err
		}
		s.Account = name
		s.Secret = sealed
		if err := s.Save(); err != nil {
			return err
		}
	}
	builtinUsers, err := acct.BuiltinUsersName()
	if err != nil {
		return err
	}
	wanted := []string{groupName, builtinUsers}
	// The read group of the person building this sandbox, and only theirs.
	// Joining a group shared by the machine would let this sandbox read
	// every profile on it that had ever run init, which is the one thing
	// the split into a group per person exists to stop.
	//
	// A sandbox built before EnsureReadGroup ever ran, or on a run where it
	// failed, simply runs without this membership -- the same tolerance
	// EnsureReadGroup's own caller already extends, since the alternative is
	// refusing to build the sandbox at all over one grant that was always
	// allowed to be missing.
	owner, err := sid.CurrentUser()
	if err != nil {
		return err
	}
	if readGroup := group.ReadGroupFor(owner); resolves(readGroup) {
		wanted = append(wanted, readGroup)
	}
	if err := acct.EnsureMembership(name, wanted...); err != nil {
		return err
	}
	if err := leaveLegacyReadGroup(name); err != nil {
		return err
	}
	if err := acct.HideFromSignIn(name); err != nil {
		return err
	}
	return acct.DenyRemoteLogon(name)
}

// accountName selects only an account that can be proved to belong to this
// sandbox. The account name used by older builds is still considered so a
// migration can keep the existing password, but a colliding account is an
// error, never something to delete and recreate.
func accountName(s *state.State, groupName, dir string) (string, error) {
	if s.Account != "" {
		if resolves(s.Account) {
			ok, err := accountBelongs(s.Account, groupName, dir)
			if err != nil {
				return "", err
			}
			if !ok {
				return "", fmt.Errorf("account %s is not owned by sandbox group %s; refusing to replace it", s.Account, groupName)
			}
		}
		return s.Account, nil
	}
	for _, candidate := range acct.Candidates(groupName) {
		if !resolves(candidate) {
			continue
		}
		ok, err := accountBelongs(candidate, groupName, dir)
		if err != nil {
			return "", err
		}
		if !ok {
			return "", fmt.Errorf("account %s collides with sandbox group %s but belongs to another project; refusing to replace it", candidate, groupName)
		}
		return candidate, nil
	}
	return acct.NameFor(groupName), nil
}

func accountBelongs(name, groupName, dir string) (bool, error) {
	return acct.BelongsTo(name, groupName, dir)
}

// replaceUnopenableAccount takes away an account nothing can log on as any
// more and lets the rest of ensureAccount make a fresh one.
//
// That happens when the account exists and the record holding its sealed
// password does not -- the record was deleted, or damaged past reading.
// Nothing recovers the password: it was generated once, handed to Windows,
// sealed into that record and never written anywhere else. Left alone, the
// sandbox is a dead end that every later `--init` walks past, because the
// account it looks for is right there.
//
// The thin profile goes with it. Its directory and its registry hive both
// carry permissions naming the SID about to stop existing, and a hive the
// new account cannot open is a sandbox that starts and then cannot write
// its own settings. It is rebuilt from nothing a moment later by
// ensureProfile, and holds only copies in the first place.
func replaceUnopenableAccount(s *state.State, name, groupName, dir string) error {
	if s.Secret != "" || !resolves(name) {
		return nil // the password to open it is kept, or there is no account
	}
	ok, err := accountBelongs(name, groupName, dir)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("account %s is not owned by sandbox group %s; refusing to delete it", name, groupName)
	}
	if err := acct.Delete(name); err != nil {
		return err
	}
	s.Account = ""
	return os.RemoveAll(ProfileDir(groupName))
}

// leaveLegacyReadGroup takes this sandbox's account out of the one read
// group every sandbox on the machine used to share.
//
// Splitting that group per person, and taking its permission off the
// profile it was run from, was only half of it: the membership outlived
// both. A machine with two people on it has the other person's profile
// still granting the old group until they run init themselves, and this
// account still in it until now -- so this sandbox could read their files,
// which is the whole thing the split was for.
//
// A failure here is not passed over the way a missing read group is. That
// one costs the sandbox a read it never had; this one leaves somebody
// else's profile open to it.
func leaveLegacyReadGroup(name string) error {
	if !resolves(group.LegacyReadGroup) {
		return nil // never existed on this machine
	}
	return acct.RemoveMember(group.LegacyReadGroup, name)
}

// resolves says whether a group or account name is one this machine knows.
func resolves(name string) bool {
	_, err := sid.Lookup(name)
	return err == nil
}

// ensureProfile builds the sandbox's own thin profile: the directory
// Windows will load as this account's HKEY_CURRENT_USER on every run,
// instead of the one it would build unattended in C:\Users the first time
// the account logs on. Requires administrator rights, the same as
// ensureAccount: tightening the hive's permissions needs SE_BACKUP_NAME
// and SE_RESTORE_NAME, and telling Windows where the profile is lives
// under HKEY_LOCAL_MACHINE.
func ensureProfile(s *state.State, groupName string) error {
	account, err := sid.Lookup(s.Account)
	if err != nil {
		return err
	}
	s.Profile = ProfileDir(groupName)
	// MakeProfile performs the link preflight immediately before its first
	// mutation. Keep that check in one place: doing it here as well only walks
	// an existing profile twice on every init, while the profile may still
	// change between the two checks.
	if err := acct.MakeProfile(s.Profile, account); err != nil {
		return err
	}
	hiveDone := trace.Current().Phase("hive_registration", trace.Field{Key: "root", Value: s.Profile})
	if err := acct.RegisterProfile(account, s.Profile); err != nil {
		hiveDone(err)
		return err
	}
	hiveDone(nil)
	return nil
}

// note says what is happening, unless the caller asked for quiet or for one
// JSON document.
func note(o Options, format string, args ...any) {
	if o.Quiet || o.JSON {
		return
	}
	fmt.Fprintf(os.Stderr, "wuserbox: "+format+"\n", args...)
}

func applyPreset(s *state.State, o Options) error {
	// Set before either branch acts, so every save either branch makes along
	// the way already carries the decision: a plain run never repeats
	// --no-ai, and reads this instead of taking a fresh run's silence for
	// "presets are wanted again."
	s.NoAI = o.NoAI
	// A sandbox built before a profile of its own existed may still hold a
	// direct grant on the real agent directories. Nothing hands those out
	// any more -- a sandbox's own profile supplies that state now, filled by
	// a copy on every run, see internal/cli/setup/run.go's fillProfile --
	// and this runs whichever way --no-ai is set, because the question it
	// answers does not depend on that flag: does this sandbox still hold a
	// grant nothing hands out any more.
	if err := grants.RetireAIGrants(s); err != nil {
		return err
	}
	if o.NoAI {
		// Skipping is not enough for a sandbox that already holds the
		// profile root: the flag has to take it back, or a later run would
		// still reach it.
		return grants.DropPreset(s)
	}
	if !o.HomeWrites {
		return nil
	}
	// Reserve the sensitive names before handing the directory over, so the
	// sandbox cannot create one of them first.
	unguarded, err := grants.ReserveSensitiveNames()
	if err != nil {
		return err
	}
	for _, path := range unguarded {
		if o.JSON {
			continue // the answer is one JSON document; prose would break it
		}
		fmt.Fprintf(os.Stderr, "wuserbox: %s does not exist and cannot be reserved; "+
			"the sandbox may create it\n", path)
	}
	home := preset.Home()
	if err := s.Ensure(home.Path, home.Kind); err != nil {
		return err
	}
	// That permission reaches every file already in the profile root, so
	// refuse the ones that were never meant for the sandbox.
	return grants.RefuseHomeFiles(s)
}

type Options struct {
	// Dir is the project directory; it is always writable.
	Dir string
	// RW and RO are extra directories to hand over. They are recorded like
	// any other permission and stay in force for later runs, until `revoke`
	// takes them back: a permission that disappeared when a process was
	// killed would be a promise the tool could not keep.
	RW, RO []string
	// NoAI skips the preset for AI agent directories.
	NoAI bool
	// Quiet silences the progress messages, leaving errors alone.
	Quiet bool
	// DryRun works out what would change and prints it, changing nothing and
	// starting nothing.
	DryRun bool
	// JSON asks for machine-readable output where a command offers it.
	JSON bool
	// HomeWrites lets the sandbox create files directly in the profile root.
	// Off by default, because the same permission reaches every file already
	// there. When it is on, the sensitive files are refused one by one.
	HomeWrites bool
	// AllowLinks hands a directory over even where a file in it answers to
	// another name as well. Handing one over hands over every name its files
	// have, wherever those names are, so this is refused by default. It
	// travels in the options rather than in the environment because asking
	// for administrator rights starts wuserbox again from these arguments,
	// and an elevated process does not inherit what was set here.
	AllowLinks bool
}

// Args rebuilds these options as an `init` command line, for re-running with
// administrator rights. The output flags travel with the rest: the elevated
// copy is the one doing the work, and an elevated process inherits nothing
// from this one's environment, so a run asked to be quiet, or to answer in
// one JSON document, would have its elevated half go back to prose unless
// the flags are carried here.
func (o Options) Args() []string {
	args := []string{"--init", "--dir", o.Dir}
	for _, d := range o.RW {
		args = append(args, "--rw", d)
	}
	for _, d := range o.RO {
		args = append(args, "--ro", d)
	}
	if o.NoAI {
		args = append(args, "--no-ai")
	}
	if o.HomeWrites {
		args = append(args, "--home-writes")
	}
	if o.AllowLinks {
		args = append(args, "--allow-links")
	}
	if o.Quiet {
		args = append(args, "--quiet")
	}
	if o.JSON {
		args = append(args, "--json")
	}
	return args
}
