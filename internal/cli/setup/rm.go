package setup

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	acct "github.com/PHPCraftdream/wuserbox/internal/account"
	"github.com/PHPCraftdream/wuserbox/internal/base/exit"
	"github.com/PHPCraftdream/wuserbox/internal/base/lock"
	"github.com/PHPCraftdream/wuserbox/internal/cli/usage"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/plan"
	"github.com/PHPCraftdream/wuserbox/internal/win/group"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
)

// Rm deletes a sandbox: every permission it applied, its temp directory, its
// bookkeeping and the group itself.
func Rm(args []string) error {
	flags, o := rmFlags()
	if err := flags.Parse(args); err != nil {
		return exit.Errorf(exit.Usage, "%v", err)
	}
	// The project is named with --dir, never as a plain argument. Taking one
	// silently would remove the sandbox of the current directory while the
	// command line says another, and this command deletes things.
	if flags.NArg() > 0 {
		return exit.Errorf(exit.Usage,
			"wuserbox --rm takes no directory as an argument; "+
				"name the project with --dir %s", flags.Arg(0))
	}
	if o.nonInteractive {
		_ = os.Setenv(EnvNonInteractive, "1")
	}
	project := o.dir
	if project == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		project = cwd
	}
	name, _, err := sandbox.Name(project)
	if err != nil {
		return err
	}
	if o.dryRun {
		return previewRemoval(name, o.asJSON)
	}
	if !token.IsAdmin() {
		return Elevate([]string{"--rm", "--dir", project})
	}
	return removeSandbox(name, o.asJSON)
}

// removal is every flag rm reads.
type removal struct {
	dir                            string
	dryRun, asJSON, nonInteractive bool
}

// rmFlags builds that set, apart from the parsing, so a test can walk it.
func rmFlags() (*flag.FlagSet, *removal) {
	flags := flag.NewFlagSet("rm", flag.ContinueOnError)
	usage.Quiet(flags)
	o := &removal{}
	flags.StringVar(&o.dir, "dir", "", "project directory")
	flags.BoolVar(&o.dryRun, "dry-run", false, "show what would change, change nothing")
	flags.BoolVar(&o.asJSON, "json", false, "print the result as JSON")
	flags.BoolVar(&o.nonInteractive, "non-interactive", false,
		"fail instead of asking for administrator rights")
	return flags, o
}

// removeSandbox does the deleting, once the right to do it is established.
// The record is held throughout, so a command handing the sandbox another
// directory cannot write that permission back into a record being deleted.
func removeSandbox(name string, asJSON bool) error {
	return lock.Hold(name, func() error { return remove(name, asJSON) })
}

func remove(name string, asJSON bool) error {
	s, damaged, err := recordFor(name, asJSON)
	if err != nil {
		return err
	}
	if s != nil {
		if left := clearGrants(s, asJSON); len(left) > 0 {
			// The record is the only list of what is still in force, and the
			// group is what those entries name. Keeping both is what makes a
			// second attempt able to finish; deleting them would leave
			// permissions behind that nothing can find again.
			return exit.Errorf(exit.Failed,
				"%s was not fully removed and is left in place so `wuserbox --rm` can finish it: %s",
				name, strings.Join(left, ", "))
		}
	}
	// Asked for unconditionally, and not only where a record was read. The
	// record and the copy behind it go missing separately: deleting the record
	// by hand leaves the copy, and a copy that outlives the sandbox it
	// describes is not merely untidy. A later sandbox of the same name starts
	// with no copy of its own until its second save, so until then the stale
	// one stands behind its record, naming directories that answered to a group
	// that no longer exists. Removing what is not there is not an error.
	if err := discardRecord(name); err != nil {
		return exit.Errorf(exit.Failed,
			"the permissions of %s are revoked, but its bookkeeping remains: %v", name, err)
	}
	dir, exists, err := group.Comment(name)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if s == nil || damaged {
		// The record is gone, or it was damaged and the copy behind it is a
		// save short, and the group is not gone. Deleting the group anyway left
		// every entry naming it behind, on paths nothing can name afterwards:
		// the identifier those entries hold is about to stop resolving, and no
		// later command could find them by it.
		//
		// The group itself remembers one thing -- the directory it belongs to,
		// in its own comment -- so that much can still be cleared. Anything
		// handed over outside that directory cannot be, and the caller is told
		// so rather than left with a success that means less than it looks.
		// Doing it after a recovered record costs nothing and covers the one
		// grant most likely to be missing from it, since taking back what is
		// not there is not an error.
		if err := clearOrphans(name, dir, asJSON); err != nil {
			return err
		}
	}
	if err := removeAccount(name, asJSON); err != nil {
		return err
	}
	return group.Delete(name)
}

// removeAccount takes the sandbox's own local account away: its profile
// directory first, while its SID still resolves, so a failure part-way
// through leaves something a retry can still find; then the sign-in screen
// entry and the account itself. It works from the group's name alone,
// deriving the account's name the same way ensureAccount does, so a missing
// or damaged record never stands between removal and an account it can
// still find.
//
// The account never existing -- a sandbox this old, or one whose account a
// previous attempt already removed -- is not a failure.
func removeAccount(groupName string, asJSON bool) error {
	name := acct.NameFor(groupName)
	if !accountExists(name) {
		return nil // never made, or already taken by an earlier attempt
	}
	value, err := sid.Lookup(name)
	if err != nil {
		return err
	}
	var left []string
	complain := func(part string, err error) {
		if !asJSON {
			fmt.Fprintln(os.Stderr, "wuserbox:", err)
		}
		left = append(left, part)
	}
	// The thin profile directory goes first, unprivileged in principle --
	// its own entry for the machine owner is what makes that true -- so a
	// failure past this point still leaves something a retry can find and
	// finish.
	if err := os.RemoveAll(sandbox.ProfileDir(groupName)); err != nil {
		complain("its profile directory", err)
	}
	if err := acct.DeleteProfile(value.String()); err != nil {
		complain("its ProfileList entry", err)
	}
	if err := acct.RemoveProfileServiceReference(value); err != nil {
		complain("its profile service reference", err)
	}
	if err := acct.UnhideFromSignIn(name); err != nil {
		complain("its sign-in screen entry", err)
	}
	if err := acct.Delete(name); err != nil {
		complain("the account itself", err)
	}
	if len(left) > 0 {
		return exit.Errorf(exit.Failed,
			"%s was not fully removed and is left in place so `wuserbox --rm` can finish it: %s",
			name, strings.Join(left, ", "))
	}
	return nil
}

// recordFor reads the record for removal, and says whether what came back is
// all there was.
//
// Every other command stops on a record it cannot read, and should: acting on
// a sandbox whose permissions are unknown is how permissions get left behind.
// Removal is the one command that must go on anyway, because leaving them
// behind is exactly what it is there to prevent, and refusing made the sandbox
// impossible to remove at all.
func recordFor(name string, asJSON bool) (*state.State, bool, error) {
	s, err := state.Load(name)
	var unreadable *state.Damaged
	if !errors.As(err, &unreadable) {
		return s, false, err
	}
	if !asJSON {
		recovered := "nothing is left naming what it was handed"
		if unreadable.Previous != nil {
			recovered = "going on with the copy from before the last save, " +
				"which may be one grant short"
		}
		fmt.Fprintf(os.Stderr, "wuserbox: %v; %s\n", unreadable, recovered)
	}
	return unreadable.Previous, true, nil
}

// discardRecord deletes the record and the copy kept beside it, whichever of
// them is still there.
func discardRecord(name string) error {
	for _, path := range bookkeeping(name) {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("deleting %s: %w", path, err)
		}
	}
	return nil
}

// bookkeeping is every file wuserbox keeps about one sandbox.
func bookkeeping(name string) []string {
	return []string{state.Path(name), state.PreviousPath(name), sandbox.UsedMarker(name)}
}

// clearOrphans takes a sandbox's entries off the directory its group belongs
// to, for a sandbox whose record is missing.
func clearOrphans(name, dir string, asJSON bool) error {
	if dir == "" {
		return nil
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil
	}
	account, named := identifierOf(name)
	if !named {
		// Nothing left to look for. The group is still removable, and removing
		// it is better than refusing to finish over a name that no longer
		// resolves.
		return nil
	}
	if !asJSON {
		fmt.Fprintf(os.Stderr,
			"wuserbox: %s has no record left, so only %s is being cleared; "+
				"anything handed over elsewhere keeps an entry naming a group that is about to go\n",
			name, dir)
	}
	if err := grant.Revoke(account, dir); err != nil {
		return err
	}
	return grant.Prune(account, dir, nil)
}

// accountExists reports whether a name resolves to a real account, the same
// way a group's existence is checked before acting on it elsewhere here.
func accountExists(name string) bool {
	_, err := sid.Lookup(name)
	return err == nil
}

// identifierOf returns the identifier a group name stands for, and whether it
// still stands for one. A name that resolves to nothing is not a failure here:
// there is simply no entry anywhere that could be naming it.
func identifierOf(name string) (string, bool) {
	value, err := sid.Lookup(name)
	if err != nil {
		return "", false
	}
	return value.String(), true
}

// clearGrants revokes everything the sandbox holds and deletes its temp
// directory, and names whatever would not go.
//
// Every step is attempted even after one fails, so a single stubborn
// directory does not leave the rest of the permissions in force.
func clearGrants(s *state.State, asJSON bool) []string {
	var left []string
	// Each failure is named in the error at the end as well. Saying it here
	// too helps where the answer is prose, and would break it where the answer
	// is one JSON document.
	complain := func(err error) {
		if !asJSON {
			fmt.Fprintln(os.Stderr, "wuserbox:", err)
		}
	}
	for _, g := range s.Grants {
		// A directory that is no longer there holds no entries, so there is
		// nothing left to take back. Counting it as a failure would leave
		// every later attempt failing on the same missing path, and the
		// sandbox could never be removed at all.
		if _, err := os.Stat(g.Path); os.IsNotExist(err) {
			continue
		}
		if err := grant.Revoke(s.SID, g.Path); err != nil {
			complain(err)
			left = append(left, g.Path)
			continue
		}
		// Rewriting the directory is not the whole of taking it back, here any
		// more than it is for a single revoke. A directory inside it that was
		// handed to another sandbox pinned its permission list with this
		// sandbox's entry copied into it, and no longer hears from above, so
		// the entry has to be taken away by name. Nothing is kept: the whole
		// sandbox is going, so every path it held loses it.
		if err := grant.Prune(s.SID, g.Path, nil); err != nil {
			complain(err)
			left = append(left, g.Path)
		}
	}
	if err := os.RemoveAll(s.Temp); err != nil {
		complain(err)
		left = append(left, s.Temp)
	}
	return left
}

// previewRemoval lists what deleting this sandbox would touch.
//
// It reads the record the same way removal does, rather than its own way. A
// preview built on a stricter reading is worse than none: it stayed silent
// about every grant of a sandbox whose record had stopped parsing, while the
// removal it is previewing would have gone ahead and taken them back from the
// copy behind it.
func previewRemoval(name string, asJSON bool) error {
	s, _, err := recordFor(name, asJSON)
	if err != nil {
		return err
	}
	var actions []plan.Action
	if s != nil {
		for _, g := range s.Grants {
			actions = append(actions, plan.Action{
				Does: "revoke", What: g.Path, Detail: string(g.Kind),
			})
		}
		actions = append(actions,
			plan.Action{Does: "delete", What: s.Temp, Detail: "temporary files"})
	}
	// Named one by one, because they go missing one by one: a record deleted by
	// hand leaves the copy behind it, and a preview that mentions only the one
	// it could read says less than it knows.
	for _, path := range bookkeeping(name) {
		if _, err := os.Stat(path); err == nil {
			actions = append(actions,
				plan.Action{Does: "delete", What: path, Detail: "bookkeeping"})
		}
	}
	if _, exists, err := group.Comment(name); err == nil && exists {
		actions = append(actions, plan.Action{Does: "delete", What: name, Detail: "local group"})
	}
	if accountName := acct.NameFor(name); accountExists(accountName) {
		actions = append(actions,
			plan.Action{Does: "delete", What: sandbox.ProfileDir(name), Detail: "thin profile"},
			plan.Action{Does: "delete", What: accountName, Detail: "local account"})
	}
	text, err := plan.RenderActions(actions, asJSON)
	if err != nil {
		return err
	}
	_, _ = io.WriteString(os.Stdout, text)
	return nil
}
