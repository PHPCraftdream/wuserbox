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
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/facts"
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
	name, resolved, err := sandbox.Name(project)
	if err != nil {
		return err
	}
	if o.dryRun {
		return previewRemoval(name, o.asJSON)
	}
	if !token.IsAdmin() {
		// The elevated copy derives the sandbox's name from --dir in its own
		// context. It gets the directory this process already resolved, not
		// the spelling it was typed with: a relative path or a drive alias
		// that does not survive the account boundary would otherwise set the
		// child looking beside the sandbox it was meant to remove.
		return Elevate([]string{"--rm", "--dir", resolved})
	}
	// A removal that went ahead under a standing run would take the ground
	// that run stands on -- the profile, the account, the grants -- so it
	// waits on the same slot a run holds and is refused like a second run
	// rather than allowed like a reader. After the elevation check, for the
	// same reason init's is: where the work goes to an elevated copy, that
	// copy takes the slot itself.
	release, err := holdSlot(name)
	if err != nil {
		return err
	}
	defer release()
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
	// Whether anything of this sandbox existed, decided before the deleting
	// starts, because deleting takes the evidence with it. A removal that
	// found a record, a copy of one, or any bookkeeping at all has something
	// real to finish; only a name nothing on the machine answers to found
	// nothing.
	found := s != nil || damaged || anyFileExists(bookkeeping(name))
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
		// With a record, a copy, or bookkeeping behind it, the removal is
		// finished, however an earlier attempt left it half-done. Nothing at
		// all is a different answer: either nothing was ever created under
		// this name, or the name was derived again and landed beside the
		// sandbox it meant -- the second is how an elevated --rm once
		// removed nothing and still reported success over an account, its
		// grants and its profile, all still alive. Reporting success is what
		// let the operator stop there, so nothing found is a failure now.
		if !found {
			return exit.Errorf(exit.Failed,
				"nothing was found to remove for %s: no record, no bookkeeping and no group exist under that name; "+
					"if a sandbox was expected here, it is known under a different name and nothing was touched",
				name)
		}
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
	if err := removeAccountState(name, s, asJSON); err != nil {
		return err
	}
	return group.Delete(name)
}

// removeAccount takes away the sandbox's own local account and everything
// wuserbox put on the machine for it. It works from the group's name alone,
// deriving the account's name the same way ensureAccount does, so a missing
// or damaged record never stands between removal and what it has to remove.
//
// Two rules shape the order, and the second was learned from a profile that
// could not be got rid of.
//
// The account goes last, and only where everything naming it has gone
// first. Its SID is how the ProfileList entry and the profile service
// reference are found, and once the account is deleted that SID resolves to
// nothing: deleting it while one of those is still standing leaves a record
// nothing can look up again.
//
// The profile directory is taken away whether or not there was an account to
// remove. It is derived from the group's name and depends on the account for
// nothing, and the early return that used to stand here -- no account, so
// nothing to do -- meant that an attempt which deleted the account but
// failed on the directory stranded it for good, because every later attempt
// left immediately. A thin profile is about two and a half megabytes; one
// somebody has added to can be gigabytes.
func removeAccount(groupName string, asJSON bool) error {
	return removeAccountState(groupName, nil, asJSON)
}

func removeAccountState(groupName string, s *state.State, asJSON bool) error {
	var left []string
	complain := func(part string, err error) {
		if !asJSON {
			fmt.Fprintln(os.Stderr, "wuserbox:", err)
		}
		left = append(left, part)
	}

	name, err := accountNameForRemoval(groupName, s)
	if err != nil {
		return err
	}
	if name != "" && accountExists(name) {
		value, err := sid.Lookup(name)
		if err != nil {
			return err
		}
		// The record Windows keeps goes before the directory it points at,
		// not after. DeleteProfileW deletes the directory itself where it
		// takes the job, and taking the directory away first leaves it
		// pointing at nothing and refusing -- which is what it did, on every
		// removal, until this was turned around.
		stillNamesIt := false
		if err := acct.DeleteProfile(value.String()); err != nil {
			complain("its ProfileList entry", err)
			stillNamesIt = true
		}
		if err := acct.RemoveProfileServiceReference(value); err != nil {
			complain("its profile service reference", err)
			stillNamesIt = true
		}
		if err := acct.UnhideFromSignIn(name); err != nil {
			complain("its sign-in screen entry", err)
			stillNamesIt = true
		}
		if stillNamesIt {
			// Kept on purpose: its SID is how a second attempt finds what
			// is still standing above.
			left = append(left, "the account itself, kept so a retry can still find the rest")
		} else if err := acct.Delete(name); err != nil {
			complain("the account itself", err)
		}
	}
	// Whatever the account's own removal made of it, and whether or not
	// there was one.
	if err := os.RemoveAll(sandbox.ProfileDir(groupName)); err != nil {
		complain("its profile directory", err)
	}

	if len(left) > 0 {
		return exit.Errorf(exit.Failed,
			"%s was not fully removed and is left in place so `wuserbox --rm` can finish it: %s",
			name, strings.Join(left, ", "))
	}
	return nil
}

// accountNameForRemoval refuses to infer ownership from a colliding name.
// A record's Account field is authoritative for migrated sandboxes; where it
// is absent, the old and current derivations are accepted only after the
// account's group membership and project comment match the group's comment.
func accountNameForRemoval(groupName string, s *state.State) (string, error) {
	if s != nil && s.Account != "" {
		if !accountExists(s.Account) {
			return s.Account, nil
		}
		dir, exists, err := group.Comment(groupName)
		if err != nil {
			return "", err
		}
		if !exists {
			return "", fmt.Errorf("sandbox group %s disappeared while removing its account", groupName)
		}
		ok, err := acct.BelongsTo(s.Account, groupName, dir)
		if err != nil {
			return "", err
		}
		if !ok {
			return "", fmt.Errorf("account %s is not owned by sandbox group %s; refusing to delete it", s.Account, groupName)
		}
		return s.Account, nil
	}
	dir, exists, err := group.Comment(groupName)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", nil
	}
	for _, candidate := range acct.Candidates(groupName) {
		if !accountExists(candidate) {
			continue
		}
		ok, err := acct.BelongsTo(candidate, groupName, dir)
		if err != nil {
			return "", err
		}
		if ok {
			return candidate, nil
		}
		return "", fmt.Errorf("account %s collides with sandbox group %s but belongs to another project; refusing to delete it", candidate, groupName)
	}
	return "", nil
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
	return []string{
		state.Path(name), state.PreviousPath(name),
		facts.UsedMarker(name), facts.SizeCache(name), facts.CopiedList(name),
		facts.PrintsList(name),
	}
}

// anyFileExists reports whether any of the paths still exists.
func anyFileExists(paths []string) bool {
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
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
	if err := grant.Revoke(account, dir, nil); err != nil {
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
		if err := grant.Revoke(s.SID, g.Path, nil); err != nil {
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
	if accountName, err := accountNameForRemoval(name, s); err != nil {
		return err
	} else if accountName != "" && accountExists(accountName) {
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
