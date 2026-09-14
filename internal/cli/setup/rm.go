package setup

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/cli/usage"
	"github.com/PHPCraftdream/wuserbox/internal/exit"
	"github.com/PHPCraftdream/wuserbox/internal/lock"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/plan"
	"github.com/PHPCraftdream/wuserbox/internal/win/group"
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
)

// Rm deletes a sandbox: every permission it applied, its temp directory, its
// bookkeeping and the group itself.
func Rm(args []string) error {
	flags := flag.NewFlagSet("rm", flag.ContinueOnError)
	usage.Quiet(flags)
	dir := flags.String("dir", "", "project directory")
	dryRun := flags.Bool("dry-run", false, "show what would change, change nothing")
	asJSON := flags.Bool("json", false, "print the result as JSON")
	nonInteractive := flags.Bool("non-interactive", false,
		"fail instead of asking for administrator rights")
	if err := flags.Parse(args); err != nil {
		return exit.Errorf(exit.Usage, "%v", err)
	}
	// The project is named with --dir, never as a plain argument. Taking one
	// silently would remove the sandbox of the current directory while the
	// command line says another, and this command deletes things.
	if flags.NArg() > 0 {
		return exit.Errorf(exit.Usage,
			"wuserbox rm takes no directory as an argument; "+
				"name the project with --dir %s", flags.Arg(0))
	}
	if *nonInteractive {
		_ = os.Setenv(EnvNonInteractive, "1")
	}
	project := *dir
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
	if *dryRun {
		return previewRemoval(name, *asJSON)
	}
	if !token.IsAdmin() {
		return Elevate([]string{"rm", "--dir", project})
	}
	return removeSandbox(name)
}

// removeSandbox does the deleting, once the right to do it is established.
// The record is held throughout, so a command handing the sandbox another
// directory cannot write that permission back into a record being deleted.
func removeSandbox(name string) error {
	return lock.Hold(name, func() error { return remove(name) })
}

func remove(name string) error {
	if s, err := state.Load(name); err != nil {
		return err
	} else if s != nil {
		if left := clearGrants(s); len(left) > 0 {
			// The record is the only list of what is still in force, and the
			// group is what those entries name. Keeping both is what makes a
			// second attempt able to finish; deleting them would leave
			// permissions behind that nothing can find again.
			return exit.Errorf(exit.Failed,
				"%s was not fully removed and is left in place so `wuserbox rm` can finish it: %s",
				name, strings.Join(left, ", "))
		}
		if err := os.Remove(state.Path(name)); err != nil && !os.IsNotExist(err) {
			return exit.Errorf(exit.Failed,
				"the permissions of %s are revoked, but its record at %s remains: %v",
				name, state.Path(name), err)
		}
	}
	if _, exists, err := group.Comment(name); err != nil {
		return err
	} else if exists {
		return group.Delete(name)
	}
	return nil
}

// clearGrants revokes everything the sandbox holds and deletes its temp
// directory, and names whatever would not go.
//
// Every step is attempted even after one fails, so a single stubborn
// directory does not leave the rest of the permissions in force.
func clearGrants(s *state.State) []string {
	var left []string
	for _, g := range s.Grants {
		// A directory that is no longer there holds no entries, so there is
		// nothing left to take back. Counting it as a failure would leave
		// every later attempt failing on the same missing path, and the
		// sandbox could never be removed at all.
		if _, err := os.Stat(g.Path); os.IsNotExist(err) {
			continue
		}
		if err := grant.Revoke(s.SID, g.Path); err != nil {
			fmt.Fprintln(os.Stderr, "wuserbox:", err)
			left = append(left, g.Path)
		}
	}
	if err := os.RemoveAll(s.Temp); err != nil {
		fmt.Fprintln(os.Stderr, "wuserbox:", err)
		left = append(left, s.Temp)
	}
	return left
}

// previewRemoval lists what deleting this sandbox would touch.
func previewRemoval(name string, asJSON bool) error {
	var actions []plan.Action
	if s, err := state.Load(name); err == nil && s != nil {
		for _, g := range s.Grants {
			actions = append(actions, plan.Action{
				Does: "revoke", What: g.Path, Detail: string(g.Kind),
			})
		}
		actions = append(actions,
			plan.Action{Does: "delete", What: s.Temp, Detail: "temporary files"},
			plan.Action{Does: "delete", What: state.Path(name), Detail: "bookkeeping"})
	}
	if _, exists, err := group.Comment(name); err == nil && exists {
		actions = append(actions, plan.Action{Does: "delete", What: name, Detail: "local group"})
	}
	text, err := plan.RenderActions(actions, asJSON)
	if err != nil {
		return err
	}
	_, _ = io.WriteString(os.Stdout, text)
	return nil
}
