package setup

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/PHPCraftdream/wuserbox/internal/cli/usage"
	"github.com/PHPCraftdream/wuserbox/internal/exit"
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
	flags.SetOutput(os.Stderr)
	flags.Usage = func() { _, _ = io.WriteString(os.Stderr, usage.Text) }
	dir := flags.String("dir", "", "project directory")
	dryRun := flags.Bool("dry-run", false, "show what would change, change nothing")
	asJSON := flags.Bool("json", false, "print the result as JSON")
	nonInteractive := flags.Bool("non-interactive", false,
		"fail instead of asking for administrator rights")
	if err := flags.Parse(args); err != nil {
		return exit.Errorf(exit.Usage, "%v", err)
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
	if s, err := state.Load(name); err != nil {
		return err
	} else if s != nil {
		for _, g := range s.Grants {
			if err := grant.Revoke(s.SID, g.Path); err != nil {
				fmt.Fprintln(os.Stderr, "wuserbox:", err)
			}
		}
		if err := os.RemoveAll(s.Temp); err != nil {
			fmt.Fprintln(os.Stderr, "wuserbox:", err)
		}
		if err := os.Remove(state.Path(name)); err != nil && !os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, "wuserbox:", err)
		}
	}
	if _, exists, err := group.Comment(name); err != nil {
		return err
	} else if exists {
		return group.Delete(name)
	}
	return nil
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
