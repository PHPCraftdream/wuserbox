package setup

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/PHPCraftdream/wuserbox/internal/cli/usage"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox"
	"github.com/PHPCraftdream/wuserbox/internal/win/group"
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
)

// Rm deletes a sandbox: every permission it applied, its temp directory, its
// bookkeeping and the group itself.
func Rm(args []string) error {
	flags := flag.NewFlagSet("rm", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.Usage = func() { io.WriteString(os.Stderr, usage.Text) }
	dir := flags.String("dir", "", "project directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	project := *dir
	if project == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		project = cwd
	}
	if !token.IsAdmin() {
		return Elevate([]string{"rm", "--dir", project})
	}
	name, _, err := sandbox.Name(project)
	if err != nil {
		return err
	}
	if s, err := state.Load(name); err != nil {
		return err
	} else if s != nil {
		for _, g := range s.Grants {
			if err := grant.Revoke(s.SID, g.Path); err != nil {
				fmt.Fprintln(os.Stderr, "wuserbox:", err)
			}
		}
		os.RemoveAll(s.Temp)
		os.Remove(state.Path(name))
	}
	if _, exists, err := group.Comment(name); err != nil {
		return err
	} else if exists {
		return group.Delete(name)
	}
	return nil
}
