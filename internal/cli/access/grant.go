package access

import (
	"fmt"
	"os"

	"github.com/PHPCraftdream/wuserbox/internal/cli/setup"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/plan"
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
)

// Grant lets the sandbox of a project write to, or read, one more directory.
func Grant(args []string) error {
	t, err := parseTarget("grant", args)
	if err != nil {
		return err
	}
	s, err := load(t.project)
	if err != nil {
		return err
	}
	if t.dryRun {
		if kind, held := s.Kind(t.path); held && kind == t.kind {
			return t.preview()
		}
		return t.preview(plan.Action{Does: "grant", What: t.path, Detail: string(t.kind) + " for " + s.Group})
	}
	if err := s.Add(t.path, t.kind); err == nil {
		return nil
	} else if token.IsAdmin() {
		return err
	} else {
		fmt.Fprintf(os.Stderr, "wuserbox: %v\n", err)
	}
	return setup.Elevate(t.args("grant"))
}
