package access

import (
	"fmt"
	"os"

	"github.com/PHPCraftdream/wuserbox/internal/base/lock"
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
	// The record is re-read inside the lock: another command may have changed
	// it between the load above and this point, and writing back what was
	// read before would drop whatever that command recorded.
	//
	// Elevation happens after the lock is let go, because the second wuserbox
	// waits for this very lock.
	if err := apply(s.Group, t); err == nil {
		return nil
	} else if token.IsAdmin() {
		return err
	} else if !t.asJSON {
		// Said out loud only where prose is what the caller asked for. Under
		// --json the answer is one document, and this would come before it.
		fmt.Fprintf(os.Stderr, "wuserbox: %v\n", err)
	}
	return setup.Elevate(t.args("grant"))
}

// apply hands the directory over with the sandbox's record held.
func apply(group string, t target) error {
	return lock.Hold(group, func() error {
		s, err := load(t.project)
		if err != nil {
			return err
		}
		return s.Add(t.path, t.kind)
	})
}
