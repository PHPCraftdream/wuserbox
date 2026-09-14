package access

import (
	"fmt"
	"os"

	"github.com/PHPCraftdream/wuserbox/internal/cli/setup"
	"github.com/PHPCraftdream/wuserbox/internal/lock"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/plan"
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
)

// Revoke takes one directory back from the sandbox of a project.
func Revoke(args []string) error {
	t, err := parseTarget("revoke", args)
	if err != nil {
		return err
	}
	s, err := load(t.project)
	if err != nil {
		return err
	}
	if t.dryRun {
		if !s.Has(t.path) {
			return t.preview()
		}
		return t.preview(plan.Action{Does: "revoke", What: t.path, Detail: "from " + s.Group})
	}
	// As in grant: the record is re-read inside the lock, and elevation
	// happens outside it, because the second wuserbox waits for the same lock.
	if err := withdraw(s.Group, t); err == nil {
		return nil
	} else if token.IsAdmin() {
		return err
	} else {
		fmt.Fprintf(os.Stderr, "wuserbox: %v\n", err)
	}
	return setup.Elevate([]string{"revoke", t.path, "--dir", t.project})
}

// withdraw takes the directory back with the sandbox's record held.
func withdraw(group string, t target) error {
	return lock.Hold(group, func() error {
		s, err := load(t.project)
		if err != nil {
			return err
		}
		return s.Remove(t.path)
	})
}
