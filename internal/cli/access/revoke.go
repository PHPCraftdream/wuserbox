package access

import (
	"fmt"
	"os"

	"github.com/PHPCraftdream/wuserbox/internal/cli/setup"
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
	if err := s.Remove(t.path); err == nil {
		return nil
	} else if token.IsAdmin() {
		return err
	} else {
		fmt.Fprintf(os.Stderr, "wuserbox: %v\n", err)
	}
	return setup.Elevate([]string{"revoke", t.path, "--dir", t.project})
}
