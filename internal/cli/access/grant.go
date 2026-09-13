package access

import (
	"fmt"
	"os"

	"wuserbox/internal/cli/setup"
	"wuserbox/internal/win/token"
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
	if err := s.Add(t.path, t.kind); err == nil {
		return nil
	} else if token.IsAdmin() {
		return err
	} else {
		fmt.Fprintf(os.Stderr, "wuserbox: %v\n", err)
	}
	return setup.Elevate(t.args("grant"))
}
