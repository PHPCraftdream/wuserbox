package setup

import (
	"fmt"

	"github.com/PHPCraftdream/wuserbox/internal/win/proc"
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
)

// Elevate re-runs wuserbox with administrator rights and reports a non-zero
// exit as an error.
//
// A sandboxed process must never reach this: asking for administrator rights
// is exactly how it would escape, and the user would face a prompt they never
// asked for.
func Elevate(args []string) error {
	if token.IsRestricted() {
		return fmt.Errorf("refusing to ask for administrator rights from inside a sandbox")
	}
	code, err := proc.Elevate(args)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("`wuserbox %s` failed with exit code %d when run as administrator", args[0], code)
	}
	return nil
}
