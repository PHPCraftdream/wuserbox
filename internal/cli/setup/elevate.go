package setup

import (
	"os"

	"github.com/PHPCraftdream/wuserbox/internal/exit"
	"github.com/PHPCraftdream/wuserbox/internal/win/proc"
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
)

// EnvNonInteractive switches off consent prompts for the whole process. The
// command line sets it, and it is passed to the elevated copy, so a script can
// set it once instead of repeating the flag.
const EnvNonInteractive = "WUSERBOX_NON_INTERACTIVE"

// Elevate re-runs wuserbox with administrator rights and reports a non-zero
// exit as an error.
//
// A sandboxed process must never reach this: asking for administrator rights
// is exactly how it would escape, and the user would face a prompt they never
// asked for. Automation must not reach it either, for a duller reason: a
// consent dialog nobody can click stops the script until it is killed.
func Elevate(args []string) error {
	if token.IsRestricted() {
		return exit.Errorf(exit.Denied,
			"refusing to ask for administrator rights from inside a sandbox")
	}
	if os.Getenv(EnvNonInteractive) != "" {
		return exit.Errorf(exit.NeedsElevation,
			"`wuserbox %s` needs administrator rights, and prompts are switched off; "+
				"run it once in an elevated terminal, or drop --non-interactive", args[0])
	}
	code, err := proc.Elevate(args)
	if err != nil {
		return err
	}
	if code != 0 {
		return exit.Errorf(exit.Code(code),
			"`wuserbox %s` failed with exit code %d when run as administrator", args[0], code)
	}
	return nil
}
