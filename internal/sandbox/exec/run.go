// Package exec starts a command inside a prepared sandbox.
package exec

import (
	"os"

	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/win/proc"
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
)

// Run executes a command in the sandbox described by s and returns its exit
// code. Temporary files are redirected into the sandbox's own directory, so
// scratch work never needs access to the user's profile.
func Run(s *state.State, commandLine string) (int, error) {
	restricted, err := token.Restricted(s.SID)
	if err != nil {
		return -1, err
	}
	defer restricted.Close()

	_ = os.Setenv("TEMP", s.Temp)
	_ = os.Setenv("TMP", s.Temp)
	_ = os.Setenv("WUSERBOX_GROUP", s.Group)
	_ = os.Setenv("WUSERBOX_DIR", s.Dir)
	return proc.Run(restricted, commandLine, s.Dir)
}
