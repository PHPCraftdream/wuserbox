package setup

import (
	"fmt"

	"github.com/PHPCraftdream/wuserbox/internal/sandbox"
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
)

// Init creates the sandbox for a directory, asking for administrator rights
// first, because a local group cannot be created without them.
func Init(args []string) error {
	options, _, err := ParseOptions("init", args)
	if err != nil {
		return err
	}
	if !token.IsAdmin() {
		return Elevate(options.Args())
	}
	s, err := sandbox.Init(options)
	if err != nil {
		return err
	}
	fmt.Printf("%s\t%s\n", s.Group, s.Dir)
	return nil
}
