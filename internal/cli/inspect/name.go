package inspect

import (
	"fmt"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/exit"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox"
)

// nameCmd prints the group name a directory maps to.
func Name(args []string) error {
	dir := "."
	if len(args) > 1 {
		return exit.Errorf(exit.Usage, "usage: wuserbox name [dir]")
	}
	if len(args) == 1 {
		if strings.HasPrefix(args[0], "-") {
			return exit.Errorf(exit.Usage, "usage: wuserbox name [dir]")
		}
		dir = args[0]
	}
	name, norm, err := sandbox.Name(dir)
	if err != nil {
		return err
	}
	fmt.Printf("%s\t%s\n", name, norm)
	return nil
}
