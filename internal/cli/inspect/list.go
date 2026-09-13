package inspect

import (
	"fmt"

	"github.com/PHPCraftdream/wuserbox/internal/exit"
	"github.com/PHPCraftdream/wuserbox/internal/win/group"
)

// listCmd prints every sandbox on this machine.
func List(args []string) error {
	if len(args) > 0 {
		return exit.Errorf(exit.Usage, "usage: wuserbox list")
	}
	entries, err := group.List()
	if err != nil {
		return err
	}
	for _, e := range entries {
		fmt.Printf("%s\t%s\n", e.Name, e.Dir)
	}
	return nil
}
