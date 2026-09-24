package setup

import (
	"fmt"

	"github.com/PHPCraftdream/wuserbox/internal/base/exit"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/grants"
)

// ReInit restores the default profile copy list without changing grants.
func ReInit(args []string) error {
	if len(args) != 0 {
		return exit.Errorf(exit.Usage, "usage: wuserbox --re-init")
	}
	backup, err := grants.ResetProfile()
	if err != nil {
		return err
	}
	if backup != "" {
		fmt.Printf("profile copy rules restored; previous rules backed up to %s; project grants unchanged\n", backup)
	} else {
		fmt.Println("profile copy rules created from defaults; no previous rules to back up")
	}
	return nil
}
