package inspect

import (
	"fmt"

	"wuserbox/internal/win/group"
)

// listCmd prints every sandbox on this machine.
func List(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("usage: wuserbox list")
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
