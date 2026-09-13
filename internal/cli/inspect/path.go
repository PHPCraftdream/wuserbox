package inspect

import (
	"fmt"

	"wuserbox/internal/win/group"
)

// pathCmd prints the directory a group belongs to.
func Path(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: wuserbox path <group>")
	}
	dir, exists, err := group.Comment(args[0])
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("group %s does not exist", args[0])
	}
	fmt.Println(dir)
	return nil
}
