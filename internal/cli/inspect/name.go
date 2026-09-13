package inspect

import (
	"fmt"

	"wuserbox/internal/sandbox"
)

// nameCmd prints the group name a directory maps to.
func Name(args []string) error {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}
	name, norm, err := sandbox.Name(dir)
	if err != nil {
		return err
	}
	fmt.Printf("%s\t%s\n", name, norm)
	return nil
}
