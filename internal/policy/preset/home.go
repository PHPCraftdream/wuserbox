package preset

import (
	"os"
	"path/filepath"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
)

// Home returns the grant for the profile root when the caller asks for it
// explicitly. It lets an agent create files there, which some need in order to
// rewrite a dotfile through a temporary file and a rename.
//
// It is not part of the default preset: the same permission is inherited by
// every file already in the profile root, which puts shell startup files and
// credentials within reach. Callers that use it must refuse the sensitive
// files separately.
func Home() grant.Spec {
	return grant.Spec{Path: paths.Home(), Kind: grant.HomeTop}
}

// HomeFiles lists the files sitting directly in the profile root. They are the
// ones a permission on the profile root would reach.
func HomeFiles() []string {
	home := paths.Home()
	entries, err := os.ReadDir(home)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			out = append(out, filepath.Join(home, e.Name()))
		}
	}
	return out
}
