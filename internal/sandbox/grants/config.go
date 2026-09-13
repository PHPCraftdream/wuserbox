// Package grants applies the permission decisions a sandbox is built from.
package grants

import (
	"os"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
)

// FromConfig grants the directories the standing rules list for this project.
// Entries that no longer exist on disk are skipped instead of failing the run.
func FromConfig(s *state.State) error {
	rules, err := config.Load()
	if err != nil {
		return err
	}
	for _, spec := range rules.GrantsFor(s.Dir) {
		if _, err := os.Stat(spec.Path); err != nil {
			continue
		}
		if err := s.Add(spec.Path, spec.Kind); err != nil {
			return err
		}
	}
	return nil
}
