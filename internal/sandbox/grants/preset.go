package grants

import (
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/policy/preset"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
)

// DropPreset takes back every permission the agent preset handed out,
// including the profile root. It runs when a sandbox that already exists is
// started with the preset switched off, so the flag narrows the sandbox
// instead of being quietly ignored on every run after the first.
func DropPreset(s *state.State) error {
	unwanted := map[string]bool{strings.ToLower(preset.Home().Path): true}
	for _, spec := range preset.AI() {
		unwanted[strings.ToLower(spec.Path)] = true
	}
	for _, granted := range append([]string(nil), pathsOf(s)...) {
		if !unwanted[strings.ToLower(granted)] {
			continue
		}
		if err := s.Remove(granted); err != nil {
			return err
		}
	}
	return nil
}

func pathsOf(s *state.State) []string {
	out := make([]string, 0, len(s.Grants))
	for _, g := range s.Grants {
		out = append(out, g.Path)
	}
	return out
}
