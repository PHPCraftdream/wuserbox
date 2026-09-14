package grants

import (
	"os"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
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
	// A project can sit inside one of those directories, and then the preset
	// and the project name the same path. The project is why the sandbox
	// exists, so it is never what a flag about agent directories takes away.
	delete(unwanted, strings.ToLower(s.Dir))
	delete(unwanted, strings.ToLower(s.Temp))
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

// Reapply puts every recorded permission back on the file system, whatever
// the record claims about it. It is how init repairs a sandbox whose entries
// were changed or removed behind its back.
//
// Applied straight from the record, and several at a time: putting a
// permission back does not change what the record says about it, including
// whether it was asked for by hand, so nothing here has to be serialized.
func Reapply(s *state.State) error {
	var present []grant.Spec
	for _, held := range s.Grants {
		if _, err := os.Stat(held.Path); err != nil {
			continue // gone; the record is kept, there is nothing to apply to
		}
		present = append(present, held)
	}
	return state.ApplyTogether(s.SID, present)
}

// ApplyPreset hands over the agent directories, and the profile root when it
// was asked for. It runs on every start, not only the first, so the flags mean
// the same thing whenever they are used: a plain run after one with --no-ai
// gets the directories back, and --home-writes reaches a sandbox that was
// built without it.
func ApplyPreset(s *state.State, homeWrites bool) error {
	// Handed over together: see State.OfferMany for why that matters.
	if err := s.OfferMany(preset.AI()); err != nil {
		return err
	}
	if !homeWrites {
		return nil
	}
	if _, err := ReserveSensitiveNames(); err != nil {
		return err
	}
	home := preset.Home()
	if err := s.Add(home.Path, home.Kind); err != nil {
		return err
	}
	return RefuseHomeFiles(s)
}
