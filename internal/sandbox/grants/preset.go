package grants

import (
	"os"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/policy/preset"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
)

// DropPreset takes back the profile-root grant the agent preset hands out
// when --home-writes is asked for. It runs when a sandbox that already
// exists is started with the preset switched off, so the flag narrows the
// sandbox instead of being quietly ignored on every run after the first.
//
// It no longer has real agent directories to take back: those are never
// granted in the first place now that a sandbox's own profile is filled by
// copying instead. RetireAIGrants is what clears a grant a sandbox built
// before that existed still holds, and it runs regardless of this flag.
func DropPreset(s *state.State) error {
	unwanted := map[string]bool{strings.ToLower(preset.Home().Path): true}
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

// RetireAIGrants takes back direct write access to the real agent
// directories a sandbox built before profile copying existed may still
// hold.
//
// A sandbox's own profile is what supplies that state now, filled by a copy
// -- see policy/profile.Copy, called on every run. Holding both would leave
// the sandbox able to reach the real directories directly regardless of what
// its profile was given, which is not a boundary at all; it is called
// unconditionally, whether or not the agent preset is wanted, because the
// question it answers -- does this sandbox still hold a grant nothing hands
// out any more -- does not depend on that flag.
func RetireAIGrants(s *state.State) error {
	unwanted := make(map[string]bool, len(preset.AI()))
	for _, spec := range preset.AI() {
		unwanted[strings.ToLower(spec.Path)] = true
	}
	// A project can sit inside, or exactly at, one of those directories, and
	// then the preset and the project name the same path. The project is why
	// the sandbox exists, so it is never what retiring a preset grant takes
	// away.
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

// ApplyPreset hands over the profile root, when it was asked for, and takes
// back a legacy grant on the real agent directories if one is still held. It
// runs on every start, not only the first, so --home-writes reaches a
// sandbox that was built without it, the same as before.
//
// It no longer hands over the real agent directories themselves. A sandbox's
// own profile is what supplies that state, filled by policy/profile.Copy on
// every run; granting the real ones as well would let the sandbox reach them
// directly; whatever its profile actually holds.
func ApplyPreset(s *state.State, homeWrites bool) error {
	if err := RetireAIGrants(s); err != nil {
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
