package state

import (
	"os"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
)

// FinishPending applies every change the record says was begun and never
// finished, and is how a sandbox is made trustworthy again after a command was
// interrupted.
//
// The record is written before the permission is applied, so that a permission
// can never be in force with nothing pointing at it. The cost of that order is
// the gap on the other side: a process stopped in between leaves a record
// saying read-only while the entries still say writable. Finishing the change
// closes it, and finishing is safe to repeat, because applying a permission
// twice is the same as applying it once.
func (s *State) FinishPending() error {
	for _, listed := range append([]grant.Spec(nil), s.Grants...) {
		// The list is walked over a copy, and finishing one entry can change
		// the record: narrowing a directory takes back what the sandbox holds
		// inside it. So each entry is looked up again before it is acted on,
		// or an entry already taken back would be handed out afresh from a
		// list made before that happened.
		held, still := s.current(listed.Path)
		if !still || !held.Pending {
			continue
		}
		if err := s.finish(held); err != nil {
			return err
		}
	}
	return nil
}

// finish carries out one marked change: applies it, reaches inside it when it
// is a refusal, and only then takes the mark off.
//
// The order is the same one a change follows when it is made, and for the same
// reason: the mark stands for the whole of it, so a stop between the halves has
// to leave the mark standing.
func (s *State) finish(held grant.Spec) error {
	if _, err := os.Stat(held.Path); os.IsNotExist(err) {
		// There is nothing to apply it to, and a record claiming a directory
		// that is gone helps nobody.
		return s.forget(held.Path)
	}
	if err := grant.Apply(s.SID, held.Path, held.Kind); err != nil {
		return err
	}
	if !held.Kind.Writable() {
		if err := s.narrow(held.Path); err != nil {
			return err
		}
	}
	return s.settle(held.Path)
}

// current reads back what the record says about a path now.
func (s *State) current(path string) (grant.Spec, bool) {
	index, found := s.find(path)
	if !found {
		return grant.Spec{}, false
	}
	return s.Grants[index], true
}

// settle records that a change has reached the file system.
func (s *State) settle(path string) error {
	index, found := s.find(path)
	if !found || !s.Grants[index].Pending {
		return nil
	}
	s.Grants[index].Pending = false
	return s.Save()
}

// narrow takes back everything the sandbox holds inside a directory that has
// just been made read-only.
//
// A permission of its own on a subdirectory beats a refusal inherited from the
// directory above it: Windows reads an entry set directly on an object before
// any entry handed down to it. So a sandbox told to read ~/.config and no more
// went on writing ~/.config/rush, which the agent preset had handed over
// separately, and the promise that a read-only directory is read-only through
// and through was not kept.
//
// The project directory and the sandbox's own temp directory are left alone.
// They are why the sandbox exists, and a project that happens to sit inside a
// directory being narrowed is not what anyone means to take away.
func (s *State) narrow(path string) error {
	for _, listed := range append([]grant.Spec(nil), s.Grants...) {
		// The list is walked over a copy, for the same reason FinishPending
		// walks one: narrowing one entry can recurse into finish, which can
		// narrow a directory inside it and remove entries this loop has not
		// reached yet. Without looking each one up again, this loop would act
		// on an entry a nested call already took back, and find it gone.
		held, still := s.current(listed.Path)
		if !still || !inside(held.Path, path) || s.isOwn(held.Path) {
			continue
		}
		if !held.Kind.Writable() {
			// A refusal of its own is not what beats the refusal from above:
			// it says the same thing. Taking it away would quietly cost the
			// directory its own restriction, and widening the parent later
			// would then make it writable.
			//
			// Unless it was never applied. A refusal written down and
			// interrupted before it reached the file system still allows
			// writing, and passing over it would leave this narrowing
			// reporting success over a directory the sandbox can still write.
			if held.Pending {
				if err := s.finish(held); err != nil {
					return err
				}
			}
			continue
		}
		if _, err := os.Stat(held.Path); os.IsNotExist(err) {
			// Nothing to take back, but the record should not keep claiming it.
			if err := s.forget(held.Path); err != nil {
				return err
			}
			continue
		}
		if err := s.Remove(held.Path); err != nil {
			return err
		}
	}
	return nil
}

// isOwn reports whether a path is one the sandbox is built around.
func (s *State) isOwn(path string) bool {
	return strings.EqualFold(path, s.Dir) || strings.EqualFold(path, s.Temp)
}

// forget drops a permission from the record without touching the file system.
func (s *State) forget(path string) error {
	index, found := s.find(path)
	if !found {
		return nil
	}
	s.Grants = append(s.Grants[:index], s.Grants[index+1:]...)
	return s.Save()
}

// inside reports whether child sits under parent. A path is not inside itself.
func inside(child, parent string) bool {
	prefix := strings.TrimSuffix(strings.ToLower(parent), `\`) + `\`
	return strings.HasPrefix(strings.ToLower(child), prefix)
}
