package state

import (
	"errors"
	"runtime"
	"sync"

	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
)

// OfferMany hands over several directories at once, and is how a sandbox is
// built without the wait being the sum of its parts.
//
// Handing a directory over means rewriting the access list of every file
// already inside it, because Windows copies an inheritable entry down rather
// than looking upwards when it is asked. On a working machine that is tens of
// thousands of files for the agent directories alone, and doing them one after
// another takes as long as all of them added together. They are independent of
// each other, so they are done at the same time and the wait becomes the
// largest single tree rather than the total.
//
// What is recorded is written once before the work and once after, rather than
// once per directory: the marks say a change was begun, so a run stopped in the
// middle is finished by the next one either way.
//
// Only offers are taken this way, and only the kinds that hand something over.
// Narrowing reaches inside a directory and changes the record as it goes, which
// is not something to do from several threads at once.
func (s *State) OfferMany(specs []grant.Spec) error {
	wanted := make([]grant.Spec, 0, len(specs))
	for _, spec := range specs {
		if !spec.Kind.Writable() {
			return s.oneByOne(specs)
		}
		if index, found := s.find(spec.Path); found &&
			(s.Grants[index].Explicit || (s.Grants[index].Kind == spec.Kind && !s.Grants[index].Pending)) {
			// Somebody has said otherwise about this path, or it is already
			// held and finished: either way there is nothing to do.
			continue
		}
		wanted = append(wanted, grant.Spec{Path: spec.Path, Kind: spec.Kind, Pending: true})
	}
	if len(wanted) == 0 {
		return nil
	}

	before := append([]grant.Spec(nil), s.Grants...)
	for _, spec := range wanted {
		if index, found := s.find(spec.Path); found {
			s.Grants[index].Kind = spec.Kind
			s.Grants[index].Pending = true
		} else {
			s.Grants = append(s.Grants, spec)
		}
	}
	if err := s.Save(); err != nil {
		s.Grants = before
		return err
	}
	if err := ApplyTogether(s.SID, wanted); errors.Is(err, acl.ErrNotLabeled) {
		// The permissions are in force and only the labels are missing, which
		// is recorded rather than treated as a failure: it is what a later run
		// repairs with the rights writing them needs.
		s.Labeled = false
	} else if err != nil {
		// The record keeps the marks: it claims more than is in force, which
		// the next run finishes and explain reports meanwhile. That is the
		// harmless way round, so the error is worth reporting as it is.
		return err
	}
	for _, spec := range wanted {
		if index, found := s.find(spec.Path); found {
			s.Grants[index].Pending = false
		}
	}
	return s.Save()
}

// oneByOne is the ordinary path, for anything OfferMany will not take.
func (s *State) oneByOne(specs []grant.Spec) error {
	for _, spec := range specs {
		if err := s.Offer(spec.Path, spec.Kind); err != nil {
			return err
		}
	}
	return nil
}

// ApplyTogether applies permissions on several paths at the same time, a few
// at once rather than all of them: each one keeps a whole directory tree busy,
// and the disk is the limit long before the processor is.
func ApplyTogether(account string, specs []grant.Spec) error {
	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8
	}
	if workers > len(specs) {
		workers = len(specs)
	}
	queue := make(chan grant.Spec)
	failures := make(chan error, len(specs))
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for spec := range queue {
				if err := grant.Apply(account, spec.Path, spec.Kind); err != nil {
					failures <- err
				}
			}
		}()
	}
	for _, spec := range specs {
		queue <- spec
	}
	close(queue)
	wg.Wait()
	close(failures)

	// A missing label is kept apart from a real failure. Joined together the
	// two cannot be told from one another afterwards, and reading a genuine
	// refusal as "only the label" would report a permission as in force when
	// it never went on.
	var all []error
	unlabeled := false
	for err := range failures {
		if errors.Is(err, acl.ErrNotLabeled) {
			unlabeled = true
			continue
		}
		all = append(all, err)
	}
	if len(all) > 0 {
		return errors.Join(all...)
	}
	if unlabeled {
		return acl.ErrNotLabeled
	}
	return nil
}
