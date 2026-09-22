// Narrowing the tree under a directory that has just been handed over.
//
// Rewriting the directory itself is not enough: an object inside it whose
// permissions are its own no longer hears from above, so whatever Everyone,
// BUILTIN\Users, or Authenticated Users hold there survives the grant and
// every sandbox that holds the tree can write through it. The whole tree is
// read before any of it is changed, so the ordinary reason to stop happens
// before anything has moved.

package acl

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

// sweep takes the changing rights of Everyone, BUILTIN\Users and
// Authenticated Users away from everything under path that holds them in
// its own entries.
//
// These are the same three identities the granted directory itself is
// narrowed against in Isolate, so the walk below answers the question the
// top already answered.
//
// Everything the sandbox's own account owns under path is written whole --
// its entries, the hand-down, and the cap -- because a list written
// individually no longer hears from above (owner.go). Everything else keeps
// its own entries narrowed and the rest arriving from the top, which is what
// lets taking the grant away reach it later.
//
// Rewriting the directory at the top is not enough on its own. Windows hands
// an inheritable entry down to what is below, but handing it down only
// replaces the handed-down part of a child's list and leaves the child's own
// entries alone — so a directory inside a granted one, carrying an entry of
// its own that lets Users write, stayed writable by every other sandbox.
// Measured, with a peer writing there after the grant.
//
// What is below is not pinned the way the top is -- except where it has to
// be. Objects the sandbox's own account owns are written whole, the hand-down
// included, because their lists stop hearing from above the moment they are
// individually written; taking the grant away reaches them by name, through
// the same Prune that reaches a grant pinned deeper still. Everything else
// keeps its own entries narrowed and the rest arriving from the top.
//
// pinned is the record's paths for this sandbox, keyed by filesystem entry,
// and it decides which owned objects are spared: a path recorded there was
// granted by the operator in their own right, and no list the sandbox could
// have written may stand in for that decision (owner.go).
func sweep(root string, sandbox *identities, hand []explicitAccess, pinned pinnedPaths) error {
	// Read the whole tree before changing any of it. Doing both in one pass
	// left a failure halfway down with part of the tree already rewritten and
	// the grant not written at all: narrowings nobody asked for and no record
	// anywhere that they happened. Reading first is not a promise -- the tree
	// can change underneath between the passes -- but it turns the ordinary
	// reason for stopping, an entry of a kind that cannot be carried over,
	// into a refusal before anything has moved.
	if err := inspect(root, sandbox.values, pinned); err != nil {
		return err
	}
	return narrowTree(root, sandbox, hand, pinned)
}

// narrowTree reads objects in parallel, but publishes ACL changes in the
// order filepath.WalkDir presents them. Most objects need no change: their
// own ACL has no changing grant, or they already carry the exact owner cap.
// Those decisions can be made from a parallel read. Objects that may need a
// write are read again by narrowOwn immediately before the ordered write; the
// reread is what preserves the parent-before-child dependency when a parent
// changes inherited permissions.
func narrowTree(root string, sandbox *identities, hand []explicitAccess, pinned pinnedPaths) error {
	_, err := orderedNarrow(root, dispatchWindow(),
		func(path string) (narrowDecision, error) {
			return classifyNarrow(path, root, sandbox, hand, pinned)
		},
		func(path string) error {
			return narrowOwn(path, root, sandbox, hand, pinned)
		})
	return err
}

// dispatchWindow is how far a real sweep lets the walk run ahead of the
// writer: two objects for each worker, the same measure the channels are cut
// to. The credits below, not these channels, are what hold the walk to it.
func dispatchWindow() int {
	return workers() * 2
}

// orderedNarrow walks root the way filepath.WalkDir does, asks classify of
// every object on the workers, and gives the answers to one writer, which
// applies them in walk order: a parent is published before whatever is inside
// it, and a publish re-reads the object first, so what it writes is the list
// as the walk left it.
//
// The channels being bounded is not what keeps this run bounded. The writer
// reads whatever result arrives, ahead of its place in the order or not, and
// one slow early answer would otherwise leave the workers free to carry every
// object in the tree into that wait, each as a held path. So the walk runs on
// credits instead: a dispatched object holds one until the writer commits it,
// and the walk stops dispatching when none are left, however eagerly the
// workers would take more.
//
// A pinned directory is what the old sequential walk answered with SkipDir.
// Results for its descendants may already be in flight, so the writer holds
// the root and discards them -- the one root whose subtree the writer is
// still inside, not the whole skip history. The walk never returns to a
// subtree it has left and the writer commits strictly in walk order, so the
// first commit outside a held root says every later commit is outside too.
// The comparison is the filesystem's own spelling, byte for byte at the
// component boundary: no Unicode folding, and a name that merely begins with
// the held one is not inside it.
//
// window is how far ahead of the writer the walk may run; at least one. What
// comes back with the error is the most the writer ever held at once, the
// number window promises to cap.
func orderedNarrow(root string, window int, classify func(string) (narrowDecision, error), apply func(string) error) (int, error) {
	type object struct {
		seq  uint64
		path string
	}
	type result struct {
		seq      uint64
		path     string
		decision narrowDecision
		err      error
	}

	jobs := make(chan object, window)
	results := make(chan result, window)
	stop := make(chan struct{})
	var stopOnce sync.Once
	cancel := func() { stopOnce.Do(func() { close(stop) }) }

	credits := make(chan struct{}, window)
	for i := 0; i < window; i++ {
		credits <- struct{}{}
	}

	var hands sync.WaitGroup
	for i := 0; i < workers(); i++ {
		hands.Add(1)
		go func() {
			defer hands.Done()
			for {
				select {
				case <-stop:
					return
				case one, ok := <-jobs:
					if !ok {
						return
					}
					decision, err := classify(one.path)
					answer := result{seq: one.seq, path: one.path, decision: decision, err: err}
					select {
					case results <- answer:
					case <-stop:
						return
					}
				}
			}
		}()
	}

	walkDone := make(chan error, 1)
	go func() {
		defer close(jobs)
		var seq uint64
		walkErr := walkTree(root, func(path string, _ fs.DirEntry) error {
			select {
			case <-credits:
			case <-stop:
				return filepath.SkipAll
			}
			one := object{seq: seq, path: path}
			select {
			case jobs <- one:
				seq++
				return nil
			case <-stop:
				return filepath.SkipAll
			}
		})
		walkDone <- walkErr
	}()
	go func() {
		hands.Wait()
		close(results)
	}()

	// The writer is where the order exists, and the only place a credit
	// comes back.
	var skipped string
	pending := make(map[uint64]result)
	var next uint64
	var held, most int
	var failure error
	failed := false
	for answer := range results {
		if failed {
			continue
		}
		pending[answer.seq] = answer
		held++
		if held > most {
			most = held
		}
		for {
			one, ok := pending[next]
			if !ok {
				break
			}
			delete(pending, next)
			next++
			held--
			credits <- struct{}{}
			if skipped != "" && underSkipped(one.path, skipped) {
				continue
			}
			// This answer is outside the subtree the writer was inside, and
			// no later one can be back inside it.
			skipped = ""
			if one.err != nil {
				failure = one.err
				failed = true
				cancel()
				break
			}
			switch one.decision {
			case narrowSkip:
				skipped = one.path
			case narrowApply:
				if err := apply(one.path); err != nil {
					failure = err
					failed = true
					cancel()
				}
			}
			if failed {
				break
			}
		}
	}
	walkErr := <-walkDone
	if failure != nil {
		return most, failure
	}
	return most, walkErr
}

// underSkipped reports whether path is inside the skipped root the writer is
// still holding.
func underSkipped(path, root string) bool {
	// Both spellings come from the same WalkDir traversal. Do not use
	// filepath.Rel here: on Windows it applies Unicode EqualFold and
	// treats the distinct K and Kelvin-sign directory names as one.
	return len(path) > len(root) && strings.HasPrefix(path, root) && path[len(root)] == filepath.Separator
}

type narrowDecision uint8

const (
	narrowNoop narrowDecision = iota
	narrowApply
	narrowSkip
)

// classifyNarrow identifies the common no-op case without touching the ACL.
// A write decision is deliberately conservative: the ordered writer rereads
// the object before applying it, because a parent may have changed inherited
// permissions since this read completed.
//
// The already-capped question is asked of the hand-down as this object would
// hold it, not as the root holds it (handDown below), so the fast path
// recognizes what narrowOwn actually writes: asking it of the root's own
// entries would rewrite every capped object on every run.
func classifyNarrow(path, root string, sandbox *identities, hand []explicitAccess, pinned pinnedPaths) (narrowDecision, error) {
	var dacl *aclHeader
	var descriptor uintptr
	if r, _, _ := procGetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(w32.UTF16(path))),
		seFileObject, daclInfo|ownerInfo, 0, 0, uintptr(unsafe.Pointer(&dacl)), 0,
		uintptr(unsafe.Pointer(&descriptor))); r != 0 {
		return narrowNoop, callFailed("reading the permissions of", path, r)
	}
	defer w32.Free(descriptor)
	owned := ownedByTheSandbox(ownerOf(descriptor), sandbox.values)
	if dacl == nil {
		return narrowApply, nil
	}
	held, err := entriesOf(dacl)
	if err != nil {
		return narrowNoop, fmt.Errorf("reading the permissions of %s: %w", path, err)
	}
	if !owned {
		for _, who := range []uintptr{sandbox.everyone, sandbox.users, sandbox.authenticated} {
			for _, one := range held {
				if one.inherited || !sameSID(one.access.trustee.name, who) {
					continue
				}
				if one.access.mode == grantAccess && one.access.permissions&changing != 0 {
					return narrowApply, nil
				}
			}
		}
		return narrowNoop, nil
	}
	spared, err := pinned.contains(path)
	if err != nil {
		return narrowNoop, err
	}
	if spared {
		info, err := os.Lstat(path)
		if err == nil && info.IsDir() {
			return narrowSkip, nil
		}
		return narrowNoop, nil
	}
	down, err := handDown(hand, root, path)
	if err != nil {
		return narrowNoop, err
	}
	if hearsFromAbove(held) || !alreadyCapped(held, down, sandbox.ownerRights, sandbox.mark) {
		return narrowApply, nil
	}
	return narrowNoop, nil
}

// inspect is the reading pass: it asks of every object whether its permissions
// can be carried over, and whether it is the only name for what it points at.
//
// It runs on several goroutines because both questions are answered by the
// disk rather than by this program, and one of them costs an open handle per
// file. Whichever answer comes back wrong first stops the rest: nothing has
// been written at that point, so stopping early costs only the reading that
// was already under way.
func inspect(root string, sandbox []uintptr, pinned pinnedPaths) error {
	counting := os.Getenv(EnvAllowLinks) == ""
	// The one spelling of the tree that the names below can be compared with.
	// Where it cannot be worked out, the given one stands in: that can only
	// refuse a tree it should have allowed, never the other way round.
	spelled := root
	if counting {
		if out, err := finalName(root); err == nil {
			spelled = out
		}
		// The root is asked about here rather than in the walk, which passes
		// over it. Its own entry is written directly rather than inherited,
		// but a file granted by name is still one name among however many the
		// file has, and the others would receive that entry too.
		info, err := os.Lstat(root)
		if err != nil {
			return fmt.Errorf("looking at %s: %w", root, err)
		}
		if err := insideOnly(spelled, root, info.IsDir()); err != nil {
			return err
		}
	}
	return together(root, func(path string, entry fs.DirEntry) error {
		owned, err := readable(path, sandbox)
		if err != nil {
			return err
		}
		// The keep-list's snapshot is asked for here, while every object can
		// still be opened, and only for the objects the narrowing will still
		// consult it about: classifyNarrow and capObject ask for objects the
		// sandbox's own account owns, and for nothing else. Forgetting the
		// rest is not an eviction gamble -- no later step ever looks -- while
		// keeping it made the snapshot of a tree the sandbox had merely been
		// allowed into as large as the tree. What is asked for is held for
		// the whole operation: once the walk's own writes have landed, an
		// owned object can be one this process can no longer open, and the
		// answer taken now is the only one there will be. A path that finds
		// nothing goes back to the file system and fails closed when the
		// answer is no longer to be had, which is what a path the first pass
		// never saw always did.
		if len(pinned.keys) != 0 && owned {
			if err := pinned.snapshot(path); err != nil {
				return err
			}
		}
		if !counting {
			return nil
		}
		return insideOnly(spelled, path, entry.IsDir())
	})
}

// together runs check over everything under root, on several goroutines, and
// returns the first answer that was an error.
func together(root string, check func(string, fs.DirEntry) error) error {
	type object struct {
		path  string
		entry fs.DirEntry
	}
	objects := make(chan object, 128)
	stop := make(chan struct{})
	var said sync.Once
	var failure error
	var hands sync.WaitGroup
	for i := 0; i < workers(); i++ {
		hands.Add(1)
		go func() {
			defer hands.Done()
			for one := range objects {
				if err := check(one.path, one.entry); err != nil {
					// Whoever is first owns the answer, and closing stop is
					// what lets the walk stop feeding the others.
					said.Do(func() { failure = err; close(stop) })
					return
				}
			}
		}()
	}
	walked := walkTree(root, func(path string, entry fs.DirEntry) error {
		select {
		case objects <- object{path, entry}:
			return nil
		case <-stop:
			return filepath.SkipAll
		}
	})
	close(objects)
	hands.Wait()
	if failure != nil {
		return failure
	}
	return walked
}

// workers is how many of these run at once. The work is waiting on the disk
// rather than thinking, so it is worth more than one, and a bound keeps a tree
// on a slow disk from asking the machine for a thousand open handles at once.
func workers() int {
	const most = 8
	if hands := runtime.NumCPU(); hands < most {
		return hands
	}
	return most
}

// walkTree visits everything under root that a sweep is allowed to touch.
func walkTree(root string, visit func(string, fs.DirEntry) error) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		switch {
		case err != nil:
			// A place that cannot be read is a place nothing can be promised
			// about, so this is not passed over quietly.
			return fmt.Errorf("looking through %s: %w", path, err)
		case path == root:
			return nil // rewritten already, and pinned
		case entry.Type()&os.ModeSymlink != 0:
			return nil // a name for somewhere else, whose permissions are its own
		}
		return visit(path, entry)
	})
}

// ownerDecision is the question readable answers about an object's owner:
// whether the identifier that owns it is one of the sandbox's. It is a
// variable so a test can stand on the seam between the comparison and the
// free that follows it, which is exactly the stretch of road the
// borrowed-pointer bug above lived on.
var ownerDecision = ownedByTheSandbox

// readable reports whether an object's permission list can be carried
// over, and whether the sandbox the narrowing is for already owns the
// object -- both answered while the one descriptor both answers come from
// is still alive. The owner is a pointer into that descriptor's memory:
// it used to travel out of this function as a bare uintptr, and the
// comparison that consumed it ran after the deferred free had put the
// memory back -- a use-after-free in Windows' own heap, no collector's
// business. The answer now leaves as a bool or not at all, and the
// comparison is made here, inside the borrowed pointer's one moment of
// validity. The entries are walked for the carryable answer alone and
// kept no longer than the question: nothing downstream of the reading
// pass ever looks at them, and the narrowing pass reads the list again
// for itself.
func readable(path string, sandbox []uintptr) (bool, error) {
	var dacl *aclHeader
	var descriptor uintptr
	if r, _, _ := procGetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(w32.UTF16(path))),
		seFileObject, daclInfo|ownerInfo, 0, 0, uintptr(unsafe.Pointer(&dacl)), 0,
		uintptr(unsafe.Pointer(&descriptor))); r != 0 {
		return false, callFailed("reading the permissions of", path, r)
	}
	defer w32.Free(descriptor)
	owned := ownerDecision(ownerOf(descriptor), sandbox)
	if dacl == nil {
		return owned, nil
	}
	if err := carryable(dacl); err != nil {
		return false, fmt.Errorf("reading the permissions of %s: %w", path, err)
	}
	return owned, nil
}

// handDown is the hand the sweep writes in explicitly, made specific to one
// object: what the directory above is about to hand down TO THIS OBJECT, in
// the shape Windows would land it in if this object's list still heard from
// above. The entries as they sit on the granted directory answer the
// directory's question, and a whole write that copied them as they sit would
// answer every object's question with the root's: an INHERIT_ONLY entry
// copied onto a file grants the file nothing -- the flag says the entry is
// about what the object hands down, and a file hands down nothing -- so a
// file whose owner had been writing it through real inheritance lost the
// write to the copy that replaced it; and an entry whose NO_PROPAGATE had
// been spent on the first generation, copied onto a grandchild, starts its
// reach over one level deeper than the deed stopped it. A files-only entry
// copied onto a container spreads the same way, handing down from a
// directory the deed never covered. The shapes below are Windows' own
// inheritance rules, measured with icacls: a child of the kind an entry
// names inherits it effective, its copy carrying exactly the propagation the
// entry had left; NO_PROPAGATE is spent on the first generation, so a child
// one generation further holds nothing of it; a container a files-only entry
// reaches without NO_PROPAGATE holds it inherit-only, for the container's
// own files; and a files-only entry with NO_PROPAGATE passes a container by
// entirely.
func handDown(hand []explicitAccess, root, path string) ([]explicitAccess, error) {
	if len(hand) == 0 {
		return nil, nil
	}
	generations, err := generationsBelow(root, path)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("looking at %s: %w", path, err)
	}
	var down []explicitAccess
	for _, one := range hand {
		if adapted, ok := handDownEntry(one, generations, info.IsDir()); ok {
			down = append(down, adapted)
		}
	}
	return down, nil
}

// handDownEntry adapts one entry for one child, and says whether the child
// holds anything of it at all. dir says whether the child is a container;
// generations counts the container hops between the directory the entry sits
// on and this child, the immediate children being the first.
func handDownEntry(one explicitAccess, generations int, dir bool) (explicitAccess, bool) {
	flags := one.inheritance
	// NO_PROPAGATE is spent on the first generation: only the immediate
	// children of the directory the entry sits on hold anything of it.
	if flags&InheritNoPropagate != 0 && generations != 1 {
		return explicitAccess{}, false
	}
	if !dir {
		// A file inherits an entry naming its kind as an effective one and
		// keeps nothing inheritable: there is nothing below a file for a
		// copy to be handed down to, and INHERIT_ONLY would leave the file
		// holding an entry about entries it will never have.
		if flags&InheritObjects == 0 {
			return explicitAccess{}, false
		}
		one.inheritance = InheritNone
		return one, true
	}
	switch {
	case flags&InheritContainers != 0:
		// Effective on the container, and inheritable exactly as far as the
		// entry it came from had left: INHERIT_ONLY shields only the
		// directory the entry sat on, so the copy loses it; and a
		// NO_PROPAGATE entry was spent arriving here, so its copy carries no
		// inheritance at all -- the child holds it, and hands down nothing.
		if flags&InheritNoPropagate != 0 {
			one.inheritance = InheritNone
			return one, true
		}
		one.inheritance = flags &^ InheritOnly
		return one, true
	case flags&InheritObjects != 0:
		// A files-only entry reaches a container as an inherit-only one:
		// the copy is about the container's files, not about the container,
		// so INHERIT_ONLY is set on it however the entry above spelled it --
		// unless NO_PROPAGATE stopped the entry at the generation above, in
		// which case the container holds nothing of it at all.
		if flags&InheritNoPropagate != 0 {
			return explicitAccess{}, false
		}
		one.inheritance = flags | InheritOnly
		return one, true
	default:
		return explicitAccess{}, false
	}
}

// generationsBelow counts how many directory hops path sits below root. Both
// names come from the same WalkDir over root, so the count is the separators
// between them, compared byte for byte at the component boundary the way
// underSkipped compares; a path that is not below root at all is an error
// rather than a generation, and so is the root itself, which the sweep never
// sees but a hand-down would have nowhere to land on.
func generationsBelow(root, path string) (int, error) {
	rest, ok := strings.CutPrefix(path, root)
	if !ok || rest == "" || rest[0] != filepath.Separator {
		return 0, fmt.Errorf("%s is not below %s", path, root)
	}
	return strings.Count(rest, string(filepath.Separator)), nil
}

// narrowOwn takes the changing rights of Everyone, BUILTIN\Users and
// Authenticated Users out of the entries one object holds itself, leaving
// what it is handed from above alone, and hands whatever it took to the
// owner by name.
//
// The handback is not a courtesy, it is the same rule the granted directory
// itself follows: those two are not who is being kept out, and a grant must
// not cost the person granting it the directory they were granting. One level
// down it was left out, and a directory inside a granted tree that had stopped
// inheriting -- one wuserbox pinned for another sandbox, or one anybody
// protected -- whose only write path was Users went read-only to its owner the
// moment the tree above it was handed over. Measured, by writing a file there
// before and after.
//
// An object the sandbox's own account owns is written whole instead, and what
// the directory above is about to hand down goes in explicitly: a list
// written individually is no longer derived from above, so the parent's
// publish would no longer replace what it inherited -- measured, a file
// carrying an inherited Modify from its tree's writable days kept it through
// a read-only narrowing, and the write was accepted. The whole write, the
// measurement and the costs live in owner.go.
//
// pinned is the record's paths for this sandbox, and it is the only thing
// that spares an owned object: a path the record names was granted in the
// operator's own right, and a list the sandbox could have written is no
// evidence of that (owner.go).
func narrowOwn(path, root string, sandbox *identities, hand []explicitAccess, pinned pinnedPaths) error {
	var dacl *aclHeader
	var descriptor uintptr
	if r, _, _ := procGetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(w32.UTF16(path))),
		seFileObject, daclInfo|ownerInfo, 0, 0, uintptr(unsafe.Pointer(&dacl)), 0,
		uintptr(unsafe.Pointer(&descriptor))); r != 0 {
		return callFailed("reading the permissions of", path, r)
	}
	defer w32.Free(descriptor)

	owned := ownedByTheSandbox(ownerOf(descriptor), sandbox.values)
	if dacl == nil {
		// No permission list at all, which Windows reads as everybody having
		// everything -- the widest an object gets. It has no entries, so
		// narrowing them reaches nothing, and a directory inside a granted tree
		// carrying one stayed open to every sandbox on the machine after the
		// tree was handed over. Measured, with a second sandbox writing there.
		if !owned {
			return giveAList(path, sandbox)
		}
		down, err := handDown(hand, root, path)
		if err != nil {
			return err
		}
		return writeWhole(path, sandbox.fromNothing(), nil, down, sandbox.ownerRights, sandbox.mark)
	}

	held, err := entriesOf(dacl)
	if err != nil {
		return fmt.Errorf("reading the permissions of %s: %w", path, err)
	}
	var update, handback []explicitAccess
	for _, who := range []uintptr{sandbox.everyone, sandbox.users, sandbox.authenticated} {
		var kept []explicitAccess
		narrowed := false
		for _, one := range held {
			if one.inherited || !sameSID(one.access.trustee.name, who) {
				continue
			}
			access := one.access
			if access.mode == grantAccess && access.permissions&changing != 0 {
				narrowed = true
				// Handed back with the reach the entry it came from had, so
				// the owner keeps exactly what the crowd was holding here and
				// nothing further.
				handback = append(handback,
					entry(sandbox.holder, access.permissions&changing, access.inheritance, grantAccess))
				access.permissions &^= changing
				if access.permissions == 0 {
					continue
				}
			}
			// Refusals are carried over untouched: taking one away would
			// widen, which is never what this is for.
			kept = append(kept, access)
		}
		if !narrowed {
			continue
		}
		update = append(update, entry(who, 0, InheritNone, setAccess))
		update = append(update, kept...)
	}
	if !owned {
		if len(update) == 0 {
			return nil
		}
		return apply(path, append(update, handback...), false)
	}
	down, err := handDown(hand, root, path)
	if err != nil {
		return err
	}
	return capObject(path, held, update, handback, down, sandbox.ownerRights, sandbox.mark, pinned)
}

// StripOwn takes away the entries an object holds itself for one account,
// leaving whatever a directory above hands down to it alone.
//
// It is the other half of pinning a granted directory. Pinning copies what
// the directory was handed into its own list, another sandbox's entry among
// them, and that copy then answers to nobody: taking the other sandbox's
// grant away rewrites the directory it was granted, which this one no longer
// hears from. So the account's access here has to be taken away by name.
//
// An object account itself owns is left alone: owning it is what the cap in
// owner.go answers, written by the sweep that just ran or by TakeBack on the
// way out, and either already leaves this object exactly where it should be.
// Stripping the account's entry here too would undo a narrowed grant the
// sweep wrote moments ago in the same update -- an owned object's own entry
// is no longer only ever an orphaned copy the way an inherited one would be.
func StripOwn(path string, subject Identity) error {
	pass, err := BeginStripOwn(subject)
	if err != nil {
		return err
	}
	defer pass.End()
	return pass.Strip(path)
}

// BeginStripOwn resolves, once, everything a pass needs to know about
// the identity it was handed: the identifier itself, and -- because
// entries go out under a group's name while files a sandbox makes are
// owned by its account -- every member of the local group the identifier
// names. The pass owns what
// its answer stands on, the same way Isolate and TakeBack own theirs
// (owner.go): the member identifiers are Go values the pass itself holds,
// the parsed account identifier is system memory freed when the pass ends,
// and nothing outlives End. Nothing is carried across passes: group
// membership decides a revoke, so membership that changed since the last
// pass must be asked again, which is why this is a context with a lifetime
// and not a cache.
func BeginStripOwn(subject Identity) (*identities, error) {
	return identitiesFor(subject)
}

// Strip takes the account's entries off one object, the same decision
// StripOwn makes, asked of the identities the pass resolved once at its
// start rather than of a fresh resolution.
func (p *identities) Strip(path string) error {
	var dacl *aclHeader
	var descriptor uintptr
	if r, _, _ := procGetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(w32.UTF16(path))),
		seFileObject, daclInfo|ownerInfo, 0, 0, uintptr(unsafe.Pointer(&dacl)), 0,
		uintptr(unsafe.Pointer(&descriptor))); r != 0 {
		return callFailed("reading the permissions of", path, r)
	}
	defer w32.Free(descriptor)

	if ownedByTheSandbox(ownerOf(descriptor), p.values) {
		return nil
	}

	held, err := entriesOf(dacl)
	if err != nil {
		return fmt.Errorf("reading the permissions of %s: %w", path, err)
	}
	var clear []explicitAccess
	for _, one := range held {
		if one.inherited || !matchesSandboxIdentity(one.access.trustee.name, p.values) {
			continue
		}
		// Only what the object holds itself is cleared. What it is handed from
		// above goes when the directory above is rewritten, which is the
		// caller's next move anyway. Preserve the trustee from the ACL rather
		// than assuming the group SID was the only spelling present.
		already := false
		for _, prior := range clear {
			if sameSID(prior.trustee.name, one.access.trustee.name) {
				already = true
				break
			}
		}
		if !already {
			clear = append(clear, entry(one.access.trustee.name, 0, InheritNone, setAccess))
		}
	}
	if len(clear) != 0 {
		return apply(path, clear, false)
	}
	return nil
}
