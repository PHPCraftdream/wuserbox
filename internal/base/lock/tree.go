package lock

import (
	"path/filepath"

	"github.com/PHPCraftdream/wuserbox/internal/base/trace"
)

// HoldTree runs work while nothing else changes the permissions anywhere in
// the tree at root, and while nothing else changes a tree that contains it.
//
// A lock on the path alone is not enough, because the thing being changed is
// not the path: handing a directory over sweeps everything under it, so
// `wuserbox --grant C:\work` and `wuserbox --grant C:\work\inner` are two
// changes to the same objects under two different names. Each held its own
// name, so they could cross, and the outer sweep could narrow what the inner
// grant had just written. Neither side gained anything it was not given —
// both only ever narrow — but one of the two grants could end up weaker than
// it was asked for.
//
// So a change claims its own root outright and every directory above it in
// passing: a shared hold says "somebody is working inside here", an exclusive
// one says "this tree is mine". An operation deeper in meets the outer
// operation's exclusive hold on the directory it is working under and waits;
// two operations in unrelated trees share only the directories above them
// both, and shared holds do not exclude each other, so they still run at once.
// That is the difference from one machine-wide lock, which would close the
// same hole by making every grant wait for every other.
//
// A tree is held under what the directory is, not under how it was named.
// A root reached through a SUBST drive or a mapped drive is resolved to
// the real tree first, so two commands naming one tree hold one chain of
// locks rather than two; a root that exists but cannot be identified
// refuses the hold instead of standing on a lock of its own.
//
// The order is fixed — from the volume root downwards, always — so two
// operations can never hold what the other is waiting for: each waits only on
// a directory deeper than everything it holds already.
func HoldTree(root string, work func() error) error {
	done := trace.Current().Phase("lock_tree_wait", trace.Field{Key: "root", Value: root})
	release, err := takeTree(root)
	done(err)
	if err != nil {
		return err
	}
	defer release()
	return work()
}

// takeTree claims the whole chain and returns how to let all of it go. A name
// that cannot be taken lets go of what was taken before it, so a failure
// halfway leaves nothing held.
// The root is resolved to the real tree's own spelling before anything is
// taken -- once, and while nothing is held -- so every alias of a tree
// claims one chain, the refusal of an unidentifiable root happens before
// any lock exists to release, and the order below stays the order that
// cannot cross.
func takeTree(root string) (func(), error) {
	under, err := identity(root)
	if err != nil {
		return nil, err
	}
	var taken []func()
	release := func() {
		for i := len(taken) - 1; i >= 0; i-- {
			taken[i]()
		}
		taken = nil
	}
	above := containing(under)
	for _, directory := range above {
		got, err := takeAs(ForPath(directory), shared)
		if err != nil {
			release()
			return nil, err
		}
		taken = append(taken, got)
	}
	got, err := takeAs(ForPath(under), exclusive)
	if err != nil {
		release()
		return nil, err
	}
	taken = append(taken, got)
	return release, nil
}

// containing lists the directories that hold path, from the volume root down
// to its immediate parent. A volume root has none.
func containing(path string) []string {
	clean := filepath.Clean(path)
	var upwards []string
	for {
		parent := filepath.Dir(clean)
		if parent == clean {
			break
		}
		upwards = append(upwards, parent)
		clean = parent
	}
	downwards := make([]string, 0, len(upwards))
	for i := len(upwards) - 1; i >= 0; i-- {
		downwards = append(downwards, upwards[i])
	}
	return downwards
}
