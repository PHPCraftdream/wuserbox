package profile

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

// EntryPlan is what filling one profile: entry would do, worked out without
// doing any of it: how many files it would copy, how many bytes those come
// to, and how many it would skip because the fingerprint kept from the last
// run still describes their source.
type EntryPlan struct {
	Path    string
	Files   int
	Bytes   int64
	Skipped int
}

// Plan answers what Copy would do to dest, without writing or deleting
// anything: what each cleanup: glob would clear, and what each profile:
// entry would copy or skip. It is --dry-run's way into this package, and it
// walks the same ground Copy does rather than a second guess at it -- see
// planSink and previewCleanup for how each half shares its real twin's walk.
//
// dest need not exist yet: a sandbox --dry-run is asked about before it has
// ever been built has no profile on disk at all, and that is answered
// correctly by a nil root rather than refused as an error, since every read
// through root below already treats "not there" as an ordinary answer.
//
// prints is read the same way Copy reads it, kept by the caller beside the
// .copied list outside the profile, so a file this call answers "skipped"
// for is the same file a real run would skip next.
func Plan(dest string, prints map[string]Print) ([]CleanupPlan, []EntryPlan, error) {
	rules, err := config.Load()
	if err != nil {
		return nil, nil, err
	}
	root, err := openForPreview(dest)
	if err != nil {
		return nil, nil, err
	}
	if root != nil {
		defer func() { _ = root.Close() }()
	}
	cleanupPlan, err := previewCleanup(root, rules.Cleanup)
	if err != nil {
		return nil, nil, err
	}
	entryPlans, err := previewEntries(paths.Home(), root, rules.Profile, prints)
	if err != nil {
		return nil, nil, err
	}
	return cleanupPlan, entryPlans, nil
}

// openForPreview opens dest read-only, the way openProfile opens it for a
// real fill, except that a destination which does not exist yet is answered
// with a nil root instead of an error -- see Plan's own doc for why that is
// the right answer here and would be the wrong one for openProfile.
func openForPreview(dest string) (*os.Root, error) {
	info, err := os.Stat(dest)
	// Not there at all is the expected answer for a sandbox this run would
	// be building, and it is not a failure: there is nothing yet to preview
	// a fill against.
	if os.IsNotExist(err) {
		return nil, nil
	}
	// Anything else is worth reporting rather than reading as an empty
	// profile. A preview that cannot look at the destination should say so;
	// answering "nothing would be skipped" because the directory could not
	// be read would be a preview quietly describing a run that is not the
	// one about to happen.
	if err != nil {
		return nil, err
	}
	// Something there that is not a directory: the real fill will refuse it
	// loudly, and a preview has nothing useful to add before it does.
	if !info.IsDir() {
		return nil, nil
	}
	return os.OpenRoot(dest)
}

// previewEntries is copyEntries' read-only twin: the same loop over the
// rules file's entries, the same within and os.Stat gate that leaves out a
// name not on this machine, and the same walk underneath. What differs is
// only the sink at the bottom -- planSink counts instead of copying -- so a
// preview can never name a file the real run would not also reach, or skip
// one it would actually copy.
func previewEntries(home string, root *os.Root, entries []config.Entry, prints map[string]Print) ([]EntryPlan, error) {
	var plans []EntryPlan
	for _, entry := range entries {
		dst, err := within(entry.Path)
		if err != nil {
			return plans, err
		}
		src := filepath.Join(home, filepath.FromSlash(entry.Path))
		info, err := os.Stat(src)
		if err != nil {
			continue // not on this machine; not an error, same as a real copy
		}
		plan := EntryPlan{Path: entry.Path}
		sk := &planSink{plan: &plan}
		if err := walkEntry(sk, src, dst, "", root, info, nil, newWalk(entry), prints, nil); err != nil {
			return plans, fmt.Errorf("previewing %s: %w", entry.Path, err)
		}
		plans = append(plans, plan)
	}
	return plans, nil
}

// planSink is copySink's read-only twin: asked the same questions by the
// same walk, and answers by counting instead of by writing. It never
// touches root beyond an Lstat, and only where root is not nil -- a preview
// asked about a sandbox that does not exist yet has nothing to Lstat, and
// answers every file "would copy" rather than guessing at "would skip".
type planSink struct{ plan *EntryPlan }

func (p *planSink) prepareDir(*os.Root, string) error { return nil }

func (p *planSink) finishDir(*os.Root, string, string, map[string]bool, *walk) error { return nil }

func (p *planSink) file(_, dst string, root *os.Root, info os.FileInfo, _ *int64, prints, _ map[string]Print) error {
	key := filepath.ToSlash(dst)
	if root != nil {
		if old, ok := prints[key]; ok && old.stillDescribes(info) {
			// The same second check copySink.file makes: a print alone does
			// not prove the destination still holds the file, only that the
			// source has not changed since it last did.
			if now, there := lookAt(root, dst); there && now.Mode().IsRegular() && now.Size() == info.Size() {
				p.plan.Skipped++
				return nil
			}
		}
	}
	p.plan.Files++
	p.plan.Bytes += info.Size()
	return nil
}
