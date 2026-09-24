package profile

import (
	"fmt"
	"os"
	"path"
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
// The halves answer in Copy's own order: what the cleanup globs would clear
// counts as gone before the copy half looks, because in a real fill
// clearCleanup runs first -- a preview that let the copy half read the tree
// as it stands would report skips the run does not make, and zero bytes
// where bytes move.
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
	// In Copy's own order: the two refusals a real fill makes before it
	// touches dest are made here too, before anything is counted -- a
	// preview that described a run Copy would refuse to start would have
	// the two disagreeing about the one thing they exist to agree about.
	if err := refuseEntriesCopyRefuses(rules.Profile); err != nil {
		return nil, nil, err
	}
	cleanupPlan, err := previewCleanup(root, rules.Cleanup)
	if err != nil {
		return nil, nil, err
	}
	// In Copy's own order: what the cleanup half would clear counts as gone
	// before the copy half looks, because in a real fill clearCleanup runs
	// first and the copy starts from what is left.
	entryPlans, err := previewEntries(paths.Home(), root, rules.Profile, prints, goneAfterCleanup(cleanupPlan))
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
	// loudly, and a preview must report the same refusal rather than describe
	// a run against a destination the real copier cannot open.
	if !info.IsDir() {
		return nil, fmt.Errorf("the profile to fill cannot be opened: %s is not a directory", dest)
	}
	return os.OpenRoot(dest)
}

// previewEntries is copyEntries' read-only twin: the same loop over the
// rules file's entries, the same within and os.Stat gate that leaves out a
// name not on this machine, and the same walk underneath. What differs is
// only the sink at the bottom -- planSink counts instead of copying -- so a
// preview can never name a file the real run would not also reach, or skip
// one it would actually copy. gone is what the cleanup half of this
// preview would clear, folded; the copy half reads it because a real run's
// copy starts from a tree clearCleanup has already been over.
func previewEntries(home string, root *os.Root, entries []config.Entry, prints map[string]Print, gone map[string]bool) ([]EntryPlan, error) {
	var plans []EntryPlan
	for _, entry := range entries {
		dst, err := within(entry.Path)
		if err != nil {
			return plans, err
		}
		src := filepath.Join(home, filepath.FromSlash(entry.Path))
		info, err := os.Stat(src)
		if err != nil && !os.IsNotExist(err) {
			return plans, fmt.Errorf("statting source %s: %w", entry.Path, err)
		}
		if os.IsNotExist(err) {
			continue // not on this machine; not an error, same as a real copy
		}
		plan := EntryPlan{Path: entry.Path}
		sk := &planSink{plan: &plan, gone: gone}
		if err := walkEntry(sk, src, dst, "", root, info, nil, newWalk(entry), prints, nil); err != nil {
			return plans, fmt.Errorf("previewing %s: %w", entry.Path, err)
		}
		plans = append(plans, plan)
	}
	return plans, nil
}

// goneAfterCleanup is the cleanup plan as the copy half of a preview has to
// read it: each planned removal under FoldedEntryPath, the key this package
// already answers "are these two spellings of one path inside the profile"
// with. Asked of the package rather than spelled out again because the two
// sides are written by different witnesses -- a plan path comes out of the
// destination tree's own names, a destination path out of the rules entry
// and the source's -- and because whatever the fold becomes, one question
// put to the package keeps the preview on its answer.
func goneAfterCleanup(cleanupPlan []CleanupPlan) map[string]bool {
	gone := make(map[string]bool, len(cleanupPlan))
	for _, removal := range cleanupPlan {
		gone[FoldedEntryPath(removal.Path)] = true
	}
	return gone
}

// takenByCleanup answers whether dst sits at or under a path the cleanup
// half of this preview would clear. At or under, not equal to: a plan path
// can name a directory cleanDir takes whole, so with cleanup: [agent] and
// profile: [agent] every file under agent/ is a copy into a directory that
// will not exist again until the copy makes it -- one level of them no
// equality check would ever reach. Asked up dst's own ancestors rather
// than across every removal, so a file pays for the depth it sits at, not
// for the number of paths the globs matched.
//
// The ancestors are taken with path.Dir and not filepath.Dir, and the
// difference is the whole of whether this works: the keys are spelled with
// forward slashes, because that is what FoldedEntryPath hands back, and
// filepath.Dir on Windows hands back the native spelling of whatever it was
// given -- so the first ancestor of agent/sessions/one.json came back as
// agent\sessions, which the map does not hold. Measured: a glob naming a
// directory more than one segment deep matched nothing, and the plan went on
// reporting the skip the run does not make. A glob naming a top-level
// directory hid it, since one segment has no separator to convert.
func takenByCleanup(gone map[string]bool, dst string) bool {
	for p := FoldedEntryPath(dst); ; p = path.Dir(p) {
		if gone[p] {
			return true
		}
		if p == "." {
			return false
		}
	}
}

// planSink is copySink's read-only twin: asked the same questions by the
// same walk, and answers by counting instead of by writing. It never
// touches root beyond an Lstat, and only where root is not nil -- a preview
// asked about a sandbox that does not exist yet has nothing to Lstat, and
// answers every file "would copy" rather than guessing at "would skip".
// gone is what the cleanup half of this preview would clear, folded; nil
// answers no to every file.
type planSink struct {
	plan *EntryPlan
	gone map[string]bool
}

func (p *planSink) prepareDir(*os.Root, string) error { return nil }

func (p *planSink) finishDir(*os.Root, string, string, map[string]bool, *walk) error { return nil }

func (p *planSink) file(_, dst string, root *os.Root, info os.FileInfo, _ *int64, prints, _ map[string]Print) error {
	// A real fill clears the cleanup globs before the copy decides
	// anything, so a file the globs take is not there to be skipped when
	// the copy reaches it -- it is copied back into the space the deletion
	// left. The preview deletes nothing, so it cannot let cleanDir's twin
	// answer by absence; it asks instead. Answering the skip question
	// against the tree as it stands reported a skip the run does not make:
	// measured, an unchanged auth.json named by a cleanup glob came back
	// "Skipped: 1, Files: 0" from a plan whose run deleted that file and
	// copied it again.
	if !takenByCleanup(p.gone, dst) {
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
	}
	p.plan.Files++
	p.plan.Bytes += info.Size()
	return nil
}
