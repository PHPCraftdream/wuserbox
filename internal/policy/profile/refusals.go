package profile

// The questions the copier and validation have to answer the same way, kept
// beside each other so neither can drift from the other. Copy runs them
// before anything below it touches dest -- an ordinary run never calls
// --config validate, so the copier is the only place these are always on the
// path -- and validation asks for them here rather than re-deciding them,
// because two answers to "does this rules file mean something that can be
// copied for" are exactly how a rules file comes to pass validation and
// then lose data on the run.

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

// EntryCarriesNegativeDepth answers whether a profile: entry names a depth
// that cannot bound anything -- on the entry itself, or on any mask in its
// include or exclude lists -- and if so, the message both a run and
// validation refuse the file with.
//
// The refusal is the copier's and not only validation's because a negative
// depth is not a limit that fails safe. A bound of -1 is below every path,
// so reachesWithin puts every mask out of reach and copiesFile refuses every
// file: nothing is copied, nothing lands on the present list, and the
// mirroring then removes what the destination already holds as stray -- the
// copied credentials and the paths the entry's own exclusions were
// protecting alike. Measured, before this refusal went in: entry `agent`
// with exclude: ["*.log"] and depth: -1 reported success and deleted the
// copied auth.json and the protected work.log both. depth: -1 is a number
// nobody meant to write, and taken at face value it silently turns every
// protection the entry had off.
func EntryCarriesNegativeDepth(entry config.Entry) error {
	if entry.Depth != nil && *entry.Depth < 0 {
		return fmt.Errorf("%s has depth %d, and a negative depth cannot bound anything -- every mask "+
			"would sit out of reach and every file would be refused, so nothing would be copied and "+
			"the mirroring would then remove what the sandbox already holds under %s",
			entry.Path, *entry.Depth, entry.Path)
	}
	for _, mask := range entry.Include {
		if mask.Depth != nil && *mask.Depth < 0 {
			return fmt.Errorf("%s: %q in its include list has depth %d, and a negative depth cannot "+
				"bound anything -- the mask reaches nothing, so the files it was written to find are "+
				"never copied", entry.Path, mask.Pattern, *mask.Depth)
		}
	}
	for _, mask := range entry.Exclude {
		if mask.Depth != nil && *mask.Depth < 0 {
			return fmt.Errorf("%s: %q in its exclude list has depth %d, and a negative depth cannot "+
				"bound anything -- the mask reaches nothing, so what it was written to protect is no "+
				"longer protected", entry.Path, mask.Pattern, *mask.Depth)
		}
	}
	return nil
}

// conflictingProfileEntry finds two entries in the list that share a path
// but do not say the same thing about what to copy under it, and reports
// the first such pair.
//
// A path repeated with identical limits is redundant, not dangerous --
// copying it twice lands the same result twice -- and validation reports it
// as the waste it is. A path repeated with different limits is not
// redundant: { path: .codex, exclude: [sessions/**] } followed by the bare
// ".codex" reads as two ways of saying the same thing and is not one. The
// second entry copies .codex whole, and the mirroring behind it deletes
// whatever the first entry's exclusion protected, because the mirror sees
// no exclusion the second time around and the excluded path is not in the
// source. That is real data loss, arriving from a rules file that only
// looks redundant, and there is no reading of "list this path twice with
// different limits" that is safe to silently pick one side of -- see
// EntriesSayTheSameThing for the comparison, and Copy's own use of this for
// why it runs before anything below it touches dest.
func conflictingProfileEntry(entries []config.Entry) (first, second config.Entry, found bool) {
	seen := make(map[string]config.Entry, len(entries))
	for _, entry := range entries {
		key := strings.ToLower(filepath.ToSlash(filepath.Clean(filepath.FromSlash(entry.Path))))
		prior, ok := seen[key]
		if !ok {
			seen[key] = entry
			continue
		}
		if !EntriesSayTheSameThing(prior, entry) {
			return prior, entry, true
		}
	}
	return config.Entry{}, config.Entry{}, false
}

// EntriesSayTheSameThing reports whether two profile: entries that name the
// same path describe exactly the same copy: the same depth, and the same
// include and exclude masks in the same order. This is the only condition
// under which a path repeated in the list is redundant rather than a silent
// change of meaning, and it is exported so validation asks this package the
// question rather than re-deciding it with a second comparison of the same
// fields.
func EntriesSayTheSameThing(a, b config.Entry) bool {
	return sameDepth(a.Depth, b.Depth) && sameMasks(a.Include, b.Include) && sameMasks(a.Exclude, b.Exclude)
}

func sameDepth(a, b *int) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	return a == nil || *a == *b
}

func sameMasks(a, b []config.Mask) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Pattern != b[i].Pattern || !sameDepth(a[i].Depth, b[i].Depth) {
			return false
		}
	}
	return true
}

// describeEntryLimits renders one entry's limits for an error message --
// terse enough to read in one line, specific enough to show what differs
// between two entries sharing a path.
func describeEntryLimits(e config.Entry) string {
	if e.Bare() {
		return "no limits, copied whole"
	}
	var parts []string
	if e.Depth != nil {
		parts = append(parts, fmt.Sprintf("depth %d", *e.Depth))
	}
	if len(e.Include) > 0 {
		parts = append(parts, fmt.Sprintf("include %v", e.Include))
	}
	if len(e.Exclude) > 0 {
		parts = append(parts, fmt.Sprintf("exclude %v", e.Exclude))
	}
	return strings.Join(parts, ", ")
}
