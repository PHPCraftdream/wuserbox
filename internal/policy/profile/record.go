package profile

import (
	"os"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

// DedupeEntries keeps one record entry for each place the profile contains.
//
// A folded spelling is only a conservative comparison key. Windows volumes
// can keep names such as i and dotless ı apart even though Unicode uppercasing
// joins them, so using that key for the .copied record can make it forget one
// place and later clear another. When the profile contains both places, ask
// the volume's stored directory-entry spelling through the root. If a place is
// absent, retain it unless its cleaned spelling is exactly the same: dropping
// an absent entry would lose the only record that can take back a copy once it
// returns.
//
// The volume is asked through one placeResolver for the whole call, and each
// entry's answer is indexed the moment it exists: a cleaned spelling seen
// before is dropped by it, a canonical place seen before by that, and an
// entry whose place cannot be witnessed joins neither index -- retained,
// unless its cleaned spelling repeats, which is the pairwise loop's answer
// for absent places too. What changed against that loop is the number of
// questions, not any answer: each entry is resolved once and compared by
// index, where the loop resolved every prior again for every entry compared,
// re-opening and re-reading the same directories once per comparison (P2-5).
func DedupeEntries(dest string, entries []config.Entry) []config.Entry {
	if len(entries) < 2 {
		return append([]config.Entry(nil), entries...)
	}
	root, err := os.OpenRoot(dest)
	if err != nil {
		return dedupeEntriesBySpelling(entries)
	}
	defer func() { _ = root.Close() }()

	resolver := newPlaceResolver(root)
	spellings := make(map[string]bool, len(entries))
	places := make(map[string]bool, len(entries))
	kept := make([]config.Entry, 0, len(entries))
	for _, entry := range entries {
		spelling := cleanEntryPath(entry.Path)
		if spellings[spelling] {
			continue
		}
		canonical := resolver.place(entry.Path)
		if canonical.ok {
			if places[canonical.canonical] {
				continue
			}
			places[canonical.canonical] = true
		}
		spellings[spelling] = true
		kept = append(kept, entry)
	}
	return kept
}

func dedupeEntriesBySpelling(entries []config.Entry) []config.Entry {
	seen := make(map[string]bool, len(entries))
	kept := make([]config.Entry, 0, len(entries))
	for _, entry := range entries {
		key := cleanEntryPath(entry.Path)
		if seen[key] {
			continue
		}
		seen[key] = true
		kept = append(kept, entry)
	}
	return kept
}
