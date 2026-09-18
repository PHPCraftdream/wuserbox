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
// the volume with os.SameFile through the root. If a place is absent, retain
// it unless its cleaned spelling is exactly the same: dropping an absent
// entry would lose the only record that can take back a copy once it returns.
func DedupeEntries(dest string, entries []config.Entry) []config.Entry {
	if len(entries) < 2 {
		return append([]config.Entry(nil), entries...)
	}
	root, err := os.OpenRoot(dest)
	if err != nil {
		return dedupeEntriesBySpelling(entries)
	}
	defer func() { _ = root.Close() }()

	kept := make([]config.Entry, 0, len(entries))
	for _, entry := range entries {
		duplicate := false
		for _, prior := range kept {
			if cleanEntryPath(prior.Path) == cleanEntryPath(entry.Path) ||
				sameEntryPlace(root, prior.Path, entry.Path) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			kept = append(kept, entry)
		}
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
