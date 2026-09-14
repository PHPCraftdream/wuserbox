package usage

import "strings"

// Full is the whole manual in one piece: the overview first, then the complete
// entry for every command, in the order the overview lists them.
//
// It is assembled from the same Commands that the overview and the single-
// command entries are assembled from, rather than written out a second time.
// A manual kept as its own copy is a manual that falls behind, and the first
// reader here is usually a program deciding what to ask a person for, which
// makes a stale answer worse than a missing one.
func Full() string {
	var b strings.Builder
	b.WriteString(Text)
	for _, command := range Commands {
		b.WriteString("\n" + rule + "\n\n" + command.String())
	}
	b.WriteString("\n" + rule + "\n" + reference)
	return b.String()
}

// rule separates one entry from the next. Plain dashes, because this is read
// in whatever terminal the reader happens to have.
const rule = "----------------------------------------------------------------------"
