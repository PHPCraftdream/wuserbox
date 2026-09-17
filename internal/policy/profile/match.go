package profile

import "strings"

// matchMask reports whether a mask's pattern matches one relative path,
// spelled with forward slashes and measured from the entry the mask belongs
// to. What the pattern is tested against depends on the pattern itself, and
// this is the part of the format most easily got wrong:
//
// A pattern with no separator in it is tested against the file's own NAME,
// wherever that file sits within the depth the mask reaches -- "*.json"
// matches auth.json and also a/b/auth.json, because both are files called
// auth.json. This is the case people write, and it is what "how many
// directories deep this mask searches" means.
//
// A pattern carrying a separator is tested against the path RELATIVE to the
// entry, anchored at it: "prompts/*.md" matches only what sits directly in
// prompts, and "sessions/**" matches everything filed under sessions
// together with sessions itself -- an exclusion has to stop the copier
// descending into the directory at all, not merely skip the files it finds
// there.
//
// The language is ?, *, and **, and nothing else: ? is exactly one character
// and * is any run of them, neither ever crossing a separator, and ** is any
// number of whole segments, including none. Matching is case-insensitive,
// because Windows is -- the names this is applied to come from a file system
// that does not distinguish AUTH.JSON from auth.json either.
//
// Both sides fold through foldedName, the fold this package measured, and
// not through Unicode's lowercase: ToLower maps the capital sigma to the
// small one and leaves the final sigma alone, while this desk's volume
// opens Σ.json and ς.json onto one and the same file, so a mask folded
// with ToLower answered a question no volume here asks, and an exclusion
// spelled with one sigma missed the ς.json the sandbox held and the
// mirroring took it as a stray -- measured, no error. The fold errs toward
// joining, and which way that errs depends on the side asking: an exclude
// that joins more than the volume spares more, an include that joins more
// copies more, and both are the safe side of holding apart two spellings
// the volume opens onto one file, which is the direction that deletes.
func matchMask(pattern, candidate string) bool {
	target := candidate
	if !strings.Contains(pattern, "/") {
		// No separator: the name is what the pattern was written for, and
		// everything before it is only where the depth let the walk find it.
		if i := strings.LastIndex(candidate, "/"); i >= 0 {
			target = candidate[i+1:]
		}
	}
	return matchSegments(
		strings.Split(foldedName(pattern), "/"),
		strings.Split(foldedName(target), "/"),
	)
}

// matchSegments matches a pattern split into its segments against a candidate
// split the same way. Everything but ** matches one segment for one segment;
// ** matches any number of whole segments, none included, which is what makes
// "sessions/**" match "sessions" itself and not only what is filed under it.
func matchSegments(pattern, candidate []string) bool {
	for len(pattern) > 0 {
		if pattern[0] == "**" {
			// ** anchored at the tail, as in "sessions/**", has to match
			// zero segments; one anchored in the middle has to let the
			// segments after it match at every possible depth. Trying each
			// starting point covers both, and a candidate split from an
			// empty path arrives as one empty segment, so "**" matches that
			// too.
			for i := 0; i <= len(candidate); i++ {
				if matchSegments(pattern[1:], candidate[i:]) {
					return true
				}
			}
			return false
		}
		if len(candidate) == 0 || !matchSegment(pattern[0], candidate[0]) {
			return false
		}
		pattern, candidate = pattern[1:], candidate[1:]
	}
	return len(candidate) == 0
}

// matchSegment matches one segment: ? stands for exactly one character and *
// for any run of them, empty allowed, neither able to reach past the
// separator the split already consumed. The remembered star is where the
// match retreats to when a later character fails: a * eats one more
// character of the name and the pattern starts over after it, which is what
// lets a segment carry more than one star without backtracking through
// every split of it.
func matchSegment(pattern, name string) bool {
	var p, n int
	star, starAte := -1, 0
	for n < len(name) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == name[n]):
			p++
			n++
		case p < len(pattern) && pattern[p] == '*':
			star, starAte = p, n
			p++
		case star >= 0:
			starAte++
			p, n = star+1, starAte
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}
