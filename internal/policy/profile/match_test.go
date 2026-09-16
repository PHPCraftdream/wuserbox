package profile

import "testing"

// The two matching rules are kept apart on purpose, because confusing them
// would make "*.json" a pattern that matches nothing under a nested entry,
// or let "prompts/*.md" copy a whole tree. A pattern with no separator is
// tested against a file's own name; one with a separator is tested against
// the path relative to the entry, anchored at it.
func TestANamePatternMatchesTheNameWhereverTheDepthFoundIt(t *testing.T) {
	if !matchMask("*.json", "auth.json") {
		t.Error("*.json did not match the name auth.json")
	}
	if !matchMask("*.json", "a/b/auth.json") {
		t.Error("*.json did not match a/b/auth.json, whose name it is written for")
	}
	if matchMask("*.json", "a/b/auth.jsonx") {
		t.Error("*.json matched a file whose name merely starts the same")
	}
}

func TestAnAnchoredPatternMatchesOnlyWhatSitsWhereItSays(t *testing.T) {
	if !matchMask("prompts/*.md", "prompts/x.md") {
		t.Error("prompts/*.md did not match prompts/x.md")
	}
	if matchMask("prompts/*.md", "prompts/a/x.md") {
		t.Error("prompts/*.md crossed a separator, and a * never does")
	}
	if matchMask("prompts/*.md", "x.md") {
		t.Error("prompts/*.md matched a file sitting directly in the entry")
	}
}

// A trailing ** matches the directory it is anchored at as well as everything
// under it. The directory itself is the half most easily lost, and the half
// an exclusion cannot work without: the copier tests the directory's own
// relative path to decide whether to descend into it at all.
func TestADoubleStarMatchesTheDirectoryItIsAnchoredAtAndEverythingUnderIt(t *testing.T) {
	for _, want := range []string{"sessions", "sessions/a", "sessions/a/b"} {
		if !matchMask("sessions/**", want) {
			t.Errorf("sessions/** did not match %s", want)
		}
	}
	if matchMask("sessions/**", "sessionship") {
		t.Error("sessions/** matched a longer name that merely starts the same")
	}
	if matchMask("sessions/**", "other/sessions") {
		t.Error("sessions/** matched a directory of that name somewhere else")
	}
}

func TestABareDoubleStarMatchesEverythingIncludingTheEmptyPath(t *testing.T) {
	for _, want := range []string{"", "auth.json", "a/b/auth.json", "sessions/a/b/c.db"} {
		if !matchMask("**", want) {
			t.Errorf("** did not match %q", want)
		}
	}
}

func TestAQuestionMarkStandsForExactlyOneCharacter(t *testing.T) {
	if !matchMask("a?c", "abc") {
		t.Error("a?c did not match abc")
	}
	if matchMask("a?c", "abbc") {
		t.Error("a?c matched abbc, but ? is one character, never two")
	}
	if matchMask("a?c", "ac") {
		t.Error("a?c matched ac, but ? is one character, never none")
	}
	if matchMask("a?c", "a/c") {
		t.Error("a?c crossed a separator, and ? never does")
	}
}

// Matching is case-insensitive because Windows is: the names this is applied
// to come from a file system that does not tell them apart either.
func TestMatchingIgnoresCase(t *testing.T) {
	if !matchMask("AUTH.JSON", "auth.json") {
		t.Error("AUTH.JSON did not match auth.json")
	}
	if !matchMask("Sessions/**", "SESSIONS/a/b") {
		t.Error("Sessions/** did not match SESSIONS/a/b")
	}
}

func TestAPlainNameMatchesExactlyThatName(t *testing.T) {
	if !matchMask("auth.json", "auth.json") {
		t.Error("a pattern with no wildcards did not match itself")
	}
	if matchMask("auth.json", "config.toml") {
		t.Error("a pattern with no wildcards matched a different name")
	}
}

func TestAPlainRelativePathMatchesExactlyThatPath(t *testing.T) {
	if !matchMask("a/b", "a/b") {
		t.Error("a pattern with no wildcards did not match itself")
	}
	if matchMask("a/b", "a/b/c") {
		t.Error("a pattern with no wildcards matched a deeper path")
	}
	if matchMask("a/b", "a") {
		t.Error("a pattern with no wildcards matched a shorter path")
	}
}
