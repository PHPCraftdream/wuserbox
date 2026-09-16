package profile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

func depthPtr(n int) *int { return &n }

// useLimitedProfile points the config package and paths.Home at fresh
// temporary directories and writes a rules file whose profile section is
// entries carrying their limits, the way a hand-edited rules file does.
func useLimitedProfile(t *testing.T, entries []config.Entry) (home, dest string) {
	t.Helper()
	home = t.TempDir()
	dest = filepath.Join(t.TempDir(), "sandbox-profile")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("USERPROFILE", home)
	t.Setenv(config.EnvPath, filepath.Join(t.TempDir(), "rules.ktav"))
	if err := (&config.Config{Profile: entries}).Save(); err != nil {
		t.Fatal(err)
	}
	return home, dest
}

// Depth is counted in directories below the entry's path: 1 is the files
// directly in it plus the files one level down, and nothing below that.
func TestAnEntryDepthBoundsHowFarTheCopyDescends(t *testing.T) {
	home, dest := useLimitedProfile(t, []config.Entry{{Path: ".c", Depth: depthPtr(1)}})
	write(t, filepath.Join(home, ".c", "a.json"), "top")
	write(t, filepath.Join(home, ".c", "sub", "b.json"), "one down")
	write(t, filepath.Join(home, ".c", "sub", "deeper", "c.json"), "two down")

	fill(t, dest)
	if got := read(t, filepath.Join(dest, ".c", "a.json")); got != "top" {
		t.Errorf("the file directly in the path was not copied: %v", got)
	}
	if got := read(t, filepath.Join(dest, ".c", "sub", "b.json")); got != "one down" {
		t.Errorf("the file one level down was not copied: %v", got)
	}
	if _, err := os.Stat(filepath.Join(dest, ".c", "sub", "deeper")); !os.IsNotExist(err) {
		t.Error("a directory beyond the entry's depth was created anyway")
	}
}

// Zero is a limit, not an absence: the files directly in the path, and no
// subdirectories at all.
func TestAZeroDepthCopiesOnlyWhatSitsDirectlyInThePath(t *testing.T) {
	home, dest := useLimitedProfile(t, []config.Entry{{Path: ".c", Depth: depthPtr(0)}})
	write(t, filepath.Join(home, ".c", "a.json"), "top")
	write(t, filepath.Join(home, ".c", "sub", "b.json"), "deeper")

	fill(t, dest)
	if got := read(t, filepath.Join(dest, ".c", "a.json")); got != "top" {
		t.Errorf("the file directly in the path was not copied: %v", got)
	}
	if _, err := os.Stat(filepath.Join(dest, ".c", "sub")); !os.IsNotExist(err) {
		t.Error("a subdirectory exists under a depth-0 entry")
	}
}

// A mask with no separator is tested against the file's own name, wherever
// the walk finds that name -- this is the case people write.
func TestAnIncludeListMatchesTheFilesNameAtAnyDepthItReaches(t *testing.T) {
	home, dest := useLimitedProfile(t, []config.Entry{{Path: ".codex", Include: config.Masks([]string{"*.json"})}})
	write(t, filepath.Join(home, ".codex", "auth.json"), "{}")
	write(t, filepath.Join(home, ".codex", "config.toml"), "[a]\n")
	write(t, filepath.Join(home, ".codex", "nested", "other.json"), "{}")

	fill(t, dest)
	if got := read(t, filepath.Join(dest, ".codex", "auth.json")); got != "{}" {
		t.Errorf("the named file was not copied: %v", got)
	}
	if got := read(t, filepath.Join(dest, ".codex", "nested", "other.json")); got != "{}" {
		t.Errorf("a file of the named kind one level down was not copied: %v", got)
	}
	if _, err := os.Stat(filepath.Join(dest, ".codex", "config.toml")); !os.IsNotExist(err) {
		t.Error("a file no mask names was copied anyway")
	}
}

// A mask carrying a separator is anchored at the entry's path: what it names
// is where the file has to sit, not what the file is called.
func TestAnAnchoredIncludeMatchesOnlyWhereItSays(t *testing.T) {
	home, dest := useLimitedProfile(t, []config.Entry{{Path: ".agent", Include: config.Masks([]string{"prompts/*.md"})}})
	write(t, filepath.Join(home, ".agent", "auth.json"), "{}")
	write(t, filepath.Join(home, ".agent", "prompts", "x.md"), "prompt")
	write(t, filepath.Join(home, ".agent", "prompts", "deep", "y.md"), "buried")

	fill(t, dest)
	if got := read(t, filepath.Join(dest, ".agent", "prompts", "x.md")); got != "prompt" {
		t.Errorf("the file the mask names was not copied: %v", got)
	}
	if _, err := os.Stat(filepath.Join(dest, ".agent", "auth.json")); !os.IsNotExist(err) {
		t.Error("a mask anchored at prompts matched a file sitting in the entry's root")
	}
	if _, err := os.Stat(filepath.Join(dest, ".agent", "prompts", "deep", "y.md")); !os.IsNotExist(err) {
		t.Error("prompts/*.md reached a level deeper than it names")
	}
}

// A directory the walk enters is created even when nothing in it ends up
// copied. Which directories exist in the destination has to be predictable
// from the rules file, and lazily creating only the ones that matched would
// make it depend on what each one happened to hold.
func TestADirectoryTheWalkEntersIsCreatedEvenWhenNothingInItIsCopied(t *testing.T) {
	home, dest := useLimitedProfile(t, []config.Entry{{Path: ".agent", Include: config.Masks([]string{"*.json"})}})
	write(t, filepath.Join(home, ".agent", "prompts", "notes.txt"), "not json")

	fill(t, dest)
	info, err := os.Stat(filepath.Join(dest, ".agent", "prompts"))
	if err != nil {
		t.Fatalf("a directory the walk entered was not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("prompts came back as something other than a directory")
	}
	if _, err := os.Stat(filepath.Join(dest, ".agent", "prompts", "notes.txt")); !os.IsNotExist(err) {
		t.Error("a file no mask names was copied anyway")
	}
}

// An exclusion stops the walk at the directory it names -- not descending
// into it is what keeps a large excluded tree from costing the walk, and
// what keeps the directory out of a destination that has never seen it.
func TestAnExcludeStopsTheWalkAtTheDirectoryItNames(t *testing.T) {
	home, dest := useLimitedProfile(t, []config.Entry{{Path: ".codex", Exclude: config.Masks([]string{"sessions/**"})}})
	write(t, filepath.Join(home, ".codex", "auth.json"), "{}")
	write(t, filepath.Join(home, ".codex", "sessions", "a.json"), "{}")

	fill(t, dest)
	if got := read(t, filepath.Join(dest, ".codex", "auth.json")); got != "{}" {
		t.Errorf("the file outside the exclusion was not copied: %v", got)
	}
	if _, err := os.Stat(filepath.Join(dest, ".codex", "sessions")); !os.IsNotExist(err) {
		t.Error("an excluded directory was created in the destination")
	}
}

// TestAnExcludeSparesWhatTheSandboxAlreadyPutThere is the test the whole
// format answers to: the sessions under an agent's directory are written by
// the agent inside the sandbox, and the next run must not wipe them for not
// being in the source. Without the exclusion check in removeStrayChildren
// this is exactly what happened -- the copy skipped the excluded path and
// the mirroring deleted it, a slower way of doing the same damage.
func TestAnExcludeSparesWhatTheSandboxAlreadyPutThere(t *testing.T) {
	home, dest := useLimitedProfile(t, []config.Entry{{Path: ".codex", Exclude: config.Masks([]string{"sessions/**"})}})
	write(t, filepath.Join(home, ".codex", "auth.json"), "{}")

	fill(t, dest)
	write(t, filepath.Join(dest, ".codex", "sessions", "day-1.json"), "the agent's work")

	fill(t, dest)
	if got := read(t, filepath.Join(dest, ".codex", "sessions", "day-1.json")); got != "the agent's work" {
		t.Errorf("the sandbox's own sessions were wiped by the next run: %v", got)
	}
	if got := read(t, filepath.Join(dest, ".codex", "auth.json")); got != "{}" {
		t.Errorf("the copy itself stopped happening: %v", got)
	}
}

// A name mask reaches an excluded path filed anywhere below the entry, not
// only at its top.
func TestAnExclusionProtectsANestedStrayByItsName(t *testing.T) {
	home, dest := useLimitedProfile(t, []config.Entry{{Path: ".codex", Exclude: config.Masks([]string{"*.db"})}})
	write(t, filepath.Join(home, ".codex", "cache", "keep.json"), "{}")

	fill(t, dest)
	write(t, filepath.Join(dest, ".codex", "cache", "history.db"), "the agent's db")

	fill(t, dest)
	if got := read(t, filepath.Join(dest, ".codex", "cache", "history.db")); got != "the agent's db" {
		t.Errorf("an excluded name was wiped from the destination: %v", got)
	}
	if got := read(t, filepath.Join(dest, ".codex", "cache", "keep.json")); got != "{}" {
		t.Errorf("the copy itself stopped happening: %v", got)
	}
}

// Exclude wins over include: a path matching both is excluded, the narrower
// statement being the one somebody wrote on purpose. Both halves of the
// exclusion hold -- the source's copy is not brought in, and what the sandbox
// already keeps under that name is not overwritten by it either.
func TestAnExcludeWinsOverInclude(t *testing.T) {
	home, dest := useLimitedProfile(t, []config.Entry{
		{Path: ".codex", Include: config.Masks([]string{"*.json"}), Exclude: config.Masks([]string{"secret*.json"})},
	})
	write(t, filepath.Join(home, ".codex", "auth.json"), "{}")
	write(t, filepath.Join(home, ".codex", "secret-keys.json"), "{}")

	fill(t, dest)
	if _, err := os.Stat(filepath.Join(dest, ".codex", "secret-keys.json")); !os.IsNotExist(err) {
		t.Error("a path matching both include and exclude was copied")
	}
	// What the sandbox writes under the excluded name is its own, though the
	// source carries a file of the same name.
	write(t, filepath.Join(dest, ".codex", "secret-keys.json"), "kept")

	fill(t, dest)
	if got := read(t, filepath.Join(dest, ".codex", "secret-keys.json")); got != "kept" {
		t.Errorf("the excluded name was copied over what the sandbox keeps there: %v", got)
	}
	if got := read(t, filepath.Join(dest, ".codex", "auth.json")); got != "{}" {
		t.Errorf("include stopped working where exclude did not apply: %v", got)
	}
}

// A mask that names a depth of its own reaches that far even where the
// entry's own depth stops -- that is the whole reason a mask can carry one.
// The entry's depth still governs the masks that do not name one, so the
// two limits compose rather than override.
func TestAMaskKeepsADepthOfItsOwn(t *testing.T) {
	home, dest := useLimitedProfile(t, []config.Entry{{
		Path:  ".a",
		Depth: depthPtr(0),
		Include: []config.Mask{
			{Pattern: "*.md", Depth: depthPtr(3)},
			{Pattern: "*.json"},
		},
	}})
	write(t, filepath.Join(home, ".a", "top.md"), "0")
	write(t, filepath.Join(home, ".a", "top.json"), "0")
	write(t, filepath.Join(home, ".a", "deep", "mid.md"), "1")
	write(t, filepath.Join(home, ".a", "deep", "mid.json"), "1")
	write(t, filepath.Join(home, ".a", "deep", "lower", "bottom.md"), "2")

	fill(t, dest)
	for _, want := range []string{
		filepath.Join(".a", "top.md"),
		filepath.Join(".a", "top.json"),
		filepath.Join(".a", "deep", "mid.md"),
		filepath.Join(".a", "deep", "lower", "bottom.md"),
	} {
		if _, err := os.Stat(filepath.Join(dest, want)); err != nil {
			t.Errorf("%s was not copied, though a mask with the reach for it names it: %v", want, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dest, ".a", "deep", "mid.json")); !os.IsNotExist(err) {
		t.Error("a bare mask copied past the entry's depth, which is what it falls back to")
	}
}

// A file the include list has stopped naming is retired like any other
// stray: the destination mirrors what the entry means now, not whatever it
// has meant over the years.
func TestAFileTheIncludeListStoppedNamingIsRetiredLikeAnyOtherStray(t *testing.T) {
	home, dest := useLimitedProfile(t, []config.Entry{{Path: ".codex", Include: config.Masks([]string{"*.json", "*.toml"})}})
	write(t, filepath.Join(home, ".codex", "auth.json"), "{}")
	write(t, filepath.Join(home, ".codex", "config.toml"), "[a]\n")

	fill(t, dest)
	if err := (&config.Config{Profile: []config.Entry{{Path: ".codex", Include: config.Masks([]string{"*.json"})}}}).Save(); err != nil {
		t.Fatal(err)
	}
	fill(t, dest)
	if got := read(t, filepath.Join(dest, ".codex", "auth.json")); got != "{}" {
		t.Errorf("the still-named file stopped being copied: %v", got)
	}
	if _, err := os.Stat(filepath.Join(dest, ".codex", "config.toml")); !os.IsNotExist(err) {
		t.Error("a file the include list no longer names is still in the destination")
	}
}

// A mask that carries a depth of its own protects only within its reach: an
// exclusion bounded to the top levels lets the thing it names through
// beneath them, the same boundary the copy obeys. "**/keep/**" is how an
// exclusion names that shape at any depth; its depth bounds how far down the
// protection goes.
func TestAnExclusionWithADepthOfItsOwnStopsProtectingPastItsReach(t *testing.T) {
	home, dest := useLimitedProfile(t, []config.Entry{{
		Path:    ".a",
		Exclude: []config.Mask{{Pattern: "**/keep/**", Depth: depthPtr(1)}},
	}})
	write(t, filepath.Join(home, ".a", "live", "real.txt"), "x")

	fill(t, dest)
	write(t, filepath.Join(dest, ".a", "keep", "thing.txt"), "at the top")
	write(t, filepath.Join(dest, ".a", "live", "keep", "thing.txt"), "in reach")
	write(t, filepath.Join(dest, ".a", "live", "deep", "keep", "thing.txt"), "beyond reach")

	fill(t, dest)
	if got := read(t, filepath.Join(dest, ".a", "keep", "thing.txt")); got != "at the top" {
		t.Errorf("what the exclusion reaches at the top was wiped: %v", got)
	}
	if got := read(t, filepath.Join(dest, ".a", "live", "keep", "thing.txt")); got != "in reach" {
		t.Errorf("what the exclusion reaches one level down was wiped: %v", got)
	}
	if _, err := os.Stat(filepath.Join(dest, ".a", "live", "deep", "keep")); !os.IsNotExist(err) {
		t.Error("what sits past the exclusion's reach was protected anyway")
	}
}

// TestADepthAlsoSparesWhatItStopsAbove closes the same damage the exclusions
// close, arriving by a different door. `depth: 0` on an agent's directory
// reads as "copy the two files at the top" -- and if the mirroring then
// emptied everything below them as stray, it would wipe the agent's own work
// on every run, having never once looked inside to see what was there.
//
// A directory the walk declines to enter is not the entry's to empty,
// whatever the reason it declined. A file is a different question: it sits
// within reach, the entry did look at it, and the test below this one holds
// that case the other way.
func TestADepthAlsoSparesWhatItStopsAbove(t *testing.T) {
	home, dest := useLimitedProfile(t, []config.Entry{{Path: ".c", Depth: depthPtr(0)}})
	write(t, filepath.Join(home, ".c", "auth.json"), "credentials")

	fill(t, dest)
	// As the agent running inside the sandbox would: its own work, below the
	// depth the entry reaches, in a directory the source does not have.
	write(t, filepath.Join(dest, ".c", "sessions", "today.jsonl"), "the agent's own")

	fill(t, dest)
	if got := read(t, filepath.Join(dest, ".c", "auth.json")); got != "credentials" {
		t.Errorf("the file the entry does reach was not copied: %v", got)
	}
	if got := read(t, filepath.Join(dest, ".c", "sessions", "today.jsonl")); got != "the agent's own" {
		t.Errorf("what sits below the entry's depth was wiped: %v", got)
	}
}

// TestTakingAnEntryWithExclusionsBackSparesWhatTheyProtected is the reason
// the record holds whole entries rather than bare paths: when an entry
// leaves the rules file, what it copied goes, and what its exclusions
// protected stays -- somebody taking .claude off the list said something
// about copying, not about the sessions the agent inside wrote there.
func TestTakingAnEntryWithExclusionsBackSparesWhatTheyProtected(t *testing.T) {
	home, dest := useLimitedProfile(t, []config.Entry{{Path: ".claude", Exclude: config.Masks([]string{"sessions/**"})}})
	write(t, filepath.Join(home, ".claude", "settings.json"), "{}")

	fill(t, dest)
	write(t, filepath.Join(dest, ".claude", "sessions", "day-1.json"), "the agent's work")

	if err := (&config.Config{Profile: config.Entries([]string{})}).Save(); err != nil {
		t.Fatal(err)
	}
	fill(t, dest)
	if _, err := os.Stat(filepath.Join(dest, ".claude", "settings.json")); !os.IsNotExist(err) {
		t.Error("the entry left the list but its copy is still there")
	}
	if got := read(t, filepath.Join(dest, ".claude", "sessions", "day-1.json")); got != "the agent's work" {
		t.Errorf("what the entry's exclusion protected was taken back with it: %v", got)
	}
}
