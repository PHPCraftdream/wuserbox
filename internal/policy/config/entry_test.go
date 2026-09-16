package config

import (
	"reflect"
	"strings"
	"testing"

	ktav "github.com/ktav-lang/golang"
)

func depthPtr(n int) *int { return &n }

// TestABareEntryStaysBareThroughTheFile guards the one promise the format
// makes to every existing rules file: an entry carrying no limits means what
// a plain path has always meant, so it has to come back from the file as one.
// An entry that grew braces on the way through would rewrite every existing
// rules file the first time wuserbox saved it.
func TestABareEntryStaysBareThroughTheFile(t *testing.T) {
	text, err := ktav.Dumps([]Entry{{Path: ".claude.json"}})
	if err != nil {
		t.Fatal(err)
	}
	var got []Entry
	if err := ktav.LoadsInto(text, &got); err != nil {
		t.Fatalf("the file did not load back: %v\n%s", err, text)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1:\n%s", len(got), text)
	}
	if got[0].Path != ".claude.json" || got[0].Depth != nil || len(got[0].Include) != 0 || len(got[0].Exclude) != 0 {
		// Field by field, not %v of the struct: Depth is a pointer and would
		// print as an address, telling nothing.
		t.Errorf("the entry did not come back bare: path %q depth %v include %v exclude %v",
			got[0].Path, got[0].Depth, got[0].Include, got[0].Exclude)
	}
	if !got[0].Bare() {
		t.Error("an entry with no limits reported itself as carrying limits, so it would be written back as an object next save")
	}
	if strings.Contains(text, "{") {
		t.Errorf("the file grew braces around a bare entry:\n%s", text)
	}
	// An empty but present mask list is still no limit: writing one would
	// limp through the file saying nothing, and turn a bare entry into an
	// object for no reason.
	empty := Entry{Path: ".claude.json", Include: []Mask{}}
	if !empty.Bare() {
		t.Error("an entry with an empty include list reported itself as carrying limits")
	}
}

// TestAnEntryWithLimitsComesBackWithEveryLimitIntact walks an entry through
// the whole file and back: ktav flattens through JSON on the way out and in,
// so a field lost anywhere in that path would quietly narrow -- or widen --
// what the entry copies on every later run.
func TestAnEntryWithLimitsComesBackWithEveryLimitIntact(t *testing.T) {
	want := Entry{
		Path:    ".codex",
		Depth:   depthPtr(2),
		Include: Masks([]string{"*.json", "*.toml"}),
		Exclude: Masks([]string{"sessions/**", "*.db"}),
	}
	text, err := ktav.Dumps([]Entry{want})
	if err != nil {
		t.Fatal(err)
	}
	var got []Entry
	if err := ktav.LoadsInto(text, &got); err != nil {
		t.Fatalf("the file did not load back: %v\n%s", err, text)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1:\n%s", len(got), text)
	}
	e := got[0]
	if e.Path != want.Path {
		t.Errorf("path came back as %q, want %q", e.Path, want.Path)
	}
	if e.Depth == nil {
		t.Fatal("depth was lost, so the entry would copy everything under the path")
	}
	if *e.Depth != 2 {
		t.Errorf("depth came back as %d, want 2", *e.Depth)
	}
	if !reflect.DeepEqual(e.Include, want.Include) {
		t.Errorf("include came back as %v, want %v", e.Include, want.Include)
	}
	if !reflect.DeepEqual(e.Exclude, want.Exclude) {
		t.Errorf("exclude came back as %v, want %v", e.Exclude, want.Exclude)
	}
}

// TestAListHoldingBothShapesSurvivesInTheOrderWritten matters because the
// copier walks the section top to bottom: a list that came back reordered
// would copy in an order nobody wrote.
func TestAListHoldingBothShapesSurvivesInTheOrderWritten(t *testing.T) {
	want := []Entry{
		{Path: ".claude.json"},
		{Path: ".codex", Depth: depthPtr(0), Exclude: Masks([]string{"sessions/**"})},
		{Path: ".gitconfig"},
	}
	text, err := ktav.Dumps(want)
	if err != nil {
		t.Fatal(err)
	}
	var got []Entry
	if err := ktav.LoadsInto(text, &got); err != nil {
		t.Fatalf("the file did not load back: %v\n%s", err, text)
	}
	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3:\n%s", len(got), text)
	}
	for i, w := range want {
		if got[i].Path != w.Path {
			t.Errorf("entry %d came back as %q, want %q", i, got[i].Path, w.Path)
		}
		if got[i].Bare() != w.Bare() {
			t.Errorf("entry %d changed shape: bare %v, want %v", i, got[i].Bare(), w.Bare())
		}
	}
	if got[1].Depth == nil || *got[1].Depth != 0 {
		t.Errorf("the limited entry lost its depth: %v", got[1].Depth)
	}
}

// TestAHandWrittenListWithAnObjectBetweenTwoBareEntriesLoads is the most
// important test here: a person edits the file by hand and can put a limited
// entry between two plain ones, and if the loader cannot read that, the
// format does not exist. The source below is spelled the way such a person
// writes it, straight from the design doc, not the way Dumps writes it.
func TestAHandWrittenListWithAnObjectBetweenTwoBareEntriesLoads(t *testing.T) {
	src := `profile: [
    .claude.json
    {
        path: .codex
        depth: 0
        include: [
            *.json
        ]
        exclude: [
            sessions/**
        ]
    }
    .gitconfig
]`
	var got Config
	if err := ktav.LoadsInto(src, &got); err != nil {
		t.Fatalf("a hand-written mixed list did not load: %v\n%s", err, src)
	}
	if len(got.Profile) != 3 {
		t.Fatalf("got %d entries, want 3:\n%s", len(got.Profile), src)
	}
	first, limited, last := got.Profile[0], got.Profile[1], got.Profile[2]
	if first.Path != ".claude.json" || !first.Bare() {
		t.Errorf("first entry came back as %q bare=%v, want .claude.json bare", first.Path, first.Bare())
	}
	if limited.Path != ".codex" {
		t.Errorf("the object came back with path %q, want .codex", limited.Path)
	}
	if limited.Depth == nil || *limited.Depth != 0 {
		t.Errorf("depth came back as %v, want 0", limited.Depth)
	}
	if len(limited.Include) != 1 || limited.Include[0].Pattern != "*.json" {
		t.Errorf("include came back as %v, want [*.json]", limited.Include)
	}
	if len(limited.Exclude) != 1 || limited.Exclude[0].Pattern != "sessions/**" {
		t.Errorf("exclude came back as %v, want [sessions/**]", limited.Exclude)
	}
	if last.Path != ".gitconfig" || !last.Bare() {
		t.Errorf("last entry came back as %q bare=%v, want .gitconfig bare", last.Path, last.Bare())
	}
}

// TestOmittedDepthAndZeroDepthStayDifferentThroughTheFile is the whole reason
// Depth is a pointer: omitted means copy everything under the path, 0 means
// only the files directly in it, and an int flattens the two into whichever
// one zero stands for. A rules file that asked for the narrower of the two
// and got the wider would copy more than the person writing it asked for,
// every run.
func TestOmittedDepthAndZeroDepthStayDifferentThroughTheFile(t *testing.T) {
	text, err := ktav.Dumps([]Entry{{Path: ".gemini"}, {Path: ".config", Depth: depthPtr(0)}})
	if err != nil {
		t.Fatal(err)
	}
	var got []Entry
	if err := ktav.LoadsInto(text, &got); err != nil {
		t.Fatalf("the file did not load back: %v\n%s", err, text)
	}
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2:\n%s", len(got), text)
	}
	if got[0].Depth != nil {
		t.Errorf("the omitted depth came back as %d, want absent -- the entry would copy less than the whole tree", *got[0].Depth)
	}
	if got[1].Depth == nil {
		t.Fatal("the zero depth came back absent, so the entry would copy the whole tree")
	}
	if *got[1].Depth != 0 {
		t.Errorf("depth came back as %d, want 0", *got[1].Depth)
	}
}

// TestAMaskWithoutADepthStaysAPlainPattern keeps the common list readable: an
// include list is usually two or three plain extensions, and if each one grew
// braces to say nothing, the shape meant for the rare case would be paid for
// by every entry that never needed it.
func TestAMaskWithoutADepthStaysAPlainPattern(t *testing.T) {
	text, err := ktav.Dumps([]Entry{{Path: ".codex", Include: Masks([]string{"*.json", "*.toml"})}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text, "mask") {
		t.Errorf("a plain pattern was written as an object:\n%s", text)
	}
	var got []Entry
	if err := ktav.LoadsInto(text, &got); err != nil {
		t.Fatalf("the file did not load back: %v\n%s", err, text)
	}
	if len(got) != 1 || len(got[0].Include) != 2 {
		t.Fatalf("the include list came back as %v:\n%s", got, text)
	}
	for i, want := range []string{"*.json", "*.toml"} {
		if got[0].Include[i].Pattern != want || !got[0].Include[i].Bare() {
			t.Errorf("mask %d came back as %q bare=%v, want %q bare",
				i, got[0].Include[i].Pattern, got[0].Include[i].Bare(), want)
		}
	}
}

// TestAMaskKeepsADepthOfItsOwnThroughTheFile is the case the per-mask depth
// exists for: one directory holding credentials at the top and prompts filed
// somewhere below it, said once instead of as two entries differing only in a
// number. A depth lost here would silently widen or narrow that search on
// every run.
func TestAMaskKeepsADepthOfItsOwnThroughTheFile(t *testing.T) {
	want := Entry{
		Path:  ".codex",
		Depth: depthPtr(0),
		Include: []Mask{
			{Pattern: "*.json"},
			{Pattern: "*.md", Depth: depthPtr(3)},
		},
	}
	text, err := ktav.Dumps([]Entry{want})
	if err != nil {
		t.Fatal(err)
	}
	var got []Entry
	if err := ktav.LoadsInto(text, &got); err != nil {
		t.Fatalf("the file did not load back: %v\n%s", err, text)
	}
	if len(got) != 1 || len(got[0].Include) != 2 {
		t.Fatalf("the include list came back as %v:\n%s", got, text)
	}
	plain, deep := got[0].Include[0], got[0].Include[1]
	if !plain.Bare() {
		t.Errorf("the mask with no depth of its own came back carrying %v", plain.Depth)
	}
	if deep.Depth == nil {
		t.Fatalf("the mask's own depth was lost, so it would search %v levels instead of 3:\n%s",
			got[0].Depth, text)
	}
	if *deep.Depth != 3 {
		t.Errorf("the mask's depth came back as %d, want 3", *deep.Depth)
	}
}

// TestAMaskWithoutADepthFallsBackToTheEntrys is the rule that lets a list of
// plain patterns mean anything at all: without it a bare mask would have no
// depth and the entry's would go unread.
func TestAMaskWithoutADepthFallsBackToTheEntrys(t *testing.T) {
	entry := Entry{Path: ".codex", Depth: depthPtr(1)}
	plain := Mask{Pattern: "*.json"}
	own := Mask{Pattern: "*.md", Depth: depthPtr(3)}

	got := entry.DepthFor(plain)
	if got == nil || *got != 1 {
		t.Errorf("a mask with no depth answered %v, want the entry's 1", got)
	}
	if got := entry.DepthFor(own); got == nil || *got != 3 {
		t.Errorf("a mask with its own depth answered %v, want 3", got)
	}
	// And an entry with no depth either: no limit, which is what a bare path
	// has always meant and has to go on meaning.
	if got := (Entry{Path: ".codex"}).DepthFor(plain); got != nil {
		t.Errorf("with no depth anywhere the answer was %d, want no limit", *got)
	}
	// Zero is a limit, not an absence. An entry that says depth 0 must not
	// hand a mask "no limit" just because zero is the empty int.
	if got := (Entry{Path: ".codex", Depth: depthPtr(0)}).DepthFor(plain); got == nil || *got != 0 {
		t.Errorf("an entry depth of 0 answered %v, want 0", got)
	}
}

// TestAHandWrittenIncludeListMixingBothMaskShapesLoads is the mask-level twin
// of the entry test above, and it matters for the same reason: this file is
// edited by hand, and a person writing two plain patterns and one with a
// depth is writing the shape the format was asked for.
func TestAHandWrittenIncludeListMixingBothMaskShapesLoads(t *testing.T) {
	src := `profile: [
    {
        path: .codex
        include: [
            *.json
            *.toml
            {
                mask: *.md
                depth: 3
            }
        ]
    }
]`
	var got Config
	if err := ktav.LoadsInto(src, &got); err != nil {
		t.Fatalf("a hand-written mixed mask list did not load: %v\n%s", err, src)
	}
	if len(got.Profile) != 1 || len(got.Profile[0].Include) != 3 {
		t.Fatalf("the include list came back as %v:\n%s", got.Profile, src)
	}
	masks := got.Profile[0].Include
	for i, want := range []string{"*.json", "*.toml", "*.md"} {
		if masks[i].Pattern != want {
			t.Errorf("mask %d came back as %q, want %q", i, masks[i].Pattern, want)
		}
	}
	if !masks[0].Bare() || !masks[1].Bare() {
		t.Error("a plain pattern came back carrying a depth nobody wrote")
	}
	if masks[2].Depth == nil || *masks[2].Depth != 3 {
		t.Errorf("the depth came back as %v, want 3", masks[2].Depth)
	}
}

// TestAnEntryWhoseOnlyLimitIsDepthZeroIsWrittenAsAnObject exists because
// depth 0 is a real limit, and writing it as a bare string would drop it,
// silently widening what the entry copies on every run.
func TestAnEntryWhoseOnlyLimitIsDepthZeroIsWrittenAsAnObject(t *testing.T) {
	text, err := ktav.Dumps([]Entry{{Path: ".gemini", Depth: depthPtr(0)}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "depth") {
		t.Errorf("the depth limit was dropped from the file:\n%s", text)
	}
	if !strings.Contains(text, "{") {
		t.Errorf("the entry was written as a bare string, dropping its only limit:\n%s", text)
	}
}
