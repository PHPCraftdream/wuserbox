package config

import (
	"os"
	"strings"
	"testing"
)

// refuse writes text as the rules file and expects Load to refuse it, naming
// every fragment in want somewhere in the refusal.
func refuse(t *testing.T, text string, want ...string) {
	t.Helper()
	path := useTempConfig(t)
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load()
	if err == nil {
		t.Fatalf("the file loaded without a word:\n%s", text)
	}
	for _, fragment := range want {
		if !strings.Contains(err.Error(), fragment) {
			t.Errorf("the refusal does not name %q:\n%v", fragment, err)
		}
	}
}

func TestLoadRefusesAnUnknownTopLevelKey(t *testing.T) {
	refuse(t, `projects: [ { dir: C:/app } ]
bogus: [ C:/somewhere ]`, `unknown key "bogus"`, `at the top of the file`, `projects, profile, cleanup`)
	refuse(t, `porjects: [ { dir: C:/app } ]`, `unknown key "porjects"`, `did you mean "projects"?`)
}

func TestLoadRefusesAnUnknownKeyInsideAnEntry(t *testing.T) {
	refuse(t, `profile: [ { path: .codex, dept: 2 } ]`,
		`profile[0] (.codex)`, `unknown key "dept"`, `did you mean "depth"?`, `next save`)
}

func TestLoadRefusesAnUnknownKeyInsideARule(t *testing.T) {
	refuse(t, `projects: [ { dir: C:/app, dirs: [ C:/tools ] } ]`,
		`projects[0] (C:/app)`, `unknown key "dirs"`, `did you mean "dir"?`)
}

func TestLoadRefusesAnUnknownKeyInsideAMask(t *testing.T) {
	refuse(t, `profile: [ { path: .codex, include: [ { mask: *.md, deep: 3 } ] } ]`,
		`profile[0]: include[0]`, `unknown key "deep"`)
}

func TestLoadRefusesAnEntryThatNamesNoPath(t *testing.T) {
	for _, doc := range []string{
		`profile: [ "" ]`,
		`profile: [ { path: "", depth: 1 } ]`,
		`profile: [ { depth: 2 } ]`,
	} {
		refuse(t, doc, `profile[0]`, `names no path`)
	}
}

func TestLoadRefusesARuleThatNamesNoDirectory(t *testing.T) {
	for _, doc := range []string{
		`projects: [ {} ]`,
		`projects: [ { dir: "", rw: [ C:/tools ] } ]`,
		`projects: [ { rw: [ C:/tools ] } ]`,
	} {
		refuse(t, doc, `projects[0]`, `names no directory`)
	}
}

func TestLoadRefusesARuleMemberThatNamesNoDirectory(t *testing.T) {
	refuse(t, `projects: [ { dir: C:/app, rw: [ C:/tools, "" ] } ]`,
		`projects[0]`, `rw[1]`, `names no directory`)
}

func TestLoadRefusesANegativeEntryDepth(t *testing.T) {
	refuse(t, `profile: [ { path: .codex, depth: -1 } ]`,
		`profile[0]`, `depth is -1`)
}

func TestLoadRefusesANegativeMaskDepth(t *testing.T) {
	refuse(t, `profile: [ { path: .codex, include: [ { mask: *.md, depth: -2 } ] } ]`,
		`profile[0]: include[0]`, `depth is -2`)
}

func TestLoadRefusesAMaskThatNamesNoPattern(t *testing.T) {
	refuse(t, `profile: [ { path: .codex, include: [ "" ] } ]`,
		`profile[0]: include[0]`, `names no pattern`)
	refuse(t, `profile: [ { path: .codex, include: [ { depth: 3 } ] } ]`,
		`profile[0]: include[0]`, `names no pattern`)
}

func TestLoadRefusesACleanupMaskThatNamesNothing(t *testing.T) {
	refuse(t, `cleanup: [ "" ]`, `cleanup[0]`, `names no pattern`)
	refuse(t, `cleanup: [ { depth: -1 } ]`, `cleanup[0]`, `depth is -1`)
}

// TestAHandWrittenFileWithEverySectionStillLoads is the false-positive
// guard: a file that looks like what the header comment teaches must load,
// and must survive the save that the check exists to protect.
func TestAHandWrittenFileWithEverySectionStillLoads(t *testing.T) {
	path := useTempConfig(t)
	text := `## wuserbox: extra directories each project may write to, and the
## profile entries copied into a sandbox before a run.
## Paths use forward slashes: ktav reads a backslash as an escape.

projects: [ { dir: C:/projects/app, rw: [ C:/projects/tools, C:/projects/logs ], ro: [ C:/shared ] } ]

profile: [
    .codex
    { path: .claude, depth: 2, include: [ *.json, { mask: *.md, depth: 3 } ], exclude: [ { mask: sessions/**, depth: 1 } ] }
]

cleanup: [ cache/**, { mask: tmp/**, depth: 2 } ]
`
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Profile) != 2 {
		t.Fatalf("got %d profile entries, want 2", len(got.Profile))
	}
	if got.Profile[1].Depth == nil || *got.Profile[1].Depth != 2 {
		t.Errorf("the entry's depth came back as %v", got.Profile[1].Depth)
	}
	if got.Profile[1].Path != ".claude" {
		t.Errorf("the second entry's path came back as %q", got.Profile[1].Path)
	}
	if len(got.Profile[1].Include) != 2 || got.Profile[1].Include[1].Pattern != "*.md" ||
		got.Profile[1].Include[1].Depth == nil || *got.Profile[1].Include[1].Depth != 3 {
		t.Errorf("the include list came back as %v", got.Profile[1].Include)
	}
	if len(got.Profile[1].Exclude) != 1 || got.Profile[1].Exclude[0].Pattern != "sessions/**" {
		t.Errorf("the exclude list came back as %v", got.Profile[1].Exclude)
	}
	if len(got.Projects) != 1 || len(got.Projects[0].RW) != 2 || len(got.Projects[0].RO) != 1 {
		t.Errorf("the rule came back as %+v", got.Projects)
	}
	if len(got.Cleanup) != 2 || got.Cleanup[0].Pattern != "cache/**" {
		t.Errorf("cleanup came back as %v", got.Cleanup)
	}
	if err := got.Save(); err != nil {
		t.Fatal(err)
	}
	again, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Profile) != 2 {
		t.Errorf("after a save the profile holds %d entries", len(again.Profile))
	}
}
