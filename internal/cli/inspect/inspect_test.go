package inspect

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/wuserbox/internal/base/exit"
	"github.com/PHPCraftdream/wuserbox/internal/cli/usage"
	"github.com/PHPCraftdream/wuserbox/internal/win/group"
)

func TestNameAcceptsNoArgumentOrADirectory(t *testing.T) {
	if err := Name(nil); err != nil {
		t.Errorf("without an argument: %v", err)
	}
	if err := Name([]string{t.TempDir()}); err != nil {
		t.Errorf("with a directory: %v", err)
	}
}

func TestPathNeedsExactlyOneGroup(t *testing.T) {
	for _, args := range [][]string{nil, {"a", "b"}} {
		if err := Path(args); err == nil {
			t.Errorf("%v should have been rejected", args)
		}
	}
}

func TestPathReportsAnUnknownGroup(t *testing.T) {
	err := Path([]string{group.Prefix + "not-here-00000000"})
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("got %v", err)
	}
}

func TestListTakesNoArguments(t *testing.T) {
	if err := List(nil); err != nil {
		t.Errorf("plain list: %v", err)
	}
	if err := List([]string{"extra"}); err == nil {
		t.Error("an argument should have been rejected")
	}
}

func TestAuditAcceptsADepth(t *testing.T) {
	if depth, err := auditDepth([]string{"0"}); err != nil || depth != 0 {
		t.Errorf("depth zero: got (%d, %v), want (0, nil)", depth, err)
	}
	if _, err := auditDepth([]string{"not-a-number"}); err == nil {
		t.Error("a non-numeric depth should have been rejected")
	}
	if _, err := auditDepth([]string{"1", "2"}); err == nil {
		t.Error("two arguments should have been rejected")
	}
	// A negative depth used to parse, and the walk's only boundary -- left
	// == 0 -- is one a negative start never reaches: every fixed drive to its
	// last leaf, two permission reads per directory on the way.
	if _, err := auditDepth([]string{"-1"}); err == nil {
		t.Error("a negative depth should have been rejected")
	}
	_, err := auditDepth([]string{"-1"})
	if got := exit.Of(err); got != exit.Usage {
		t.Errorf("a negative depth gave %v, want %v", got, exit.Usage)
	}
	// And whatever followed the number used to be dropped on the floor.
	if _, err := auditDepth([]string{"2x"}); err == nil {
		t.Error("trailing garbage after the depth should have been rejected")
	}
}

func TestVersionPrintsTheRelease(t *testing.T) {
	if err := Version(nil); err != nil {
		t.Errorf("version: %v", err)
	}
	if Release == "" {
		t.Error("the release string is empty")
	}
	if err := Version([]string{"extra"}); err == nil {
		t.Error("an argument should have been rejected")
	}
}

// TestListOffersJSONAndRejectsNonsense covers the contract a script relies on:
// a machine-readable list, and a wrong command line that says so through the
// exit code rather than through the general failure code.
func TestListOffersJSONAndRejectsNonsense(t *testing.T) {
	if err := List([]string{"--json"}); err != nil {
		t.Errorf("list --json: %v", err)
	}
	if got := exit.Of(List([]string{"--nonsense"})); got != exit.Usage {
		t.Errorf("an unknown flag gave %v, want %v", got, exit.Usage)
	}
	if got := exit.Of(List([]string{"extra"})); got != exit.Usage {
		t.Errorf("a stray argument gave %v, want %v", got, exit.Usage)
	}
}

func TestFlagFailuresAreUsageFailures(t *testing.T) {
	// A mistyped flag is a wrong command line, not an unexplained failure.
	for name, run := range map[string]func([]string) error{
		"audit": Audit, "list": List, "name": Name, "path": Path, "version": Version,
	} {
		if got := exit.Of(run([]string{"--nonsense"})); got != exit.Usage {
			t.Errorf("%s gave %v, want %v", name, got, exit.Usage)
		}
	}
}

// TestTheHelpListsExactlyTheFlagsListTakes holds list to its entry.
func TestTheHelpListsExactlyTheFlagsListTakes(t *testing.T) {
	flags, _, _ := listFlags()
	undocumented, missing := usage.Mismatch("list", flags)
	if len(undocumented) > 0 {
		t.Errorf("list takes %v, which its help never mentions", undocumented)
	}
	if len(missing) > 0 {
		t.Errorf("the help offers %v on list, which it would reject", missing)
	}
}

// The long form has to tell "nothing was recorded" from "recorded as
// nothing". A sandbox this machine never measured is not a sandbox of no
// size, and one never run is not one last used at the start of 1601.
func TestTheLongFormSaysWhatItDoesNotKnowInsteadOfGuessing(t *testing.T) {
	var out strings.Builder
	unknown := []Sandbox{{Group: "wub-old-00000000", Dir: `C:\projects\old`}}
	if err := write(&out, unknown, false, true); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"not measured", "not recorded", "nothing"} {
		if !strings.Contains(text, want) {
			t.Errorf("the block never says %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "1601") || strings.Contains(text, "0 B") {
		t.Errorf("the block invented a value it was never given:\n%s", text)
	}
}

// A program is handed the whole shape whatever form a person asked for.
func TestJSONCarriesEverythingWithoutBeingAskedForTheLongForm(t *testing.T) {
	made := time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)
	full := []Sandbox{{
		Group: "wub-app-0000beef", Dir: `C:\projects\app`,
		Account: "wub-0000beef", Profile: `C:\state\profile`, Temp: `C:\state\tmp`,
		Write: []string{`C:\projects\app`}, Read: []string{`C:\reference`},
		Made: &made, Used: &made,
		Size: &SizeOnDisk{Bytes: 2500000, Files: 118, Taken: made},
	}}
	var out strings.Builder
	if err := write(&out, full, true, false); err != nil {
		t.Fatal(err)
	}
	var back struct {
		Sandboxes []Sandbox `json:"sandboxes"`
	}
	if err := json.Unmarshal([]byte(out.String()), &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Sandboxes) != 1 {
		t.Fatalf("got %d sandboxes back, want 1", len(back.Sandboxes))
	}
	got := back.Sandboxes[0]
	if got.Account == "" || got.Profile == "" || got.Temp == "" || got.Size == nil || got.Made == nil {
		t.Errorf("JSON dropped part of what was known: %+v", got)
	}
	if len(got.Write) != 1 || len(got.Read) != 1 {
		t.Errorf("JSON dropped the directories: %+v", got)
	}
}

// Two runs that change nothing have to print the same thing, or the output
// is no use for telling what actually changed between them.
func TestTheBlocksComeOutInTheSameOrderEveryTime(t *testing.T) {
	entries := []group.Entry{
		{Name: "wub-c-00000003", Dir: `C:\c`},
		{Name: "wub-a-00000001", Dir: `C:\a`},
		{Name: "wub-b-00000002", Dir: `C:\b`},
	}
	first := describe(entries)
	second := describe(entries)
	var order []string
	for i := range first {
		order = append(order, first[i].Group)
		if first[i].Group != second[i].Group {
			t.Fatalf("two identical calls ordered them differently: %v then %v", first, second)
		}
	}
	if !sort.StringsAreSorted(order) {
		t.Errorf("the blocks are not in a fixed order: %v", order)
	}
}
