// Tests for the checks on profile: and cleanup:, the rules file's other two
// sections -- config_test.go covers projects:.

package diagnose

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/base/exit"
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

func depthPtr(n int) *int { return &n }

// TestValidateRefusesAProfileEntryThatEscapesTheProfile checks point 1: an
// absolute path and one that climbs out with ".." are both what the copier's
// own within refuses at run time, and validate has to say so first.
func TestValidateRefusesAProfileEntryThatEscapesTheProfile(t *testing.T) {
	for _, path := range []string{`C:\outside`, "../escaped"} {
		useRules(t, &config.Config{Profile: []config.Entry{{Path: path}}})
		err := Config([]string{"validate"})
		if got := exit.Of(err); got != exit.BadConfig {
			t.Errorf("path %q: exit code is %v, want %v", path, got, exit.BadConfig)
		}

		var found bool
		for _, c := range inspectProfile([]config.Entry{{Path: path}}, nil) {
			if c.Kind == "outside" {
				found = true
				if !c.Fatal {
					t.Errorf("path %q: an entry escaping the profile was not marked fatal", path)
				}
				if !strings.Contains(c.Message, config.Path()) {
					t.Errorf("path %q: the message does not name the rules file: %s", path, c.Message)
				}
			}
		}
		if !found {
			t.Errorf("path %q: escaping the profile was not reported", path)
		}
	}
}

// TestValidateRefusesAProfileEntryWithAnEmptyPath checks point 2: an entry
// with no path names nothing to copy, which is not something a run can act
// on at all.
func TestValidateRefusesAProfileEntryWithAnEmptyPath(t *testing.T) {
	useRules(t, &config.Config{Profile: []config.Entry{{Path: ""}}})
	err := Config([]string{"validate"})
	if got := exit.Of(err); got != exit.BadConfig {
		t.Errorf("exit code is %v, want %v", got, exit.BadConfig)
	}
	complaints := inspectProfile([]config.Entry{{Path: ""}}, nil)
	if len(complaints) != 1 || complaints[0].Kind != "empty" || !complaints[0].Fatal {
		t.Errorf("got %+v", complaints)
	}
}

// TestValidateRefusesAMaskWithAnEmptyPattern checks point 3 across all three
// lists a mask can appear in: include, exclude and cleanup.
func TestValidateRefusesAMaskWithAnEmptyPattern(t *testing.T) {
	cases := map[string]*config.Config{
		"include": {Profile: []config.Entry{{Path: ".codex", Include: []config.Mask{{Pattern: ""}}}}},
		"exclude": {Profile: []config.Entry{{Path: ".codex", Exclude: []config.Mask{{Pattern: ""}}}}},
		"cleanup": {Cleanup: []config.Mask{{Pattern: ""}}},
	}
	for name, rules := range cases {
		useRules(t, rules)
		err := Config([]string{"validate"})
		if got := exit.Of(err); got != exit.BadConfig {
			t.Errorf("%s: exit code is %v, want %v", name, got, exit.BadConfig)
		}
	}

	complaints := inspectProfile(
		[]config.Entry{{Path: ".codex", Include: []config.Mask{{Pattern: ""}}}}, nil)
	var found bool
	for _, c := range complaints {
		if c.Kind == "empty" {
			found = true
			if !c.Fatal {
				t.Error("an empty mask pattern was not marked fatal")
			}
		}
	}
	if !found {
		t.Error("an empty pattern in an include list was not reported")
	}
}

// TestValidateRefusesANegativeDepth checks point 4, on the entry itself and
// on one of its masks: neither can bound anything below zero.
func TestValidateRefusesANegativeDepth(t *testing.T) {
	cases := map[string]*config.Config{
		"entry": {Profile: []config.Entry{{Path: ".codex", Depth: depthPtr(-1)}}},
		"mask":  {Profile: []config.Entry{{Path: ".codex", Include: []config.Mask{{Pattern: "*.json", Depth: depthPtr(-1)}}}}},
	}
	for name, rules := range cases {
		useRules(t, rules)
		err := Config([]string{"validate"})
		if got := exit.Of(err); got != exit.BadConfig {
			t.Errorf("%s: exit code is %v, want %v", name, got, exit.BadConfig)
		}
	}

	complaints := inspectProfile([]config.Entry{{Path: ".codex", Depth: depthPtr(-1)}}, nil)
	if len(complaints) != 1 || complaints[0].Kind != "depth" || !complaints[0].Fatal {
		t.Errorf("got %+v", complaints)
	}
}

// TestValidateRefusesACleanupGlobTheCopierWouldAlsoRefuse checks point 5,
// reusing the copier's own reserved-names check rather than a second guess
// at NTUSER.DAT's companion files.
func TestValidateRefusesACleanupGlobTheCopierWouldAlsoRefuse(t *testing.T) {
	useRules(t, &config.Config{Cleanup: config.Masks([]string{"NTUSER*"})})
	err := Config([]string{"validate"})
	if got := exit.Of(err); got != exit.BadConfig {
		t.Errorf("exit code is %v, want %v", got, exit.BadConfig)
	}

	complaints := inspectProfile(nil, config.Masks([]string{"NTUSER*"}))
	var found bool
	for _, c := range complaints {
		if c.Kind == "cleanup" {
			found = true
			if !c.Fatal {
				t.Error("a cleanup glob the copier would refuse was not marked fatal")
			}
			if !strings.Contains(c.Message, "registry hive") {
				t.Errorf("unhelpful message: %s", c.Message)
			}
		}
	}
	if !found {
		t.Error("a cleanup glob the copier would refuse was not reported")
	}
}

// TestValidateReportsAPathListedTwiceInProfile checks point 6: waste, not
// breakage, so it must not fail the command.
func TestValidateReportsAPathListedTwiceInProfile(t *testing.T) {
	useRules(t, &config.Config{Profile: []config.Entry{{Path: ".claude"}, {Path: ".claude"}}})
	if err := Config([]string{"validate"}); err != nil {
		t.Errorf("a duplicate profile entry should not fail validate: %v", err)
	}

	complaints := inspectProfile([]config.Entry{{Path: ".claude"}, {Path: ".claude"}}, nil)
	var found bool
	for _, c := range complaints {
		if c.Kind == "profile-duplicate" {
			found = true
			if c.Fatal {
				t.Error("a duplicate profile entry was marked fatal")
			}
		}
	}
	if !found {
		t.Error("the duplicate profile entry was not reported")
	}
}

// TestValidateRefusesProfileEntriesRepeatedWithDifferentLimits is the fatal
// half of point 6: a path listed twice is waste only when both listings say
// the same thing. { path: .codex, exclude: [sessions/**] } followed by the
// bare ".codex" is not waste -- the second entry's mirroring would delete
// what the first entry's exclusion protected -- so validate has to refuse
// it rather than report it the same harmless way as a genuine repeat.
func TestValidateRefusesProfileEntriesRepeatedWithDifferentLimits(t *testing.T) {
	entries := []config.Entry{
		{Path: ".codex", Exclude: []config.Mask{{Pattern: "sessions/**"}}},
		{Path: ".codex"},
	}
	useRules(t, &config.Config{Profile: entries})
	err := Config([]string{"validate"})
	if got := exit.Of(err); got != exit.BadConfig {
		t.Errorf("exit code is %v, want %v", got, exit.BadConfig)
	}

	complaints := inspectProfile(entries, nil)
	var found bool
	for _, c := range complaints {
		if c.Kind == "profile-conflict" {
			found = true
			if !c.Fatal {
				t.Error("a duplicate with different limits was not marked fatal")
			}
		}
		if c.Kind == "profile-duplicate" {
			t.Errorf("a duplicate with different limits was reported as merely waste: %+v", c)
		}
	}
	if !found {
		t.Error("the conflicting duplicate was not reported")
	}
}

// TestValidateReportsAProfileEntryNamingASensitiveFile checks point 7:
// somebody may name .ssh or its neighbors on purpose, and wuserbox has to
// say so rather than either refuse it or stay silent.
func TestValidateReportsAProfileEntryNamingASensitiveFile(t *testing.T) {
	useRules(t, &config.Config{Profile: []config.Entry{{Path: ".ssh"}}})
	if err := Config([]string{"validate"}); err != nil {
		t.Errorf("naming a sensitive entry on purpose should not fail validate: %v", err)
	}

	complaints := inspectProfile([]config.Entry{{Path: ".ssh"}}, nil)
	var found bool
	for _, c := range complaints {
		if c.Kind == "sensitive" {
			found = true
			if c.Fatal {
				t.Error("a sensitive entry was marked fatal")
			}
		}
	}
	if !found {
		t.Error("naming a sensitive entry was not reported")
	}
}

// TestValidateReportsAFileInsideASensitiveDirectory is the spelling somebody
// would actually write. The sensitive table names ~/.ssh, but nobody copies a
// directory of keys by naming the directory -- they name the key. A check that
// matched the whole path against the table would answer only about ".ssh" and
// say nothing about ".ssh/id_rsa", which is the same mistake by the same
// route, made one segment further in. preset.Profile has always read the
// first segment for this; validate now does too.
func TestValidateReportsAFileInsideASensitiveDirectory(t *testing.T) {
	for _, path := range []string{".ssh/id_rsa", ".aws/credentials", ".gnupg/secring.gpg"} {
		complaints := inspectProfile([]config.Entry{{Path: path}}, nil)
		var found bool
		for _, c := range complaints {
			if c.Kind == "sensitive" {
				found = true
				if c.Fatal {
					t.Errorf("%s was marked fatal, and naming one on purpose is allowed", path)
				}
			}
		}
		if !found {
			t.Errorf("%s was not reported, and it is under a directory wuserbox protects", path)
		}
	}
	// And a path that merely starts with the same letters is not under it.
	for _, path := range []string{".sshconfig", ".claude/settings.json"} {
		for _, c := range inspectProfile([]config.Entry{{Path: path}}, nil) {
			if c.Kind == "sensitive" {
				t.Errorf("%s was called sensitive, and nothing protects it", path)
			}
		}
	}
}

// TestValidateReportsProfileLimitsOnAFileEntry checks the fatal half of
// point 8: a depth on an entry whose path is a plain file on this machine
// would be ignored by the copier, and that is worth saying without failing
// the file over it -- see the next test for the other half of the judgment
// call.
func TestValidateReportsProfileLimitsOnAFileEntry(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	entry := config.Entry{Path: ".claude.json", Depth: depthPtr(1)}
	useRules(t, &config.Config{Profile: []config.Entry{entry}})
	if err := Config([]string{"validate"}); err != nil {
		t.Errorf("a limit on a file entry should not fail validate: %v", err)
	}

	complaints := inspectProfile([]config.Entry{entry}, nil)
	var found bool
	for _, c := range complaints {
		if c.Kind == "profile-limits" {
			found = true
			if c.Fatal {
				t.Error("a limit on a file entry was marked fatal")
			}
		}
	}
	if !found {
		t.Error("depth on a file entry was not reported")
	}
}

// TestValidateSaysNothingAboutLimitsOnAProfileEntryThatDoesNotExist is the
// other half of point 8's judgment call: a rules file shared across
// machines names things some of them lack, and an entry whose path is not
// on this machine at all cannot be judged either way -- refusing it, or even
// flagging it, would be worse than the mistake this check exists for.
func TestValidateSaysNothingAboutLimitsOnAProfileEntryThatDoesNotExist(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	// Nothing written at home/.gemini.

	complaints := inspectProfile([]config.Entry{{Path: ".gemini", Depth: depthPtr(1)}}, nil)
	for _, c := range complaints {
		if c.Kind == "profile-limits" {
			t.Errorf("a path that does not exist at all was judged anyway: %+v", c)
		}
	}
}
