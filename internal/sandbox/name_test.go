package sandbox

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/win/group"
)

func TestNameIsStableAndReadable(t *testing.T) {
	dir := t.TempDir()
	name, norm, err := Name(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(name, group.Prefix) {
		t.Errorf("name %q lacks prefix %q", name, group.Prefix)
	}
	if !strings.Contains(name, slug(filepath.Base(norm))) {
		t.Errorf("name %q does not mention folder %q", name, filepath.Base(norm))
	}
	again, _, err := Name(dir)
	if err != nil {
		t.Fatal(err)
	}
	if again != name {
		t.Errorf("not stable: %q then %q", name, again)
	}
}

func TestNameIgnoresSpellingOfSamePath(t *testing.T) {
	dir := t.TempDir()
	want, _, err := Name(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, spelling := range []string{
		strings.ToUpper(dir),
		dir + string(filepath.Separator),
		filepath.ToSlash(dir),
		filepath.Join(dir, "sub", ".."),
	} {
		got, _, err := Name(spelling)
		if err != nil {
			t.Fatalf("%s: %v", spelling, err)
		}
		if got != want {
			t.Errorf("%s gave %q, want %q", spelling, got, want)
		}
	}
}

func TestNameDiffersPerDirectory(t *testing.T) {
	first, _, err := Name(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := Name(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Errorf("two directories share the name %q", first)
	}
}

func TestSlugKeepsGroupNamesLegal(t *testing.T) {
	cases := map[string]string{
		"wuserbox":              "wuserbox",
		"my project":            "my_project",
		"tools/v2":              "tools_v2",
		"...":                   "root",
		"":                      "root",
		strings.Repeat("x", 60): strings.Repeat("x", 32),
	}
	for in, want := range cases {
		if got := slug(in); got != want {
			t.Errorf("slug(%q) = %q, want %q", in, got, want)
		}
	}
}
