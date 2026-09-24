package profile

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

func cahFixture(t *testing.T) (string, string, []byte) {
	t.Helper()
	home := t.TempDir()
	dest := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv(config.EnvPath, filepath.Join(t.TempDir(), "rules.ktav"))
	bin := filepath.Join(home, ".claude", "cah-bin", "bin")
	lib := filepath.Join(home, ".claude", "cah-bin", "lib")
	cache := filepath.Join(home, ".claude", "cah-bin", "cache")
	for _, dir := range []string{bin, lib, cache} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for path, content := range map[string]string{
		filepath.Join(bin, "cah-status.js"): "status",
		filepath.Join(bin, "cah-stamp.js"):  "stamp",
		filepath.Join(lib, "helper.js"):     "helper",
		filepath.Join(cache, "stale.json"):  "cache",
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	from := filepath.Join(home, ".claude", "cah-bin", "bin", "cah-status.js")
	settings := map[string]any{
		"statusLine": map[string]string{"command": "node " + filepath.ToSlash(from)},
		"other":      "node " + from,
		"enabledPlugins": map[string]bool{
			"frontend-design@claude-plugins-official": false,
		},
	}
	data, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	rules := &config.Config{Profile: []config.Entry{
		{Path: ".claude/settings.json"},
		{Path: ".claude/cah-bin", Exclude: config.Masks([]string{"cache/**"})},
	}}
	if err := rules.Save(); err != nil {
		t.Fatal(err)
	}
	return home, dest, data
}

func TestCahCommandsUseTheCopiedBinAndLeaveTheSourceUntouched(t *testing.T) {
	home, dest, source := cahFixture(t)
	copied, prints, err := Copy(dest, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	settingsPath := filepath.Join(dest, ".claude", "settings.json")
	check := func() {
		t.Helper()
		data, err := os.ReadFile(settingsPath)
		if err != nil {
			t.Fatal(err)
		}
		var settings struct {
			StatusLine     struct{ Command string } `json:"statusLine"`
			Other          string                   `json:"other"`
			EnabledPlugins map[string]bool          `json:"enabledPlugins"`
		}
		if err := json.Unmarshal(data, &settings); err != nil {
			t.Fatal(err)
		}
		want := filepath.Join(dest, ".claude", "cah-bin", "bin", "cah-status.js")
		if !strings.Contains(settings.StatusLine.Command, filepath.ToSlash(want)) ||
			!strings.Contains(settings.Other, want) {
			t.Errorf("commands did not name the copied cah binary")
		}
		if settings.EnabledPlugins["frontend-design@claude-plugins-official"] {
			t.Error("a disabled plugin was enabled")
		}
	}
	check()
	if data, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json")); err != nil || !bytes.Equal(data, source) {
		t.Fatalf("source settings changed: %v", err)
	}
	for _, relative := range []string{"bin/cah-status.js", "bin/cah-stamp.js", "lib/helper.js"} {
		if _, err := os.Stat(filepath.Join(dest, ".claude", "cah-bin", filepath.FromSlash(relative))); err != nil {
			t.Fatalf("missing copied cah file %s: %v", relative, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dest, ".claude", "cah-bin", "cache", "stale.json")); !os.IsNotExist(err) {
		t.Errorf("cah cache was copied: %v", err)
	}
	if _, _, err := Copy(dest, copied, prints); err != nil {
		t.Fatal(err)
	}
	check()
}

func TestCahRebaseReplacesAStagedHardLinkWithoutWritingOutside(t *testing.T) {
	_, dest, source := cahFixture(t)
	copied, prints, err := Copy(dest, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	settings := filepath.Join(dest, ".claude", "settings.json")
	external := filepath.Join(t.TempDir(), "outside.json")
	outsideContent := bytes.Repeat([]byte{'x'}, len(source))
	if err := os.WriteFile(external, outsideContent, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(settings); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(external, settings); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Copy(dest, copied, prints); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(external); err != nil || !bytes.Equal(data, outsideContent) {
		t.Fatalf("external hard link target changed: %v", err)
	}
	if data, err := os.ReadFile(settings); err != nil || !strings.Contains(string(data), filepath.ToSlash(dest)) {
		t.Fatalf("settings copy was not rebased: %v", err)
	}
}

func TestCahRebaseDoesNotTurnAVanishedSettingsSourceIntoAnError(t *testing.T) {
	home, dest, _ := cahFixture(t)
	copied, prints, err := Copy(dest, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(home, ".claude", "settings.json")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Copy(dest, copied, prints); err != nil {
		t.Fatalf("a source retained for retry made cah rebasing fail: %v", err)
	}
}
