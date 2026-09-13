// Package preset knows which directories AI coding agents need, and which
// files must stay out of their reach.
package preset

import (
	"os"
	"path/filepath"

	"github.com/PHPCraftdream/wuserbox/internal/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
)

// AI returns grants for the agent state directories that exist on this
// machine. The profile root is never included: handing it over would make
// every dotfile already in it writable, because Windows pushes an inherited
// permission down to the files that are already there.
func AI() []grant.Spec {
	home := paths.Home()
	local := os.Getenv("LOCALAPPDATA")
	roaming := os.Getenv("APPDATA")
	join := filepath.Join

	dirs := []string{
		join(home, ".claude"), join(home, ".claude-flow"), join(home, ".agents"), join(local, "claude-cli-nodejs"),
		join(home, ".codex"), join(roaming, "Codex"), join(local, "Codex"),
		join(home, ".crush"),
		join(home, ".rush"), join(home, ".config", "rush"), join(local, "rush"),
		join(home, ".gemini"), join(home, ".grok"), join(home, ".qwen"),
		join(home, ".zai"), join(home, ".zcode"),
		join(home, ".config", "opencode"), join(home, ".local", "share", "opencode"), join(home, ".cache", "opencode"),
		join(home, ".factory"), join(home, ".kilocode"), join(home, ".continue"), join(home, ".trae"),
		join(home, ".junie"), join(home, ".lingma"), join(home, ".cagent"), join(home, ".config", "cagent"),
		join(roaming, "Goose"), join(local, "Goose"),
	}
	files := []string{join(home, ".claude.json")}

	var out []grant.Spec
	for _, dir := range dirs {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			out = append(out, grant.Spec{Path: dir, Kind: grant.RW})
		}
	}
	for _, file := range files {
		if info, err := os.Stat(file); err == nil && !info.IsDir() {
			out = append(out, grant.Spec{Path: file, Kind: grant.File})
		}
	}
	return out
}
