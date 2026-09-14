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
		// The whole of ~/.config, not the agent directories inside it: tools
		// keep their settings there and expect to be able to write them.
		//
		// Nothing under it is listed separately, and that matters. A
		// permission set directly on a subdirectory is read before a refusal
		// handed down from above it, so `grant ~/.config --ro` would refuse
		// the directory and leave anything listed inside it writable.
		//
		// It is wider than the rest of this list, and everything already in it
		// becomes writable, so narrow it with `grant ~/.config --ro` if that is
		// not wanted.
		join(home, ".config"),
		join(home, ".claude"), join(home, ".claude-flow"), join(home, ".agents"), join(local, "claude-cli-nodejs"),
		join(home, ".codex"), join(roaming, "Codex"), join(local, "Codex"),
		join(home, ".crush"),
		join(home, ".rush"), join(local, "rush"),
		join(home, ".gemini"), join(home, ".grok"), join(home, ".qwen"),
		join(home, ".zai"), join(home, ".zcode"),
		join(home, ".local", "share", "opencode"), join(home, ".cache", "opencode"),
		join(home, ".factory"), join(home, ".kilocode"), join(home, ".continue"), join(home, ".trae"),
		join(home, ".junie"), join(home, ".lingma"), join(home, ".cagent"),
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
