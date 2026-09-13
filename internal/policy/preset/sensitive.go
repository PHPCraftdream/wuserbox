package preset

import (
	"os"
	"path/filepath"

	"github.com/PHPCraftdream/wuserbox/internal/paths"
)

// sensitiveNames are entries in the profile root that a shell or a tool reads
// with the user's own authority. A sandbox must never be able to change them,
// nor to create one that is missing: an empty file it controls is as good as a
// rewritten one.
var sensitiveNames = []string{
	".profile", ".bashrc", ".bash_profile", ".bash_login", ".bash_logout",
	".zshrc", ".zprofile", ".zshenv", ".cshrc", ".kshrc", ".inputrc", ".minttyrc",
	".gitconfig", ".gitattributes", ".npmrc", ".yarnrc", ".pnpmrc",
	".netrc", ".curlrc", ".wgetrc", ".ssh", ".gnupg", ".aws", ".azure",
	".docker", ".kube", ".wuserbox.ktav",
}

// shadowing lists the startup files a shell reads in order, most preferred
// first. Creating one that is missing would hide the one below it, so an empty
// placeholder is only safe for the entries after the first that exists.
var shadowing = [][]string{
	{".bash_profile", ".bash_login", ".profile"},
}

// Sensitive lists the entries from that set which exist on this machine.
func Sensitive() []string {
	home := paths.Home()
	var out []string
	for _, name := range sensitiveNames {
		path := filepath.Join(home, name)
		if _, err := os.Stat(path); err == nil {
			out = append(out, path)
		}
	}
	return out
}

// Missing lists the sensitive entries that do not exist yet and can safely be
// created as empty placeholders, so a sandbox cannot get there first.
//
// An entry inside a shell's startup chain is only included once a file it
// cannot shadow is already there; otherwise creating it would change which
// startup file the shell reads. Those remain reachable and are reported by
// Shadowable so the caller can warn.
func Missing() []string {
	home := paths.Home()
	var out []string
	for _, name := range sensitiveNames {
		if _, err := os.Stat(filepath.Join(home, name)); err == nil {
			continue
		}
		if shadows(home, name) {
			continue
		}
		out = append(out, filepath.Join(home, name))
	}
	return out
}

// Shadowable lists the missing entries that cannot be pre-created, because an
// empty one would hide a startup file the shell reads today.
func Shadowable() []string {
	home := paths.Home()
	var out []string
	for _, name := range sensitiveNames {
		if _, err := os.Stat(filepath.Join(home, name)); err == nil {
			continue
		}
		if shadows(home, name) {
			out = append(out, filepath.Join(home, name))
		}
	}
	return out
}

// shadows reports whether creating name would hide a file further down its
// shell's reading order.
func shadows(home, name string) bool {
	for _, chain := range shadowing {
		position := -1
		for i, entry := range chain {
			if entry == name {
				position = i
			}
		}
		if position < 0 {
			continue
		}
		for _, below := range chain[position+1:] {
			if _, err := os.Stat(filepath.Join(home, below)); err == nil {
				return true
			}
		}
	}
	return false
}
