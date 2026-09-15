package preset

import (
	"os"
	"path/filepath"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
)

// Entry is one thing in the profile root that must stay out of a sandbox's
// reach, and what kind of thing it is. The kind matters when the entry is
// missing and has to be taken before a sandbox can claim the name: a tool that
// expects a directory is no better off finding an empty file there.
type Entry struct {
	Path        string
	IsDirectory bool
}

// sensitive lists what a shell or a tool reads with the user's own authority.
// The flag says whether the name belongs to a directory.
var sensitive = []struct {
	name        string
	isDirectory bool
}{
	{".profile", false}, {".bashrc", false}, {".bash_profile", false},
	{".bash_login", false}, {".bash_logout", false},
	{".zshrc", false}, {".zprofile", false}, {".zshenv", false},
	{".cshrc", false}, {".kshrc", false}, {".inputrc", false}, {".minttyrc", false},
	{".gitconfig", false}, {".gitattributes", false},
	{".npmrc", false}, {".yarnrc", false}, {".pnpmrc", false},
	{".netrc", false}, {".curlrc", false}, {".wgetrc", false},
	{".wuserbox.ktav", false},
	{".ssh", true}, {".gnupg", true}, {".aws", true}, {".azure", true},
	{".docker", true}, {".kube", true},
}

// shadowing lists the startup files a shell reads in order, most preferred
// first. Creating one that is missing would hide the one below it, so an empty
// placeholder is only safe for the entries after the first that exists.
var shadowing = [][]string{
	{".bash_profile", ".bash_login", ".profile"},
}

// Sensitive lists the entries that exist on this machine.
func Sensitive() []string {
	home := paths.Home()
	var out []string
	for _, entry := range sensitive {
		path := filepath.Join(home, entry.name)
		if _, err := os.Stat(path); err == nil {
			out = append(out, path)
		}
	}
	return out
}

// Missing lists the entries that do not exist yet and can safely be taken as
// empty placeholders, so a sandbox cannot get to the name first.
//
// An entry inside a shell's startup chain is left out while a file it would
// hide is in place; Shadowable reports those, so the caller can say so.
func Missing() []Entry {
	home := paths.Home()
	var out []Entry
	for _, entry := range sensitive {
		path := filepath.Join(home, entry.name)
		if _, err := os.Stat(path); err == nil {
			continue
		}
		if shadows(home, entry.name) {
			continue
		}
		out = append(out, Entry{Path: path, IsDirectory: entry.isDirectory})
	}
	return out
}

// Shadowable lists the missing entries that cannot be taken, because an empty
// one would hide a startup file the shell reads today.
func Shadowable() []string {
	home := paths.Home()
	var out []string
	for _, entry := range sensitive {
		if _, err := os.Stat(filepath.Join(home, entry.name)); err == nil {
			continue
		}
		if shadows(home, entry.name) {
			out = append(out, filepath.Join(home, entry.name))
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
