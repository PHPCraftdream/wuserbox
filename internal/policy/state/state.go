// Package state persists what a sandbox was given, so grants can be listed and
// rolled back later. The authoritative permissions live in NTFS; this is a
// record of what wuserbox itself applied.
package state

import "github.com/PHPCraftdream/wuserbox/internal/policy/grant"

// State is one sandbox: its group, project directory, private temp directory
// and the grants applied so far.
type State struct {
	Group string `json:"group"`
	// SID identifies the group in access control entries. It is resolved once,
	// so grants survive even if name lookup is unavailable later.
	SID    string       `json:"sid"`
	Dir    string       `json:"dir"`
	Temp   string       `json:"temp"`
	Grants []grant.Spec `json:"grants"`
	// Profile is the sandbox's own thin profile directory: an empty
	// registry hive and three folders a shell expects, made by --init and
	// loaded as this account's HKEY_CURRENT_USER on every run. Kept here
	// rather than recomputed from Group, the same reason Temp is: removal
	// has to find it even from a record a naming change never touches.
	Profile string `json:"profile,omitempty"`
	// Marked says the grants below carry the mark that tells a permission
	// somebody asked for apart from one the preset offered. A record written
	// before that mark existed carries no such thing, and reading its entries
	// as offers would let an upgrade undo a narrowing made by hand.
	Marked bool `json:"marked"`
	// NoAI says the agent preset was explicitly withheld, by `init --no-ai`.
	// A plain run never carries that flag — configuring is not something a
	// run does — so this is what makes the decision outlast the command that
	// made it: without it, the very next run would have nothing to tell it
	// apart from a sandbox that never asked, and would offer the preset back.
	NoAI bool `json:"no_ai,omitempty"`
	// Account is the local user account made for this sandbox: a member of
	// nothing but Group, BUILTIN\Users and group.ReadGroup. Kept here rather
	// than recomputed from Group on every use because older sandboxes carry a
	// shorter legacy name and must keep it through migration, the same reason
	// Group is kept rather than recomputed from Dir.
	Account string `json:"account,omitempty"`
	// Secret is Account's password, sealed with account.Protect and stored
	// as base64. It has to be kept, not only created: CreateProcessWithLogonW
	// needs the password on every run, not only when the account is made.
	Secret string `json:"secret,omitempty"`
}
