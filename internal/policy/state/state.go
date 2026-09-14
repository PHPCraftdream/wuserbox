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
	// Marked says the grants below carry the mark that tells a permission
	// somebody asked for apart from one the preset offered. A record written
	// before that mark existed carries no such thing, and reading its entries
	// as offers would let an upgrade undo a narrowing made by hand.
	Marked bool `json:"marked"`
	// Labeled says every directory this sandbox may write to carries the Low
	// mandatory integrity label that lets a Low token write there.
	//
	// It decides whether the sandbox runs Low at all. Writing those labels
	// needs administrator rights, so a sandbox built before they existed — or
	// one whose labeling was refused — has none, and running it Low would
	// refuse it its own writes rather than protect anything. A sandbox in that
	// state is repaired, with the rights the repair needs, before it is used.
	Labeled bool `json:"labeled,omitempty"`
	// NoAI says the agent preset was explicitly withheld, by `init --no-ai`.
	// A plain run never carries that flag — configuring is not something a
	// run does — so this is what makes the decision outlast the command that
	// made it: without it, the very next run would have nothing to tell it
	// apart from a sandbox that never asked, and would offer the preset back.
	NoAI bool `json:"no_ai,omitempty"`
}
