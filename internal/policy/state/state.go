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
}
