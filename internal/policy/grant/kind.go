// Package grant expresses sandbox permissions as access control entries.
package grant

import "github.com/PHPCraftdream/wuserbox/internal/win/acl"

// Kind is the access a sandbox gets on one path.
type Kind string

const (
	// RW allows creating, changing and deleting anything under a directory.
	RW Kind = "rw"
	// RO allows reading a directory that the sandbox could not otherwise
	// reach, for example one that a refusal covers.
	RO Kind = "ro"
	// File allows changing a single file in place, without any access to the
	// directory around it.
	File Kind = "file"
	// HomeTop allows creating files directly in a directory, and changing the
	// files created there afterwards, without reaching its subdirectories.
	// Agents that rewrite a dotfile through a temporary file and a rename
	// need this, but it also makes every file already in that directory
	// writable, so wuserbox does not use it for the profile root by default.
	HomeTop Kind = "home-top"
)

// Entries expands a Kind into the access control entries it applies.
func (k Kind) Entries() []acl.ACE {
	const subtree = acl.InheritObjects | acl.InheritContainers
	switch k {
	case RW:
		return []acl.ACE{{Access: acl.AccessModify, Inheritance: subtree}}
	case RO:
		return []acl.ACE{{Access: acl.AccessReadExecute, Inheritance: subtree}}
	case File:
		return []acl.ACE{{Access: acl.AccessModify, Inheritance: acl.InheritNone}}
	case HomeTop:
		return []acl.ACE{
			{Access: acl.AccessCreateFiles, Inheritance: acl.InheritNone},
			{Access: acl.AccessModify, Inheritance: acl.InheritObjects | acl.InheritOnly | acl.InheritNoPropagate},
		}
	default:
		return nil
	}
}

// Writable reports whether a kind hands out the right to change anything.
func (k Kind) Writable() bool {
	return k == RW || k == File || k == HomeTop
}
