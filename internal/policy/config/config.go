// Package config reads and writes ~/.wuserbox.ktav, the user's standing rules
// about which extra directories a project's sandbox may write to.
//
//	projects: [
//	    {
//	        dir: C:/Users/Computer/Desktop/pc/wuserbox
//	        rw: [
//	            C:/Users/Computer/Desktop/pc/tools
//	            C:/Users/Computer/Desktop/pc/logs
//	        ]
//	    }
//	]
package config

// Config is the whole file.
type Config struct {
	Projects []Rule `json:"projects"`
	// Profile lists the files and directories copied from the user's profile
	// into a sandbox's own thin profile before a run, each named as a path
	// relative to the profile root so a copy can land at the same relative
	// place under whatever a sandbox is given. An item is either that path,
	// spelled as every rules file so far has it, or an Entry, an object
	// carrying the path plus limits on the copy. It is pre-filled when this
	// file is first created and otherwise edited by hand, the same as the
	// project rules above it.
	Profile []Entry `json:"profile"`
	// Cleanup lists globs, relative to the profile root, cleared from the
	// sandbox's own profile before each fill. Separate from Profile because
	// it answers a different question -- what should not be sitting there --
	// and the two overlap only by coincidence: a cache worth clearing is
	// usually one nothing copies. Omitted means nothing is cleared.
	Cleanup []Mask `json:"cleanup,omitempty"`
}
