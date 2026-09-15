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
	// place under whatever a sandbox is given. It is pre-filled when this
	// file is first created and otherwise edited by hand, the same as the
	// project rules above it.
	Profile []string `json:"profile"`
}
