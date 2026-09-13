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
}
