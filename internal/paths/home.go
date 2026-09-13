package paths

import "os"

// Home is the calling user's profile directory.
func Home() string {
	if h := os.Getenv("USERPROFILE"); h != "" {
		return h
	}
	h, _ := os.UserHomeDir()
	return h
}
