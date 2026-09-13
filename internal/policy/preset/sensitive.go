package preset

import (
	"os"
	"path/filepath"

	"wuserbox/internal/paths"
)

// sensitiveNames are entries in the profile root that a shell or a tool reads
// with the user's own authority. A sandbox must never be able to change them.
var sensitiveNames = []string{
	".profile", ".bashrc", ".bash_profile", ".bash_login", ".bash_logout",
	".zshrc", ".zprofile", ".zshenv", ".cshrc", ".kshrc", ".inputrc", ".minttyrc",
	".gitconfig", ".gitattributes", ".npmrc", ".yarnrc", ".pnpmrc",
	".netrc", ".curlrc", ".wgetrc", ".ssh", ".gnupg", ".aws", ".azure",
	".docker", ".kube", ".wuserbox.ktav",
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
