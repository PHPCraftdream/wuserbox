package config

import (
	"os"
	"path/filepath"

	"github.com/PHPCraftdream/wuserbox/internal/paths"
)

// EnvPath overrides the config location; tests and unusual setups use it.
const EnvPath = "WUSERBOX_CONFIG"

// Path is the config file location.
func Path() string {
	if custom := os.Getenv(EnvPath); custom != "" {
		return custom
	}
	return filepath.Join(paths.Home(), ".wuserbox.ktav")
}
