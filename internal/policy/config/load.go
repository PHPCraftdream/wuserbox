package config

import (
	"fmt"
	"os"

	ktav "github.com/ktav-lang/golang"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
)

// Load reads the config, returning an empty one when the file is absent.
func Load() (*Config, error) {
	data, err := paths.ReadWhole(Path())
	if os.IsNotExist(err) {
		return &Config{}, nil
	}
	if err != nil {
		return nil, err
	}
	var c Config
	if err := ktav.LoadsInto(string(data), &c); err != nil {
		return nil, fmt.Errorf("%s: %w", Path(), err)
	}
	if err := checkSource(string(data)); err != nil {
		return nil, fmt.Errorf("%s: %w", Path(), err)
	}
	return &c, nil
}
