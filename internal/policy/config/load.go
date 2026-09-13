package config

import (
	"fmt"
	"os"

	ktav "github.com/ktav-lang/golang"
)

// Load reads the config, returning an empty one when the file is absent.
func Load() (*Config, error) {
	data, err := os.ReadFile(Path())
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
	return &c, nil
}
