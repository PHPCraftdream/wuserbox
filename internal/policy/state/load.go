package state

import (
	"encoding/json"
	"os"
)

// Load reads the state for a group, returning nil when the sandbox has never
// been initialized.
func Load(group string) (*State, error) {
	data, err := os.ReadFile(Path(group))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}
