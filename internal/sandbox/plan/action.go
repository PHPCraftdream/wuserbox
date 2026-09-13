package plan

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Action is one change a command would make, for the commands whose work is
// too small to be a whole plan: handing over a single directory, forgetting a
// rule, removing a sandbox.
type Action struct {
	// Does is the verb: grant, revoke, record, forget, delete.
	Does string `json:"does"`
	// What is the thing it happens to, usually a path.
	What string `json:"what"`
	// Detail is anything worth adding, such as the access or the file the
	// change is written to. It may be empty.
	Detail string `json:"detail,omitempty"`
}

// RenderActions writes a list of changes, as lines or as an object.
func RenderActions(actions []Action, asJSON bool) (string, error) {
	if asJSON {
		if actions == nil {
			actions = []Action{}
		}
		encoded, err := json.MarshalIndent(map[string]any{"actions": actions}, "", "  ")
		if err != nil {
			return "", err
		}
		return string(encoded) + "\n", nil
	}
	if len(actions) == 0 {
		return "nothing to do\n", nil
	}
	var b strings.Builder
	b.WriteString("would:\n")
	for _, action := range actions {
		fmt.Fprintf(&b, "  %s %s", action.Does, action.What)
		if action.Detail != "" {
			fmt.Fprintf(&b, "  (%s)", action.Detail)
		}
		b.WriteString("\n")
	}
	return b.String(), nil
}
