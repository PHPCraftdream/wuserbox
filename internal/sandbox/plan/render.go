package plan

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Render writes the plan out, as lines for a person or as an object for a
// program. The two carry the same facts, so a script and a reader never see
// different answers.
func Render(p Plan, asJSON bool) (string, error) {
	if asJSON {
		encoded, err := json.MarshalIndent(p, "", "  ")
		if err != nil {
			return "", err
		}
		return string(encoded) + "\n", nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "sandbox   %s\n", p.Group)
	fmt.Fprintf(&b, "project   %s\n", p.Dir)
	fmt.Fprintf(&b, "temp      %s\n", p.Temp)
	if len(p.Entries) > 0 {
		b.WriteString("\npermissions\n")
		width := 0
		for _, entry := range p.Entries {
			if len(entry.Path) > width {
				width = len(entry.Path)
			}
		}
		for _, entry := range p.Entries {
			fmt.Fprintf(&b, "  %-4s %s%s  from %s\n", entry.Kind, entry.Path,
				strings.Repeat(" ", width-len(entry.Path)), entry.Source)
		}
	}
	if len(p.Reserved) > 0 {
		fmt.Fprintf(&b, "\nreserved as empty files, so the sandbox cannot claim them\n")
		for _, path := range p.Reserved {
			fmt.Fprintf(&b, "  %s\n", path)
		}
	}
	if len(p.Unreserved) > 0 {
		fmt.Fprintf(&b, "\nleft open, because an empty file would hide a real one\n")
		for _, path := range p.Unreserved {
			fmt.Fprintf(&b, "  %s\n", path)
		}
	}
	return b.String(), nil
}
