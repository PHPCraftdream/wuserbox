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
	if len(p.Cleanup) > 0 {
		fmt.Fprintf(&b, "\ncleanup would clear\n")
		for _, glob := range p.Cleanup {
			fmt.Fprintf(&b, "  %-24s %d file(s)\n", glob.Path, glob.Files)
		}
	}
	if len(p.Profile) > 0 {
		fmt.Fprintf(&b, "\nprofile would copy\n")
		for _, entry := range p.Profile {
			fmt.Fprintf(&b, "  %-24s %d file(s), %s", entry.Path, entry.Files, planBytes(entry.Bytes))
			if entry.Skipped > 0 {
				fmt.Fprintf(&b, ", %d skipped (source unchanged)", entry.Skipped)
			}
			b.WriteString("\n")
		}
	}
	return b.String(), nil
}

// planBytes renders a size the way somebody deciding whether an entry is
// worth trimming wants to read it, the same units internal/cli/inspect uses
// for the same reason -- one small helper repeated is cheaper than a shared
// one that would make a presentation package of two commands depend on each
// other for a line of arithmetic.
func planBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	value, exp := float64(n)/unit, 0
	for value >= unit && exp < 3 {
		value /= unit
		exp++
	}
	return fmt.Sprintf("%.1f %s", value, [...]string{"KB", "MB", "GB", "TB"}[exp])
}
