// Package usage holds the help text: a short overview for orientation and a
// detailed entry for every command.
package usage

import "strings"

// Command is everything the help knows about one command.
type Command struct {
	// Name is the word typed after wuserbox.
	Name string
	// Summary is the single line shown in the overview.
	Summary string
	// Call is the shape of the command line, without the program name.
	Call string
	// Detail explains what the command does and when to reach for it.
	// Paragraphs are separated by a blank line and wrapped by hand.
	Detail string
	// Options are the flags this command reads.
	Options []Option
	// Examples are complete command lines, most useful first.
	Examples []string
	// Exits are the codes this command returns that the common set does not
	// cover, written as one line. Most commands have none and say so, which is
	// the point: an entry read on its own should never leave a reader guessing
	// whether the command has an answer of its own in its exit code.
	Exits string
	// Default marks the command wuserbox carries out when the first word is
	// not a command at all. Its call and its examples are therefore written
	// without a name in front, which is the shape people will type.
	Default bool
	// Elevates marks a command that asks for administrator rights.
	Elevates bool
	// Privileged marks a command barred inside a sandbox, because it widens
	// or withdraws permissions.
	Privileged bool
}

// String renders the entry as the detailed help for this command.
func (c Command) String() string {
	var b strings.Builder
	b.WriteString("wuserbox " + c.Name + " - " + c.Summary + "\n\nUSAGE\n  wuserbox " + c.Call + "\n")
	b.WriteString("\nDESCRIPTION\n" + indent(c.Detail) + "\n")
	if len(c.Options) > 0 {
		b.WriteString("\nOPTIONS\n")
		width := 0
		for _, o := range c.Options {
			if len(o.Name) > width {
				width = len(o.Name)
			}
		}
		for _, o := range c.Options {
			b.WriteString("  " + o.Name + strings.Repeat(" ", width-len(o.Name)+3) + o.Effect + "\n")
		}
	}
	if len(c.Examples) > 0 {
		b.WriteString("\nEXAMPLES\n")
		for _, e := range c.Examples {
			b.WriteString("  " + e + "\n")
		}
	}
	b.WriteString("\nEXIT CODES\n")
	if c.Exits != "" {
		b.WriteString("  " + c.Exits + "\n")
	} else {
		b.WriteString("  The common set, with nothing of its own.\n")
	}
	b.WriteString("  Run \"wuserbox --help\" for what each code means.\n")
	if notes := c.notes(); notes != "" {
		b.WriteString("\nNOTES\n" + notes)
	}
	return b.String()
}

func (c Command) notes() string {
	var b strings.Builder
	if c.Elevates {
		b.WriteString("  Asks for administrator rights, because it creates or removes a local\n" +
			"  group. You will see a consent prompt.\n")
	}
	if c.Privileged {
		b.WriteString("  Refuses to run inside a sandbox: a sandboxed process may not change\n" +
			"  its own permissions.\n")
	}
	return b.String()
}

// indent shifts a block of prose under a heading.
func indent(text string) string {
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = "  " + line
		}
	}
	return strings.Join(lines, "\n")
}
