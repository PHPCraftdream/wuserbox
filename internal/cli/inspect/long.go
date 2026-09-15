// The long form of the list: everything wuserbox knows about each sandbox,
// a block at a time. Kept beside list.go rather than made a command of its
// own, because "show me the sandboxes" is one question and the answer only
// differs in how much of it is printed.

package inspect

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox/facts"
	"github.com/PHPCraftdream/wuserbox/internal/win/group"
)

// SizeOnDisk is what a sandbox takes up and when that was found out. Taken
// travels with it everywhere, because measuring is slow enough that the
// number is always from some earlier moment, and one shown without its date
// is a number that quietly stops being true.
type SizeOnDisk struct {
	Bytes   int64     `json:"bytes"`
	Files   int       `json:"files"`
	Partial bool      `json:"partial"`
	Taken   time.Time `json:"taken"`
}

// describe gathers everything known about each sandbox, in a fixed order so
// two runs that change nothing print the same thing.
//
// Nothing here fails on a sandbox it cannot read. A record that is missing
// or damaged leaves the fields it would have filled empty, and the listing
// says so rather than refusing to describe the rest: this is the command
// somebody reaches for precisely when something is wrong.
func describe(entries []group.Entry) []Sandbox {
	out := make([]Sandbox, 0, len(entries))
	for _, entry := range entries {
		out = append(out, describeOne(entry))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Group < out[j].Group })
	return out
}

func describeOne(entry group.Entry) Sandbox {
	found := Sandbox{Group: entry.Name, Dir: entry.Dir}
	if s, err := state.Load(entry.Name); err == nil && s != nil {
		found.Account = s.Account
		found.Profile = s.Profile
		found.Temp = s.Temp
		for _, held := range s.Grants {
			if held.Kind.Writable() {
				found.Write = append(found.Write, held.Path)
			} else {
				found.Read = append(found.Read, held.Path)
			}
		}
		sort.Strings(found.Write)
		sort.Strings(found.Read)
	}
	if life, err := facts.Times(entry.Name); err == nil && life != nil {
		found.Made = &life.Made
		found.Used = &life.Used
	}
	if size, err := facts.Known(entry.Name); err == nil && size != nil {
		found.Size = &SizeOnDisk{
			Bytes: size.Bytes, Files: size.Files, Partial: size.Partial, Taken: size.Taken,
		}
	}
	return found
}

// blocks renders the long form: one block per sandbox, a blank line between.
func blocks(sandboxes []Sandbox) string {
	var b strings.Builder
	for i, s := range sandboxes {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(block(s))
	}
	return b.String()
}

func block(s Sandbox) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", s.Group)
	field(&b, "project", s.Dir)
	field(&b, "account", orNot(s.Account, "none -- run `wuserbox --init` to give it one"))
	field(&b, "profile", orNot(s.Profile, "not recorded"))
	field(&b, "on disk", describeSize(s.Size))
	field(&b, "temp", orNot(s.Temp, "not recorded"))
	paths(&b, "write", s.Write)
	paths(&b, "read", s.Read)
	field(&b, "made", moment(s.Made))
	field(&b, "last used", moment(s.Used))
	return b.String()
}

// field writes one labeled line, with the labels in a column so a block can
// be read down its left edge.
func field(b *strings.Builder, label, value string) {
	fmt.Fprintf(b, "  %-10s %s\n", label, value)
}

// paths writes a list under one label, the rest of it aligned under the
// first, so which paths belong to which permission stays obvious however
// many there are.
func paths(b *strings.Builder, label string, list []string) {
	if len(list) == 0 {
		field(b, label, "nothing")
		return
	}
	field(b, label, list[0])
	for _, path := range list[1:] {
		field(b, "", path)
	}
}

func orNot(value, missing string) string {
	if value == "" {
		return missing
	}
	return value
}

// moment prints a time this machine actually observed, or says it never did.
// The two are different answers and a listing that printed a zero time for
// the second would be inventing one.
func moment(at *time.Time) string {
	if at == nil || at.IsZero() {
		return "not recorded"
	}
	return at.Local().Format("2006-01-02 15:04")
}

// describeSize says how much, how many files, and when that was found out.
// Never measured and empty are different answers, and so is a number that
// could not include everything.
func describeSize(size *SizeOnDisk) string {
	if size == nil {
		return "not measured"
	}
	text := fmt.Sprintf("%s in %d files, measured %s",
		bytes(size.Bytes), size.Files, size.Taken.Local().Format("2006-01-02 15:04"))
	if size.Partial {
		text += " (at least: something in it could not be read)"
	}
	return text
}

// bytes renders a size the way somebody deciding whether to delete something
// wants to read it.
func bytes(n int64) string {
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
