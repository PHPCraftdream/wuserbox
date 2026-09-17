package profile

import "strings"

// The one description of what the profile service builds into a sandbox's
// profile -- the registry hive and the transaction families Windows keeps
// beside it -- and the two questions asked of it, kept beside each other
// so they cannot drift apart again. The defect this file exists to correct
// was exactly that drift: one set of representative names, written for the
// glob question ("could this cleanup glob reach a reserved path"), was
// also read as the answer to the name question ("is this file a reserved
// path"). A glob broad enough to hit the representative is broad enough to
// hit its siblings; a name equal to the representative is equal to nothing
// else, and the siblings were swept by walks that reported success.
//
// The family scheme is Windows' transactional registry (TxR/KTM) naming,
// established from the names found beside real hives in forensics corpora
// of live profiles and from the scheme's own documentation, not invented
// here:
//
//	%FILE%                        the hive itself, with .LOG1 and .LOG2
//	%FILE%{%GUID%}.TM.blf         the transaction manager's CLFS base log
//	%FILE%{%GUID%}.TMContainer%020d.regtrans-ms
//	                              its containers -- a counter, zero-padded
//	                              to twenty digits, that moves on as
//	                              transactions are recycled (01, 02, ...)
//	%FILE%{%GUID%}.TxR.blf        the TxR root's own CLFS base log
//	%FILE%{%GUID%}.TxR.%d.regtrans-ms
//	                              the TxR log segments, indexed from 0
//	                              with no fixed width (0, 1, 2 seen)
//
// {%GUID%} is braces around 8-4-4-4-12 hexadecimal. The transaction
// manager's files carry one GUID and the TxR files another, both differing
// machine to machine and run to run, and more than one superseded family
// can sit beside one hive; only the shape is fixed, so the shape is what
// this description records. Both hives use it: NTUSER.DAT at the profile
// root, UsrClass.dat under AppData/Local/Microsoft/Windows -- a directory
// sharing no prefix with AppData/Local/Temp or with account.MakeProfile's
// own AppData/Local/Roaming, neither of which is the profile service's,
// and neither of which any shape here reaches.
//
// The name question reads the shapes as a membership test: reservedAt asks
// it of one folded concrete name. The glob question reads them as a
// language: refuseReservedCleanup asks, of a cleanup glob, whether its
// language meets a family's -- whether some name the shape allows is one
// the glob would match. That is the conservative reading the refusal
// needs, and it cannot lose an old refusal: every representative the old
// tables held is itself spelled inside its family's shape, so any glob
// matching one matches a language that still contains it, and the family's
// other members arrive with it instead of beside it.

// The examples spell real GUIDs observed in real profiles, in the same
// spellings the old tables held. They exist only so a refusal can name
// what it is refusing; nothing matches against them.
const (
	familyExampleGUID    = "a0876e4c-1cb1-11d9-9669-0800200c9a66"
	familyExampleTxRGUID = "53b39e3d-18c4-11ea-a811-000d3aa4692b"
	familyExampleCounter = "00000000000000000001"
)

// usrClassDir is where the profile service keeps the class hive, relative
// to the profile root. It shares no prefix with Temp or with
// account.MakeProfile's own Roaming, which is the whole reason a shape
// anchored here cannot reach them.
const usrClassDir = "AppData/Local/Microsoft/Windows"

// namePart is one piece of a reserved name's shape: a run of fixed
// characters, or a varying stretch drawn from one class -- the GUID's hex
// digits at their fixed 8-4-4-4-12 widths, the container counter's twenty
// digits, the TxR index's unbounded run. Literals are stored folded.
type namePart struct {
	literal string // folded characters that must appear verbatim
	hex     int    // exactly this many hex digits
	decimal int    // exactly this many decimal digits
	decRun  bool   // one or more decimal digits
}

func (p namePart) accepts(c byte) bool {
	switch {
	case p.hex > 0:
		return c >= '0' && c <= '9' || c >= 'A' && c <= 'F'
	case p.decimal > 0 || p.decRun:
		return c >= '0' && c <= '9'
	default:
		return strings.IndexByte(p.literal, c) >= 0
	}
}

// reservedShape is one family: the directory it sits in, relative to the
// profile root and spelled with forward slashes (empty for the profile
// root itself), the shape of its members' names, and a real member kept
// for refusal messages only.
type reservedShape struct {
	dir     string // already folded
	name    []namePart
	example string // a full root-relative member path, spelled for the message
	hive    bool   // the hive itself, which refusal words differently from its companions

	segs [][]famChar // the shape as the glob question reads it
}

// reservedFamilies is the description both readers consume: the root
// hive's family, the class hive's, and ntuser.ini, which sits at the root
// beside NTUSER.DAT and is Windows' own.
var reservedFamilies = func() (out []reservedShape) {
	out = append(out, baseShapes("", "NTUSER.DAT")...)
	out = append(out, reservedShape{
		dir: "", hive: false, example: "ntuser.ini",
		name: []namePart{{literal: foldedName("ntuser.ini")}},
		segs: famSegsOf("", []namePart{{literal: foldedName("ntuser.ini")}}),
	})
	out = append(out, baseShapes(usrClassDir, "UsrClass.dat")...)
	return out
}()

// baseShapes builds one hive's family: the hive, its two logs, and the
// four GUID-bearing transaction shapes, all in dir.
func baseShapes(dir, base string) (out []reservedShape) {
	prefix := ""
	if dir != "" {
		prefix = dir + "/"
	}
	counter := make([]namePart, 20)
	for i := range counter {
		counter[i] = namePart{decimal: 1}
	}
	withGUID := func(suffix string) []namePart {
		return joined(
			[]namePart{{literal: foldedName(base + "{")}},
			guidChain(),
			[]namePart{{literal: foldedName(suffix)}},
		)
	}
	example := func(name string) string { return prefix + name }
	return append(out,
		shape(dir, true, example(base),
			[]namePart{{literal: foldedName(base)}}),
		shape(dir, false, example(base+".LOG1"),
			[]namePart{{literal: foldedName(base + ".LOG1")}}),
		shape(dir, false, example(base+".LOG2"),
			[]namePart{{literal: foldedName(base + ".LOG2")}}),
		shape(dir, false, example(base+"{"+familyExampleGUID+"}.TM.blf"),
			withGUID("}.TM.blf")),
		shape(dir, false, example(base+"{"+familyExampleGUID+"}.TMContainer"+familyExampleCounter+".regtrans-ms"),
			joined(withGUID("}.TMContainer"), counter, []namePart{{literal: foldedName(".regtrans-ms")}})),
		shape(dir, false, example(base+"{"+familyExampleTxRGUID+"}.TxR.blf"),
			withGUID("}.TxR.blf")),
		shape(dir, false, example(base+"{"+familyExampleTxRGUID+"}.TxR.0.regtrans-ms"),
			joined(withGUID("}.TxR."), []namePart{{decRun: true}}, []namePart{{literal: foldedName(".regtrans-ms")}})),
	)
}

// shape folds the directory, spells the shape, and builds the form the
// glob question reads, once, so the two readings of one family cannot
// disagree about what the family is.
func shape(dir string, hive bool, example string, parts []namePart) reservedShape {
	foldedDir := foldedName(dir)
	return reservedShape{
		dir: foldedDir, name: parts, example: example, hive: hive,
		segs: famSegsOf(foldedDir, parts),
	}
}

// guidChain is the GUID body and its dashes, at the fixed widths
// StringFromGUID2 spells them with.
func guidChain() []namePart {
	return []namePart{
		{hex: 8}, {literal: "-"},
		{hex: 4}, {literal: "-"},
		{hex: 4}, {literal: "-"},
		{hex: 4}, {literal: "-"},
		{hex: 12},
	}
}

func joined(parts ...[]namePart) []namePart {
	var out []namePart
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// matches answers whether one path, already folded by the package's fold
// and spelled with forward slashes relative to the profile root, names a
// member of this family.
func (s reservedShape) matches(folded string) bool {
	var dir, name string
	if i := strings.LastIndexByte(folded, '/'); i >= 0 {
		dir, name = folded[:i], folded[i+1:]
	} else {
		name = folded
	}
	if s.dir != "" {
		if dir != s.dir {
			return false
		}
	} else if dir != "" {
		return false
	}
	return nameMatches(s.name, name)
}

// nameMatches answers whether one folded name is spelled the way the shape
// says a member is spelled.
func nameMatches(parts []namePart, folded string) bool {
	pos := 0
	for _, p := range parts {
		switch {
		case p.literal != "":
			if !strings.HasPrefix(folded[pos:], p.literal) {
				return false
			}
			pos += len(p.literal)
		case p.decRun:
			start := pos
			for pos < len(folded) && folded[pos] >= '0' && folded[pos] <= '9' {
				pos++
			}
			if pos == start {
				return false
			}
		default:
			for n := p.hex + p.decimal; n > 0; n-- {
				if pos >= len(folded) || !p.accepts(folded[pos]) {
					return false
				}
				pos++
			}
		}
	}
	return pos == len(folded)
}

// famChar is one position a family name can occupy, as the glob question
// reads it: a fixed character, one character of a class, or -- after a
// TxR index's first digit -- any further number of digits.
type famChar struct {
	literal byte
	hex     bool
	decimal bool
	decMore bool
}

func famSegsOf(dir string, parts []namePart) [][]famChar {
	var segs [][]famChar
	if dir != "" {
		for _, seg := range strings.Split(dir, "/") {
			segs = append(segs, famCharsOf([]namePart{{literal: seg}}))
		}
	}
	return append(segs, famCharsOf(parts))
}

func famCharsOf(parts []namePart) []famChar {
	var out []famChar
	for _, p := range parts {
		switch {
		case p.literal != "":
			for i := 0; i < len(p.literal); i++ {
				out = append(out, famChar{literal: p.literal[i]})
			}
		case p.decRun:
			out = append(out, famChar{decimal: true}, famChar{decMore: true})
		default:
			class := famChar{hex: p.hex > 0, decimal: p.decimal > 0}
			for n := p.hex + p.decimal; n > 0; n-- {
				out = append(out, class)
			}
		}
	}
	return out
}

// famAccepts answers whether one family position can hold one folded
// character.
func famAccepts(c famChar, b byte) bool {
	switch {
	case c.hex:
		return b >= '0' && b <= '9' || b >= 'A' && b <= 'F'
	case c.decimal || c.decMore:
		return b >= '0' && b <= '9'
	default:
		return c.literal == b
	}
}

// segmentReaches answers whether a glob segment's language -- literal
// characters, ?, and *, the whole of matchSegment's alphabet -- meets one
// family name segment: whether some name the shape allows is one the glob
// would match. The sweep walks both sides at once; a * may consume any
// number of the name's characters, each of which the shape must still
// allow, and that is what makes the question the conservative one -- the
// glob is answered against every member of the family at once, not
// against one example of it.
func segmentReaches(glob string, fam []famChar) bool {
	glob = foldedName(glob)
	reach := make([]bool, len(fam)+1)
	next := make([]bool, len(fam)+1)
	star := make([]bool, len(fam)+1)
	reach[0] = true
	// A star, once its turn in the glob has come, may eat any run of the
	// name's remaining characters without eating another glob character --
	// that is what one star matching "any run" means -- so before each
	// glob character, and once at the end, every state a star sits at
	// reaches every later state of the name.
	starSpread := func(reach []bool) {
		for j := 0; j <= len(fam); j++ {
			if star[j] && reach[j] {
				for k := j + 1; k <= len(fam); k++ {
					reach[k] = true
				}
			}
		}
		// A decMore position holds zero or more further digits, so it may
		// also be passed without eating anything -- an index of one digit
		// stops after its first.
		for j := 0; j < len(fam); j++ {
			if fam[j].decMore && reach[j] {
				reach[j+1] = true
			}
		}
	}
	for i := 0; i < len(glob); i++ {
		starSpread(reach)
		for j := range next {
			next[j] = false
		}
		c := glob[i]
		for j := 0; j < len(fam); j++ {
			if !reach[j] {
				continue
			}
			switch c {
			case '*':
				star[j] = true
				next[j] = true // the star may also match nothing here
			case '?':
				next[j+1] = true
			default:
				if famAccepts(fam[j], c) {
					next[j+1] = true
					// A decMore position eats a digit and may eat more
					// after it, so eating one leaves it still in play.
					if fam[j].decMore && c >= '0' && c <= '9' {
						next[j] = true
					}
				}
			}
		}
		// A star at the end of the name has nothing left to eat.
		if c == '*' && reach[len(fam)] {
			star[len(fam)] = true
			next[len(fam)] = true
		}
		reach, next = next, reach
	}
	starSpread(reach)
	return reach[len(fam)]
}

// pathReaches asks segmentReaches of whole paths: a glob split on its
// separators against a family's segments. It is matchSegments' own
// traversal -- ** across any number of whole segments, none included --
// with the per-segment question turned into the language question.
func pathReaches(segs []string, fam [][]famChar) bool {
	for len(segs) > 0 {
		if segs[0] == "**" {
			for i := 0; i <= len(fam); i++ {
				if pathReaches(segs[1:], fam[i:]) {
					return true
				}
			}
			return false
		}
		if len(fam) == 0 || !segmentReaches(segs[0], fam[0]) {
			return false
		}
		segs, fam = segs[1:], fam[1:]
	}
	return len(fam) == 0
}

// reservedFamilyReachedBy answers the question refuseReservedCleanup
// exists for: could this cleanup glob match some member of some reserved
// family, and if so, which family first -- for the message. It is
// matchMask's own semantics turned around: a pattern with no separator is
// tested against the last segment, a name-only glob reaching by name
// wherever the file sits; a pattern carrying a separator is anchored at
// the profile root; both sides go through the package's fold -- so a glob
// the walk would honor cannot slip past the guard that refuses it at the
// door.
func reservedFamilyReachedBy(pattern string) (reservedShape, bool) {
	segs := strings.Split(pattern, "/")
	nameOnly := len(segs) == 1
	for i := range segs {
		segs[i] = foldedName(segs[i])
	}
	for _, fam := range reservedFamilies {
		if nameOnly {
			if segmentReaches(segs[0], fam.segs[len(fam.segs)-1]) {
				return fam, true
			}
			continue
		}
		if pathReaches(segs, fam.segs) {
			return fam, true
		}
	}
	return reservedShape{}, false
}
