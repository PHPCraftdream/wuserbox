package profile

import (
	"path/filepath"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/base/exit"
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
)

// What cleanup may never take is described once, in families.go: the two
// hives and the transaction families Windows builds beside them, shapes
// rather than examples. refuseReservedCleanup below is one of that
// description's two readers -- the glob question -- and reserved.go's
// guards are the other.

// CleanupNamesSomethingReserved answers whether any cleanup glob in the list
// would be refused for reaching the registry hive, what the profile service
// keeps beside it, or the profile root itself, and if so, the exact message
// a run would give when the same check stopped it. Exported so validation
// asks this package the question rather than re-deciding it with a copy of
// the reserved names and the matching rules: two answers to "would this
// cleanup line be refused" are exactly how a rules file comes to pass
// validation and then fail the run.
func CleanupNamesSomethingReserved(cleanup []config.Mask) error {
	return refuseReservedCleanup(cleanup)
}

// refuseReservedCleanup refuses the whole run if any cleanup glob can match
// the registry hive, what the profile service keeps beside it, or the
// profile root itself, checked against the glob as written rather than
// waiting for the walk to reach the file. The glob is answered against the
// reserved families' whole language -- reservedFamilyReachedBy -- so a glob
// reaches nothing by spelling a member the old examples never carried: the
// TxR set, a container past its first counter, a GUID some other machine's
// hive left. A glob that says ** is refused for
// the same reason a glob naming NTUSER.DAT outright would be: it is asking
// for something that cannot be granted, and saying so plainly is kinder than
// clearing everything else and quietly skipping the one name that cannot go.
//
// This is enforced here, when the rules are read, rather than by skipping
// the reserved names during the walk below. Skipping would make "cleanup:
// [**]" appear to succeed while doing something quite different from what it
// says -- clearing an entire profile apart from one file nobody who wrote
// that line was thinking about -- and that is a worse outcome than refusing
// the run.
//
// A glob naming a directory a reserved file sits under is refused the same
// way, though it matches none of the reserved paths: matchMask tests a
// name-only glob against the last segment, so "AppData" never matches
// AppData\Local\Microsoft\Windows\UsrClass.dat -- that path ends in
// UsrClass.dat -- and yet the walk removes the AppData directory whole,
// hive and all, with Copy reporting success. Removing the directory is the
// same destruction with one name fewer, so every ancestor of a reserved
// path is tested exactly as the path itself is.
//
// The questions are asked of the spelling the volume would act on as well
// as the one written, and the message still names the pattern as written.
// A cleanup glob is refused for what it asks for, and "NTUSER.DAT." asks
// for the hive as surely as "NTUSER.DAT" does -- Windows strips trailing
// dots and spaces per segment before it opens or creates a name, so the
// volume opens them onto the same file, measured. A segment spelled like
// an 8.3 alias is asked the same way through the wildcard the alias really
// stands for: the volume resolves the short spelling onto whatever long
// name it aliases, and the glob would ride along. A normalized spelling
// that reaches no reserved family refuses nothing -- the as-written check
// is the one that has always run, and a glob that names nothing reserved
// under either reading is exactly what cleanup is for.
func refuseReservedCleanup(cleanup []config.Mask) error {
	for _, mask := range cleanup {
		if err := refuseReservedGlobSpelling(mask.Pattern); err != nil {
			return err
		}
		// The same questions asked of the spelling the volume would read,
		// which exists only where the written one is one the volume
		// improves on -- a glob stored exactly as it is spelled pays
		// nothing here. The error is wrapped rather than returned so the
		// message keeps naming the pattern as written: that is the line
		// the person reading it can find in the rules file.
		if stripped := paddedGlobStripped(mask.Pattern); stripped != mask.Pattern {
			if err := refuseReservedGlobSpelling(stripped); err != nil {
				return exit.Errorf(exit.BadConfig,
					"cleanup glob %q ends a segment in dots or spaces, and Windows strips those "+
						"before it opens or creates anything -- the glob asks for the same thing "+
						"its stripped spelling does, as surely: %s",
					mask.Pattern, err)
			}
		}
		if dealiased := shortNameGlobDealiased(mask.Pattern); dealiased != mask.Pattern {
			if err := reachedReservedGlob(dealiased); err != nil {
				return exit.Errorf(exit.BadConfig,
					"cleanup glob %q is spelled the way Windows spells an 8.3 alias, and the volume "+
						"resolves such a spelling onto the long name it aliases -- the star in what "+
						"follows stands for the truncation the alias does not show: %s",
					mask.Pattern, err)
			}
		}
	}
	return nil
}

// refuseReservedGlobSpelling is the whole of what one spelling of a
// cleanup glob is refused for: naming the profile root itself, reaching a
// reserved family's language, or matching a directory a family sits under.
// Kept as one question so the as-written and volume-read spellings are
// asked exactly the same three things -- refuseReservedCleanup asks it
// twice per glob where the two spellings differ.
func refuseReservedGlobSpelling(pattern string) error {
	if namesTheProfileRootItself(pattern) {
		return exit.Errorf(exit.BadConfig,
			"cleanup glob %q names the profile root itself, which cleanup may never remove -- "+
				"name what to clear inside it instead", pattern)
	}
	return reachedReservedGlob(pattern)
}

// reachedReservedGlob is refuseReservedGlobSpelling without the root-itself
// check -- the two questions about what a glob's language reaches. The
// volume-read spellings are asked these two only: a root-itself glob is "."
// or empty in whatever spelling, and no spelling the volume would improve on
// is part of writing one.
func reachedReservedGlob(pattern string) error {
	if fam, reached := reservedFamilyReachedBy(pattern); reached {
		if fam.hive {
			return exit.Errorf(exit.BadConfig,
				"cleanup glob %q matches %s, which is the sandbox's own registry hive -- "+
					"deleting it does not clear a cache, it destroys HKEY_CURRENT_USER "+
					"and the sandbox will not start again", pattern, fam.example)
		}
		return exit.Errorf(exit.BadConfig,
			"cleanup glob %q reaches %s -- one of the transaction files Windows keeps beside "+
				"the sandbox's registry, whose GUID and counter differ machine to machine and "+
				"run to run, so the family stands or falls as one. The profile service built "+
				"it, not the sandbox: cleanup clears what the sandbox wrote, not what Windows "+
				"keeps beside its registry", pattern, fam.example)
	}
	for _, fam := range reservedFamilies {
		for _, dir := range familyAncestors(fam) {
			if matchMask(pattern, dir) {
				return exit.Errorf(exit.BadConfig,
					"cleanup glob %q matches %s, the directory %s sits under -- clearing the "+
						"directory clears the hive with it, which is the same destruction with "+
						"one name fewer. Name what the sandbox wrote instead",
					pattern, dir, fam.example)
			}
		}
	}
	return nil
}

// paddedGlobStripped spells a cleanup glob the way the volume reads it:
// each segment loses the trailing dots and spaces Win32 strips per segment
// before it opens or creates a name. Pure string work on the forward-slash
// form globs are written in -- the volume never stores a name carrying
// them, so nothing the walk could ever match does either.
func paddedGlobStripped(pattern string) string {
	segs := strings.Split(pattern, "/")
	for i, seg := range segs {
		segs[i] = strings.TrimRight(seg, ". ")
	}
	return strings.Join(segs, "/")
}

// shortNameGlobDealiased spells a cleanup glob with every segment shaped
// like an 8.3 alias opened into the wildcard the alias really stands for:
// the trailing tilde-and-digits becomes *, the extension stays --
// "NTUSER~1.BLF" becomes "NTUSER*.BLF" -- because the volume resolves the
// short spelling onto whatever long name it aliases, and the truncation is
// the part the alias does not show. Segments that are not short-name
// shaped are left alone, and a glob with none of them comes back as it
// went in.
func shortNameGlobDealiased(pattern string) string {
	segs := strings.Split(pattern, "/")
	for i, seg := range segs {
		if !looksLikeShortName(seg) {
			continue
		}
		ext := ""
		base := seg
		if j := strings.LastIndexByte(seg, '.'); j >= 0 {
			base, ext = seg[:j], seg[j:]
		}
		j := strings.LastIndexByte(base, '~')
		segs[i] = base[:j] + "*" + ext
	}
	return strings.Join(segs, "/")
}

// familyAncestors lists the directories a family's files sit under and in,
// nearest the family's directory first, as forward-slash paths relative to
// the profile root -- the question ancestorsOf answered of a concrete
// reserved path, asked of the one directory a whole family shares. A
// family at the profile root has none: a bare name is the whole of its
// path, and no directory is taken with it.
func familyAncestors(fam reservedShape) []string {
	if fam.dir == "" {
		return nil
	}
	return append(ancestorsOf(fam.dir), fam.dir)
}

// namesTheProfileRootItself reports whether a glob, cleaned as a path, comes
// to the profile root and not anything inside it -- "." or an empty pattern,
// the two ways of writing "here" rather than naming something in it. Neither
// wildcard nor a separator lets a glob reach further up than the root cleanup
// is already anchored to, so this is the whole of what could ever name it.
func namesTheProfileRootItself(pattern string) bool {
	return filepath.Clean(filepath.FromSlash(pattern)) == "."
}

// ancestorsOf lists the directories a reserved path sits under, nearest the
// reserved file first, as forward-slash paths relative to the profile root.
// Pure string work on the forward-slash form the reserved paths are written
// in: filepath.Dir would swap the separators under this platform's rules,
// and matchMask reads forward slashes only.
func ancestorsOf(path string) []string {
	var dirs []string
	for i := strings.LastIndexByte(path, '/'); i >= 0; i = strings.LastIndexByte(path[:i], '/') {
		dirs = append(dirs, path[:i])
	}
	return dirs
}
