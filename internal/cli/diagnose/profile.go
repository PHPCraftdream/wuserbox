// Checks on the profile: and cleanup: sections of the rules file: the
// shapes that can only be spelled by hand, since wuserbox never writes an
// entry carrying limits or a cleanup glob itself. inspectRules holds the
// checks on projects:; this file holds their profile: and cleanup: twins,
// in the same voice -- naming what will actually happen, not just what is
// wrong.

package diagnose

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"github.com/PHPCraftdream/wuserbox/internal/policy/preset"
	"github.com/PHPCraftdream/wuserbox/internal/policy/profile"
)

// inspectProfile looks for the mistakes a hand-edited profile: or cleanup:
// section collects. Some are fatal, because the copier or the cleanup would
// refuse the very same file at run time and a rules file should be told so
// before that run rather than during it -- reusing the copier's own answer
// rather than a second guess at it, the same reasoning inspectRules already
// holds for projects:. Others are worth mentioning without failing the
// command: what they cost is a wasted line in the file, not a broken run.
func inspectProfile(entries []config.Entry, cleanup []config.Mask) []Complaint {
	var complaints []Complaint
	complaints = append(complaints, inspectProfileEntries(entries)...)
	complaints = append(complaints, inspectCleanupGlobs(cleanup)...)
	return complaints
}

// inspectProfileEntries covers points 1, 2, 4, 6, 7 and 8 of the profile:
// checks -- 4 through the copier's own EntryCarriesNegativeDepth, which
// answers for the entry's depth and every mask's at once; inspectMasks,
// called from here, covers 3.
func inspectProfileEntries(entries []config.Entry) []Complaint {
	var complaints []Complaint
	seen := map[string]config.Entry{}
	sensitive := sensitiveNames()

	for _, entry := range entries {
		if entry.Path == "" {
			complaints = append(complaints, Complaint{
				Kind: "empty", Fatal: true,
				Message: "a profile: entry has no path, and names nothing to copy",
			})
			continue // nothing else about a nameless entry can be checked
		}

		// Reuses within, through EntryEscapesProfile, rather than
		// re-deciding "absolute or climbs out" here: the copier refuses
		// exactly this at run time, and a second implementation of the same
		// rule is exactly how a rules file comes to pass validation and
		// then fail the run.
		if err := profile.EntryEscapesProfile(entry.Path); err != nil {
			complaints = append(complaints, Complaint{
				Kind: "outside", Path: entry.Path, Fatal: true,
				Message: fmt.Sprintf("%s: %v", config.Path(), err),
			})
		}

		// The copier's own refusal, asked rather than re-decided: Copy puts
		// this same question to the file before it touches dest, about the
		// entry's own depth and about every mask's in one answer.
		if err := profile.EntryCarriesNegativeDepth(entry); err != nil {
			complaints = append(complaints, Complaint{
				Kind: "depth", Path: entry.Path, Fatal: true,
				Message: err.Error(),
			})
		}
		complaints = append(complaints, inspectMasks(entry.Path, "include", entry.Include)...)
		complaints = append(complaints, inspectMasks(entry.Path, "exclude", entry.Exclude)...)

		key := profilePathKey(entry.Path)
		if first, repeated := seen[key]; repeated {
			// EntriesSayTheSameThing is the copier's own answer, reused
			// rather than re-decided here: it is also what conflictingProfileEntry
			// asks before Copy touches dest, and two answers to "do these
			// entries say the same thing" are exactly how a rules file comes
			// to pass validation and then lose data on the run.
			if profile.EntriesSayTheSameThing(first, entry) {
				complaints = append(complaints, Complaint{
					Kind: "profile-duplicate", Path: entry.Path,
					Message: fmt.Sprintf("%s is listed twice in profile:; both are copied and the "+
						"second lands on top of %s, so this is waste rather than breakage",
						entry.Path, first.Path),
				})
			} else {
				complaints = append(complaints, Complaint{
					Kind: "profile-conflict", Path: entry.Path, Fatal: true,
					Message: fmt.Sprintf("%s is listed twice in profile: with limits that differ "+
						"from %s; the second entry's copy would land on top of the first, and its "+
						"mirroring would then delete whatever the first entry's exclusions were "+
						"protecting -- make the two entries say exactly the same thing, or remove one",
						entry.Path, first.Path),
				})
			}
		} else {
			seen[key] = entry
		}

		// The first segment, not the whole path, which is the same rule
		// preset.Profile applies and for the same reason: the sensitive
		// table names ~/.ssh, and what makes ~/.ssh worth protecting is the
		// keys inside it. Matching the whole path would say nothing about
		// ".ssh/id_rsa" -- the entry somebody would actually write -- and
		// speak up only about the one spelling that copies the directory
		// whole.
		if name, on := sensitive[strings.ToLower(firstSegmentOf(entry.Path))]; on {
			complaints = append(complaints, Complaint{
				Kind: "sensitive", Path: entry.Path,
				Message: fmt.Sprintf("%s is under %s, which wuserbox otherwise keeps out of a "+
					"sandbox's reach; this rule copies it in on purpose", entry.Path, name),
			})
		}

		// Point 8: depth/include/exclude describe what to copy under a
		// directory, and a file has nothing under it, so they would be
		// ignored rather than refused at run time -- see copySink.file and
		// mirror's own doc, which never filters the entry itself. A path
		// that does not exist at all is left alone here: a rules file
		// shared across machines names things some of them lack, and
		// refusing for that would be worse than the mistake this check is
		// for. Only a path confirmed to be a plain file is complained
		// about.
		if !entry.Bare() {
			if info, err := os.Stat(filepath.Join(paths.Home(), filepath.FromSlash(entry.Path))); err == nil && !info.IsDir() {
				complaints = append(complaints, Complaint{
					Kind: "profile-limits", Path: entry.Path,
					Message: fmt.Sprintf("%s is a file on this machine, and depth/include/exclude "+
						"describe what to copy under a directory; they will be ignored", entry.Path),
				})
			}
		}
	}
	return complaints
}

// inspectMasks covers point 3 (an empty pattern) for one entry's include or
// exclude list. list names which one, for the message. A mask's depth is not
// asked here: EntryCarriesNegativeDepth already answered for every mask on
// the entry, and a second ask would be a second answer to the same question.
func inspectMasks(entryPath, list string, masks []config.Mask) []Complaint {
	var complaints []Complaint
	for _, mask := range masks {
		if mask.Pattern == "" {
			complaints = append(complaints, Complaint{
				Kind: "empty", Path: entryPath, Fatal: true,
				Message: fmt.Sprintf("%s has an empty pattern in its %s list", entryPath, list),
			})
		}
	}
	return complaints
}

// inspectCleanupGlobs covers the cleanup: half of points 3 and 4, and point
// 5: a glob the copier would refuse outright for reaching the registry hive
// or the profile root itself.
func inspectCleanupGlobs(cleanup []config.Mask) []Complaint {
	var complaints []Complaint
	for _, mask := range cleanup {
		if mask.Pattern == "" {
			complaints = append(complaints, Complaint{
				Kind: "empty", Fatal: true,
				Message: "cleanup: has an empty pattern",
			})
			continue
		}
		// Not the copier's shared question, on purpose: a cleanup glob whose
		// depth cannot bind reaches nothing and so deletes nothing -- it
		// fails closed, where a profile entry's fails by deleting what its
		// exclusions protect -- so validation may complain without a run
		// needing to refuse the file over it.
		if mask.Depth != nil && *mask.Depth < 0 {
			complaints = append(complaints, Complaint{
				Kind: "depth", Path: mask.Pattern, Fatal: true,
				Message: fmt.Sprintf("cleanup glob %q has depth %d, and a negative depth cannot bound anything",
					mask.Pattern, *mask.Depth),
			})
		}
	}
	// Reuses the copier's own reserved-names check rather than a copy of
	// NTUSER.DAT's companion files and the profile-root rule: see
	// profile.CleanupNamesSomethingReserved's own doc for why that pairing
	// matters here.
	if err := profile.CleanupNamesSomethingReserved(cleanup); err != nil {
		complaints = append(complaints, Complaint{Kind: "cleanup", Fatal: true, Message: err.Error()})
	}
	return complaints
}

// profilePathKey normalizes a profile: entry's path by asking the copier
// rather than by spelling the rule out again, so a duplicate reported here
// is exactly the duplicate the copier would also treat as one, landing the
// second copy on top of the first. The spelled-out version stood here until
// the copier's own key was cleaned: it claimed to match forget and did not,
// because forget folded case and separators without cleaning, and the day
// the two disagreed is the day this report starts naming duplicates that
// are not and missing the ones that are.
func profilePathKey(path string) string {
	return profile.FoldedEntryPath(path)
}

// sensitiveNames maps each sensitive entry's own lowercase name to how it is
// actually spelled, for a case-insensitive lookup that still reports the
// name the way somebody would recognize it.
// firstSegmentOf is the part of an entry's path the sensitive table names:
// a directory on that table protects everything filed under it, so the
// question asked of a path is which top-level name it belongs to.
// Spelled with forward slashes and cut there, never cleaned first: on
// Windows filepath.Clean hands back backslashes whatever it was given, so a
// cleaned path has no '/' left to find and the whole of ".ssh/id_rsa" comes
// back as its own first segment -- which is how this check silently answered
// nothing at all. preset.firstSegment avoids it the same way and for the
// same reason.
func firstSegmentOf(path string) string {
	slashed := filepath.ToSlash(path)
	if cut := strings.IndexByte(slashed, '/'); cut >= 0 {
		return slashed[:cut]
	}
	return slashed
}

func sensitiveNames() map[string]string {
	names := preset.Names()
	out := make(map[string]string, len(names))
	for _, name := range names {
		out[strings.ToLower(name)] = name
	}
	return out
}
