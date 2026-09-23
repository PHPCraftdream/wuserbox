package profile

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/PHPCraftdream/wuserbox/internal/win/pathid"
)

// canonicalEntryPath resolves the stored directory-entry spelling without
// collapsing hard links. A path within refuses -- absolute, or climbing out
// -- and a missing component has no witnessed place. The walk reads each
// directory from the resolver's snapshot; the one opening left in an exact
// match's absence is the alias branch below, where the volume itself has
// to say which stored spelling a name resolves onto. That branch's whole
// answer is kept in the resolver's alias memo and its siblings' canonical
// spellings in the snapshot, and the snapshot's byCanonical index holds
// the same scan's answers for every other spelling of the same place, so
// a second question about one spelling -- or a first question about a
// different spelling of it -- in a directory this resolver has already
// scanned opens nothing at all.
//
// The walk answers three ways, not two. A witnessed place and the volume's
// own nothing are answers; an open or a ReadDir that failed for any other
// reason is not, and the answer nobody got is carried back with its cause
// rather than dressed up as absence -- the round-11 review's record loss
// was exactly that dressing, a locked destination directory reading as a
// place the record no longer names.
func (r *placeResolver) canonicalEntryPath(path string) placeResult {
	clean := cleanEntryPath(path)
	if clean == "." || filepath.IsAbs(clean) || clean == ".." ||
		strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return placeResult{}
	}
	r.lastDependentDir = ""
	current := "."
	for _, component := range strings.Split(clean, string(filepath.Separator)) {
		snap, ok := r.snapshot(current)
		if !ok {
			r.lastDependentDir = current
			if snap.unknown {
				return placeResult{unknown: true, err: snap.err}
			}
			return placeResult{}
		}
		chosen := snap.byName[component]
		if chosen == "" {
			r.lastDependentDir = current
			// Go's Unicode fold is only a candidate. NTFS has a
			// per-volume table, so open the spelling itself before
			// accepting a case-insensitive directory entry.
			aliasPath := filepath.Join(current, component)
			if memo, seen := r.alias[aliasPath]; seen && memo.version == r.dirVersion[current] {
				chosen = memo.canonical
			} else {
				delete(r.alias, aliasPath)
				opened, err := r.root.Open(aliasPath)
				if err != nil {
					answer := placeResult{}
					if !os.IsNotExist(err) {
						answer = placeResult{unknown: true, err: err}
					}
					r.noteAlias(current, aliasPath, answer)
					r.lastDependentDir = current
					return answer
				}
				openedPath, err := pathid.Canonical(opened.Name())
				_ = opened.Close()
				if err != nil {
					r.noteAlias(current, aliasPath, placeResult{unknown: true, err: err})
					r.lastDependentDir = current
					return placeResult{unknown: true, err: err}
				}
				// A sibling scan here already ran for an earlier alias
				// spelling and canonicalized every child on its way
				// past, so this spelling's answer is in the snapshot's
				// index whether or not the alias memo has heard of it;
				// only a canonical path the index has never seen asks
				// the volume for the siblings again.
				if indexed, seen := snap.byCanonical[openedPath]; seen {
					if indexed.unique {
						chosen = indexed.name
						r.noteAlias(current, aliasPath, placeResult{canonical: chosen, ok: true})
					} else {
						r.noteAlias(current, aliasPath, placeResult{})
						r.lastDependentDir = current
						return placeResult{}
					}
				} else {
					r.scans++
					complete := true
					var scanErr error
					for _, child := range snap.children {
						name := child.Name()
						if _, known := snap.canonical[name]; known {
							continue
						}
						childFile, err := r.root.Open(filepath.Join(current, name))
						if err != nil {
							complete = false
							scanErr = err
							continue
						}
						var childErr error
						childPath, childErr := pathid.Canonical(childFile.Name())
						_ = childFile.Close()
						if childErr != nil {
							complete = false
							scanErr = childErr
							continue
						}
						snap.canonical[name] = childPath
						// The index is extended in place, beside the
						// canonical row the answer just got, rather than
						// cleared and rebuilt out of the whole snapshot's
						// answers on every scan. The children an earlier
						// scan already answered are exactly the ones this
						// loop skips, so a scan adds only the answers it
						// newly computed: a retried scan re-observes
						// nothing, and an inner membership map is built
						// once per canonical path a snapshot first stored
						// a name under instead of once for every known path
						// on every scan. That rebuild is the cumulative
						// allocation work the reviews of 2026-09-30 (round
						// 11) and 2026-09-23 (round 12) measured: with B
						// unchanged neighbors and M changed names it paid
						// O(B·M+M²) for answers the increment already held.
						//
						// A second observation of one child cannot read
						// as a second stored name, because there is no
						// second observation to make: the child the scan
						// re-met is the name already stored under that
						// path, and the guard keeps the two apart. Only a
						// genuinely second stored name carrying one
						// canonical path -- hard links -- demotes
						// uniqueness, exactly as the scan's own
						// matches != 1 refused it, so the answers an
						// earlier partial scan managed to keep stay
						// answered.
						//
						// refresh and retract keep the index the exact
						// fold of the snapshot's canonical answers the
						// same way: they point at the rows they change and
						// let rebuildCanonical fold what stays, so no hand
						// needs to know how many scans it took to reach
						// the answers it is amending.
						if snap.canonicalNames[childPath] == nil {
							snap.canonicalNames[childPath] = make(map[string]bool)
							r.canonicalMaps++
						}
						snap.canonicalNames[childPath][name] = true
						if prior, seen := snap.byCanonical[childPath]; seen {
							if prior.name != name {
								prior.unique = false
								snap.byCanonical[childPath] = prior
							}
						} else {
							snap.byCanonical[childPath] = canonicalChild{name: name, unique: true}
						}
					}
					snap.canonicalComplete = complete
					// The snapshot goes back into the resolver's table,
					// because snapshot hands its look by value: the maps
					// inside it are shared and the completeness flag is
					// not, so a scan that left it on the copy it holds
					// would let the next rebuildCanonical read a stale
					// false and drop the unique answer this scan has just
					// witnessed. Writing it down here is the pattern every
					// other mutating hand already uses, and the flag the
					// next update reads is this scan's own.
					r.dirs[current] = snap
					// Canonical paths retain the stored directory-entry spelling. Hard
					// links therefore match only the name Windows actually resolved,
					// rather than merging every name for the same file identity.
					if answer, seen := snap.byCanonical[openedPath]; !seen || !answer.unique {
						r.noteAlias(current, aliasPath, placeResult{})
						r.lastDependentDir = current
						if !complete {
							// The refusal may be the unread
							// sibling's shadow: a sibling this scan
							// could not open or canonicalize
							// might be the one carrying the
							// opened path, so no answer about
							// this spelling was got at all.
							return placeResult{unknown: true, err: scanErr}
						}
						return placeResult{}
					}
					chosen = snap.byCanonical[openedPath].name
					r.noteAlias(current, aliasPath, placeResult{canonical: chosen, ok: true})
				}
			}
		}
		if chosen == "" {
			r.lastDependentDir = current
			return placeResult{}
		}
		current = filepath.Join(current, chosen)
	}
	return placeResult{canonical: current, ok: true}
}
