# Release-readiness review — 2026-09-15

Commit reviewed: `5de7faa`. Reviewer: an independent agent, asked to hunt for one
thing above all — a sandboxed process able to delete or modify something outside
what it was granted, or inside another sandbox. The special folders of the user
profile and the shared system folders the machine itself makes writable were
excluded from that definition, as was anything already listed in README.md under
"Limits worth knowing".

The report is reproduced below as it was delivered. A note on what was checked
independently afterwards follows at the end.

---

## Scope

Read `README.md` ("Limits worth knowing" taken as accepted), the whole of
`internal/win/acl`, `internal/policy/{grant,state}`, `internal/base/lock`,
`internal/sandbox/{init,grants,exec}`, `internal/win/token`, `internal/cli/setup`,
and the e2e/acl boundary tests. `go build ./...` and `go vet ./...` pass at
`5de7faa`. Where the report says "measured", a throwaway test was run in a
worktree and deleted afterwards; no product code was changed.

## Findings

### P0 — a hard link inside a granted tree hands the sandbox write+delete on a file outside it

**Where:** `internal/win/acl/isolate.go:149` (`publish(path, list, true)`) and
`internal/win/acl/set.go:143` (`SetNamedSecurityInfoW` with inheritable entries).
The sweep (`sweep.go:36-70`) visits every object but never asks whether a file
has more than one name.

**Mechanism:** an NTFS hard link is the same file object under two names; the
DACL belongs to the file, not to the name. When a grant is applied, Windows
propagates the inheritable `sandbox:Modify` ACE into every file under the granted
directory — including a file whose second name lives outside. From then on the
sandbox passes both checks on that file by its *outside* path: Modify includes
`DELETE (0x10000)`, so it can rewrite it and delete the outside name.

**Concrete scenario (measured):**

1. Outside the sandbox: `C:\proj\` is the project; the user has
   `C:\Users\me\Documents\notes.txt` and at some point
   `mklink /H C:\proj\link.txt C:\Users\me\Documents\notes.txt` — or any tool
   that does this: `git clone` of a local repository hard-links `.git/objects`,
   pnpm hard-links its store into `node_modules`, deduplication tools do it too.
2. `wuserbox --init` (or `--grant C:\proj`, or any later `--init` — `build()`
   calls `Ensure(dir, RW)` and `grants.Reapply` every time, so a link created
   *after* the first grant is picked up at the next init).
3. Inside the sandbox: `echo x > C:\Users\me\Documents\notes.txt` succeeds;
   `del C:\Users\me\Documents\notes.txt` succeeds.

**Evidence:** measured with the e2e harness. Link `box.granted\link.txt` →
`box.denied\target.txt`; writing via the outside name before re-apply gives
`Access is denied` (exit 1); after `state.Ensure(box.granted, RW)` it gives
exit 0; `del` by the outside name removed it. `icacls` on the outside name shows
`S-1-5-21-1111…-543210:(I)(M)` — the sandbox's entry, marked inherited, on a file
outside the tree.

**Preconditions and limits:** the link must already exist. The sandbox cannot
create one itself against a file it cannot write, because Windows' hard-link
mitigation requires write access to the target, so this is not a self-serve
escape; it is a grant silently reaching outside what it names. Not covered by any
test and not mentioned under "Limits worth knowing".

**Cheapest fix that fits the design:** the first sweep pass (`readable`) already
opens every object; add `GetFileInformationByHandle` → `nNumberOfLinks > 1` and
either refuse the grant naming the file (the same fail-closed shape as the
unsupported-ACE-kind refusal in `entries.go:105`) or enumerate its other names
(`FindFirstFileNameW`) and refuse only when one lies outside the tree. At
minimum, document it beside the junction and protected-file limits.

### P1 — `grant.Refuse` denies reading, not only changing

**Where:** `internal/policy/grant/refuse.go:15` —
`acl.Deny(path, account, acl.AccessModify)`.

**Mechanism:** `AccessModify` (0x1301BF) contains `FILE_READ_DATA`,
`READ_CONTROL` and `SYNCHRONIZE`. A deny ACE carrying those bits, matched against
the sandbox SID in the restricted pass, refuses the whole read. `ace.go:54`
already explains exactly this for the read-only kind and uses `AccessChange`
there; `Refuse` was not updated.

**Scenario:** `wuserbox --init --home-writes` → `RefuseHomeFiles`
(`protect.go:123`) refuses *every* file in the profile root that existed at init:
`.gitconfig`, `.npmrc`, `.bashrc`, `.wuserbox.ktav`, and so on. Inside the
sandbox, `git` cannot read `~/.gitconfig` and `npm` cannot read `~/.npmrc`. The
README says these are "refused one by one", meaning writes; reading is the
promise the tool opens with.

**Evidence:** measured. `type file` inside the sandbox: exit 0 before
`grant.Refuse`, `Access is denied` after. `TestRefusalBeatsAnInheritedPermission`
checks only that write and delete fail; nothing checks that reading survives.

**Fix:** `acl.Deny(path, account, acl.AccessChange)`.

### P2 — Go buffers backing restricting SIDs are not kept alive across `CreateRestrictedToken`

**Where:** `internal/win/token/restricted.go:66,85,89-91`.

**Mechanism:** `logon` is a `uintptr` into `logonBuf` (a `[]byte`), and the
`wub-read` entry is `uintptr(unsafe.Pointer(&read[0]))` into a Go slice. Neither
slice is referenced after those lines, so the collector may reclaim them before
`procCreateRestrictedToken.Call`; the `unsafe.Pointer` → `uintptr` liveness rule
only applies inside the call expression. The same holds for `user`/`userBuf`,
used by `formatSID` afterwards.

**Consequence:** almost always fail-closed — an invalid SID makes the call fail,
and a garbage-but-valid SID matches nothing. Widening would need the freed bytes
to be reused by another SID-shaped allocation in the same microseconds. Read from
the code, not measured.

**Fix:** `runtime.KeepAlive(logonBuf)`, `runtime.KeepAlive(read)`,
`runtime.KeepAlive(userBuf)` after the calls, or convert inside the call
arguments.

## Checked and found sound

- **Masks:** `AccessModify` and `AccessCreateFiles` carry neither
  `FILE_DELETE_CHILD` nor `WRITE_DAC`/`WRITE_OWNER`; `changing` covers both plus
  the generic bits; `fromNothing` narrows Everyone to exactly `0x1200A9`.
- **Deny entries:** product code writes a deny only against the sandbox SID
  (`kind.go:36`, `refuse.go:15`). Nothing denies Everyone or BUILTIN\Users.
- **Junctions:** measured — `Isolate` on a tree containing a junction leaves the
  target untouched (no added entry, nothing narrowed); the junction object itself
  gets the inherited entry, which is harmless. Note that
  `TestAGrantDoesNotReachThroughAJunction` only asserts that nothing was *removed*
  beyond the junction; it would not catch propagation *adding* an entry there. It
  holds anyway, but the test is weaker than its comment claims.
- **Restricting list:** `{sandbox, Everyone, Users, logon SID, wub-read}` — none
  grants beyond what the README states; `wub-read` is read-only and gated by the
  first, unrestricted check.
- **Ordering:** the record is saved before `Apply` (`grants.go:104-114`), the
  sweep runs before the top-level publish (`isolate.go:146-149`), and the whole
  tree is read before any of it is written (`sweep.go:44-52`). `Remove` runs
  Revoke → Prune → Save; an interruption there leaves the record claiming *more*
  than is in force, which is the harmless direction.
- **Locks:** `HoldTree` takes shared holds on the ancestors from the volume root
  down and an exclusive hold on the root, so no cycle is possible;
  `ApplyTogether`'s preset paths do not nest.
- **`--rm` temp cleanup:** `os.RemoveAll` on Go 1.26 treats junctions and
  symlinks as non-directories and removes the link, so a junction planted by the
  sandbox in its temp directory is not followed by the elevated removal.
- **Implicit owner `WRITE_DAC`:** does not apply in the restricted pass, because
  the owner SID is not in the restricting list;
  `TestASandboxCannotRewriteThePermissionsItWasLeft` measures this.

## Untested boundary claims worth a named test

1. A grant does not reach a file outside the tree through a hard link — currently
   false, see the P0 above.
2. A refused file inside `--home-writes` stays readable — currently false, see
   the P1 above.
3. One sandbox cannot write another's temp directory
   (`LOCALAPPDATA\wuserbox\tmp\<group>`): the same mechanism as the project
   directory, but no test names it.

## Verdict

Not release-ready as it stands. The core mechanism — a fully restricted token
plus pinning and sweeping — holds up under reading and under every measurement
taken, except one: a pre-existing hard link inside a granted tree lets the
sandbox modify and delete a file outside it, which is precisely the thing the
tool promises against, and it is neither tested nor listed as a limit. The
precondition is narrow and it is cheap to close in the sweep's first pass, so it
should be fixed, or at the very least documented, before tagging. The `Refuse`
mask (P1) is a one-token fix that makes `--home-writes` actually usable; the
`KeepAlive` (P2) is hygiene in the one function that builds the boundary. With
those three addressed and a test named in `ci.yml` for the hard-link case, the
reviewer would call it ready.

---

## Checked independently afterwards

Not part of the report above; recorded here so the next reader knows which claims
were re-measured rather than taken on trust.

- **P0 confirmed.** An independent probe in `internal/win/acl`: create
  `outside\target.txt`, `mklink /H granted\link.txt outside\target.txt`, then
  `Isolate(granted, …)`. `icacls` on the outside name afterwards lists
  `S-1-5-21-1111111111-2222222222-3333333333-543210:(I)(M)` — the sandbox's own
  identifier, inherited, on a file outside the granted tree. What was measured is
  that the entry lands there; that the write and the delete then succeed follows
  from the mask and from both passes of the restricted check reading the same
  list, and was not separately measured, since that needs a real local group and
  administrator rights.
- **P1 confirmed by arithmetic.** `AccessModify` is `0x1301BF`, which contains
  `FILE_READ_DATA` (`0x1`) and `READ_CONTROL` (`0x20000`). The read-only grant
  kind already uses `AccessChange` for exactly this reason, and the comment above
  `AccessChange` spells out why a refusal must not carry read bits.
- **P2 confirmed, and narrowed.** `information()` returns `make([]byte, size)` and
  `sid.Lookup` returns `make(Value, sidLen)`, so `userBuf`, `logonBuf` and `read`
  are Go-owned and at risk. `groupSID`, `everyone` and `users` are not:
  `sid.Parse` calls `ConvertStringSidToSid`, whose memory belongs to Windows.
