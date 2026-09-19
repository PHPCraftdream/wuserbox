# Sandbox security review — 2026-09-19

Independent review of the whole sandbox boundary at `f0fb913`
(`Carry a sandboxed process's stdout and stderr back to the caller's
terminal`), the tip of `main` at review time. This is not a first look: nine
prior `docs/reviews/release-review-P-*` rounds (2026-09-15 through
2026-09-18-round9) already hammered the ACL/hard-link/owner-cap/revoke
boundary hard and repeatedly found and closed P0s there. This review reads
that history first, treats it as a map of what has already been adversarially
tested rather than as proof of absence, and spends its effort on: (a)
confirming the two P0s open at the end of round 9 are actually closed in the
commits that followed it, and (b) the code that landed *after* round 9 and has
not been through an adversarial pass yet — output-stream bridging in
`internal/win/proc/logon.go`, the parallelized ACL sweep in
`internal/win/acl/sweep.go`, the pinned-path preflight filter in
`internal/win/acl/pinned.go`, and the "skip a freshly-applied grant" optimization
in `internal/sandbox/grants/preset.go` and `internal/policy/state/state.go`.

**Summary.** One P2 finding (a process-boundary hygiene gap with no
demonstrated exploit given the handles the codebase currently holds open at
the relevant call site). No P0 or P1 found in this pass. The two P0s open at
the end of round 9 (`docs/reviews/release-review-P-2026-09-18-round9.md`) —
link preflight running after `ProtectFull` in profile init, and the copy
guard missing an internal-symlink-to-external-hardlink path — read as fixed
by the commits that followed round 9 (`facfdf1`, `ad20558`, `f6f8da8`,
`31e187e`); see "Checked and found sound" below for what was verified and
what was not re-measured live. `go build ./...` and `go vet ./...` are clean
at the reviewed commit. **Verdict: no new release-blocking finding from this
round.** This is not a certification that the tool is free of P0s — nine
rounds of adversarial review on this exact boundary each found something the
last round missed, and this round's negative result should be weighted
accordingly, not treated as the last word.

## P0

None found in this round.

## P1

None found in this round.

## P2

### P2-1 — no positive handle-inheritance boundary at the account crossing in `RunAsAccount`

**Where:** `internal/win/proc/logon.go:48-91` (`duplicateStandardHandles`,
`duplicateInheritable`), `internal/win/proc/logon.go:143-184`
(`duplicateOutput`, `bridgePipe`), `internal/win/proc/logon.go:290-411`
(`runAsAccount`, the `CreateProcessWithLogonW` call at line 362).

**Mechanism.** `runAsAccount` is the one place a trusted, higher-privileged
process (wuserbox running as the operator) starts a process as the
sandbox's own, lower-privileged local account. Three handles are
deliberately marked inheritable and passed through `STARTUPINFO`
(`streams.input/output/errout`, built by `duplicateStandardHandles` with an
explicit `DuplicateHandle(..., true, DUPLICATE_SAME_ACCESS)`), because
`CreateProcessWithLogonW` takes no `bInheritHandles` argument and — per the
code's own comment at `logon.go:38-41` — "the handles in STARTUPINFO must
already be inheritable" for the call to honor `STARTF_USESTDHANDLES` at all.

The read end of the console-output bridge pipe (`os.Pipe()`, whose Windows
handles are inheritable **by both ends** — this is documented on `os.Pipe`
itself, `file_windows.go:267-270`: "The Windows handles underlying the
returned files are marked as inheritable by child processes") is created in
`bridgePipe` and kept open across the `CreateProcessWithLogonW` call as
`bridge.stdoutRead`/`bridge.stderrRead` (closed only after the process
starts, in the deferred `bridge.finish()`/`bridge.close()`). Nothing strips
`HANDLE_FLAG_INHERIT` from that read end before the call, unlike every other
handle-hygiene decision in this codebase, which is otherwise meticulous about
this exact class of problem — see `internal/base/lock/slot.go:177-187`
(`PassTo`), whose comment spells out in detail why its duplicate is built with
"desired access zero and is not inherited."

**Why this matters even though it is not demonstrated to be exploitable
today.** Go's own `os.OpenFile`/`os.Open` on Windows always pass
`syscall.O_CLOEXEC` (`file_windows.go:158`, confirmed by reading
`GOROOT/src/os/file_windows.go` and `GOROOT/src/syscall/syscall_windows.go`
at the toolchain used to build this repo, go1.26.0), so ordinary file handles
opened through `os` are *not* inheritable by default — that already covers
most of what a process holds open. The lease/lock file handles in
`internal/base/lock/slot.go:223-226` and `internal/base/lock/hold.go:133-135`
are opened with `syscall.CreateFile(..., nil, ...)`, i.e. a NULL
`SECURITY_ATTRIBUTES`, which Windows also treats as non-inheritable by
default. The trace/bootstrap log file in `internal/base/trace/trace.go:69`
goes through `os.OpenFile`, same CLOEXEC guarantee. So, having walked every
place that opens a handle ahead of the `CreateProcessWithLogonW` call in
`runAsAccount`, the only *currently* inheritable handle left standing at that
call, besides the three intentional ones, is the bridge pipe's read end —
and even in the worst case (if `CreateProcessWithLogonW`/the secondary-logon
service duplicates more than the three `STARTUPINFO` handles from the
caller's table, which this review could not confirm or rule out without a
live two-account experiment — see below) the account process would only gain
a redundant handle to the read end of a pipe it is already the write end of.
That is not a boundary crossing by itself.

The actual gap is structural, not a specific leaked secret: **nothing in this
codebase enforces, checks, or tests that only the three intended handles
cross the account boundary.** The current safety of this call rests entirely
on every other file/pipe/handle-opening call site in the whole program never
using `syscall.CreateFile` with an inheritable `SECURITY_ATTRIBUTES`, never
using `os.Pipe()` without immediately stripping the inherit flag off ends
that should not cross, and so on — an invariant nothing verifies, unlike the
`lock.PassTo` case a few files away, which earns a paragraph of comment and a
named test (`TestALeaseHandedToTheStubCarriesNoRightsOverTheSlotFile`) for
exactly this property. The design doc for this whole call
(`docs/design/one-stub-for-a-sandbox.md:205-210`) records that
`STARTUPINFOEX`/`PROC_THREAD_ATTRIBUTE_*` is refused by
`CreateProcessWithLogonW` (measured), which rules out the parent-process
attribute as the inheritance mechanism, but does not say anything about
whether ambient (non-`STARTUPINFO`) inheritable handles cross — this specific
question does not appear to have been measured anywhere in the repository's
design docs or tests. `internal/base/lock/slot_chain_test.go:300-301`
separately documents, and relies on, blanket `bInheritHandles`-style
inheritance for the *unrelated* `Run`/stub→program hop (`syscall.CreateProcess`
with `bInheritHandles=true`), which shows the authors are alert to this
mechanism in general — just not, as far as this review found, at this
specific account-crossing call site.

**Suggested fix.** Two independent, cheap hardenings, either of which closes
this regardless of how `CreateProcessWithLogonW` actually behaves
internally: (1) call `SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0)`
on `bridge.stdoutRead`/`stderrRead` immediately after `os.Pipe()` in
`bridgePipe`, the same way `lock.PassTo` documents and enforces
non-inheritance for its own duplicate; (2) add a regression test that opens a
throwaway file/pipe with `os.Pipe()` right before a `RunAsAccountWithLease`
call in the existing e2e account-test harness and asserts, via the adopted
handle's `GetHandleInformation` flags on the far side (the pattern
`slot_chain_test.go` already uses for `Adopt`), that nothing beyond the three
named streams is visible to the started stub — turning "we believe only
three handles cross" into a measured property the way the rest of this
codebase insists on for every other boundary claim.

## P3

None found in this round beyond the P2 above.

## Checked and found sound

- **Round-9 P0-1 (link preflight ordering in profile init).**
  `internal/account/ownprofile.go:51-66` (`MakeProfile`) now calls
  `validateProfileLinks(dir, false)` before any mutation — before
  `os.MkdirAll`, before `acl.ProtectFull` — with a comment explicitly citing
  the round-9 defect ("ProtectFull below replaces the profile DACL and
  propagates its inherited entries to existing children. Refuse an external
  hard-link name before any profile mutation..."). `internal/sandbox/init.go:390-396`
  keeps the check inside `MakeProfile` itself rather than duplicating it at
  the call site, which is exactly what round 9 asked for ("держать эту
  проверку внутри пути, который действительно изменяет разрешения"). Read
  the code and the commit that introduced it (`facfdf1`); did not
  independently re-run a live hard-link repro against a real profile
  directory in this session, so this is a code-review confirmation of the
  fix shape, not a fresh empirical measurement.
- **Round-9 P0-2 (copy guard missing the internal-symlink-to-external-hardlink
  path).** `internal/policy/profile/mirror.go:259-281` (`mirrorFile`) now
  checks the destination's mode for `ModeSymlink|ModeIrregular` and refuses
  before opening, in addition to the existing `pathid.OutsideNames` check for
  a plain regular-file destination — closing exactly the gap round 9
  described ("Проверка `OutsideNames` выполняется только когда
  `root.Lstat(dst)` сообщает об обычном файле"). Same caveat as above: read
  and reasoned through, not re-measured with a live repro in this session.
- **Parallelized ACL sweep classification** (`internal/win/acl/sweep.go`,
  commit `06a8750`). Traced the ordering argument in detail: workers classify
  objects from an unordered parallel read (`classifyNarrow`), but the
  single-goroutine ordered writer applies changes strictly in
  `filepath.WalkDir` order and *rereads* the object immediately before any
  write (`narrowOwn`), so a parent's write landing between a worker's read and
  the writer's turn cannot make a stale `narrowApply` decision wrong — only
  stale it further, which the reread then corrects. A stale `narrowNoop`
  decision is also safe: for the not-owned branch it depends only on the
  object's own (non-inherited) entries, which a parent's later rewrite cannot
  touch; for the owned/self-contained branch, an object that already "does
  not hear from above" is by construction immune to a parent's later publish.
  The pinned-directory skip (`narrowSkip`) replicates `capObject`'s own
  `pinned.contains` + `IsDir` check exactly, and `underSkipped` correctly
  discards a descendant's result — including a descendant's *read error* —
  before that error can abort the sweep, as long as the skipped ancestor is
  finalized first, which strict sequence-number ordering guarantees. No
  divergence found from the sequential predecessor's behavior.
- **`Reapply` skip-if-fresh optimization** (`internal/policy/state/state.go`,
  `internal/policy/state/grants.go:112-122`, `internal/sandbox/grants/preset.go:93-141`,
  commit `46cf518`). Confirmed `markFresh` only fires after `grant.Apply`
  has already succeeded (`grants.go:113-121`), and that every earlier step in
  `sandbox.build()` (`internal/sandbox/init.go:84-192`) returns its error
  immediately rather than continuing to `grants.Reapply`, so a `record()` call
  that fails partway through its narrow/prune tail (after `markFresh` would
  have run) can never leave `Reapply` reachable with an inconsistent "fresh"
  entry. `overlapsAnother`'s error handling is fail-closed (an error from
  `pathid.Within` counts as overlap, forcing the safe/slow path). The added
  regression tests (`TestReapplySkipsAFreshDisjointGrant`,
  `TestFreshGrantStillReappliesWhenTreesOverlap`) match this reasoning.
- **`pinnedPaths.relevant` preflight filter** (`internal/win/acl/pinned.go`,
  `internal/win/acl/isolate.go`, `internal/win/acl/reclaim.go`, commit
  `1a389c3`). The filter only ever *removes* pinned entries that
  `pathid.Within` proves are not real descendants of the current sweep root
  (or are the root itself, by filesystem identity in both directions, which
  also correctly excludes an external hard-link name for a file root). Since
  the sweep only ever visits genuine descendants of that same root, an
  excluded, non-descendant entry could never have matched a visited path
  anyway — the filter changes what work is done, not what is protected.
- **`pathid.Within`/`Canonical`/`Key`** (`internal/win/pathid/pathid.go`).
  The upward walk in `Within` re-resolves each ancestor's identity through a
  fresh `CreateFile` at every step rather than trusting string manipulation,
  so a reparse point anywhere in the chain is transparently re-resolved by
  Windows on each call rather than by Go's own path logic — traced through
  to confirm this does not silently diverge for a path that crosses a
  junction partway up.
- **Restricted-token construction and the stub/shield boundary**
  (`internal/win/token/restricted.go`, `internal/win/proc/shield.go`,
  `internal/win/proc/job.go`, `internal/sandbox/exec/stub.go`). Specifically
  checked whether a sandboxed program could pass an arbitrary group SID as
  `-sandbox-stub`'s first argument (`internal/sandbox/exec/stub.go:58-93`,
  `token.AsSandbox`) to mint itself a token restricted to *another* sandbox's
  group. `CreateRestrictedToken`'s restricting-SID list can only narrow an
  access check (both the ordinary check against the token's real identities
  and the restricted-SID check must pass), and the ordinary check still runs
  against the caller's own real token — which never held the other sandbox's
  group membership — so this does not grant anything. Matches the reasoning
  already recorded in `token.Restricted`'s own doc comment.
- **`internal/cli/setup/rm.go`** end to end: removal ordering (ProfileList
  entry and profile-service reference removed before the account, account
  before the profile directory is unconditionally cleared, group deleted
  last), the damaged-record fallback path, and `accountNameForRemoval`'s
  refusal to infer ownership across a name collision. No issue found.
- **`internal/cli/setup/run.go`**: slot-lease placement relative to profile
  refresh and elevation, `onlyRunning`'s refusal of configuration flags on a
  plain run, and `fillProfile`'s partial-copy bookkeeping (`union`). No issue
  found.
- **`internal/account/restrict.go`** (sign-in hiding, `SeDenyRemoteInteractiveLogonRight`
  via LSA): correctly does *not* set `SeDenyInteractiveLogonRight`, which the
  file's own header comment explains would break `CreateProcessWithLogonW`
  itself — read this against the actual Windows logon-type semantics and it
  holds up.

## Not independently re-verified in this round

- The full existing test suite was not run (per this review's scope: depth
  over exhaustive re-execution). `go build ./...` and `go vet ./...` were run
  and are clean.
- The ambient-handle-inheritance question in P2-1 was reasoned through from
  Go/Windows source and the codebase's own design docs, not confirmed with a
  live two-account experiment (which needs a real second local account and
  administrator rights to set up cleanly); the finding is scoped and worded
  to reflect that.
- Areas read but not given the same line-by-line scrutiny as the above,
  because nothing in a first pass suggested a lead worth following further:
  `internal/policy/grant/{apply,revoke,prune,refuse}.go`,
  `internal/policy/config`, `internal/policy/preset`, `internal/win/group`,
  `internal/win/sid`, `internal/win/w32`, `internal/sandbox/facts`,
  `internal/sandbox/plan`. These were the subject of heavy, repeated
  adversarial review in prior rounds (most of rounds 3-9's P0s trace to
  `grant`/`acl`); nothing here changed since round 9's clean pass over them,
  per `git log`.
- Documented, accepted limits — shared-writable `Everyone`/`BUILTIN\Users`
  directories, no network isolation, weak UI/clipboard isolation, reading
  within a granted tree being unrestricted, already-open handles surviving a
  revoke, DPAPI/Credential Manager being out of reach by account design
  rather than by a tested boundary — are exactly as `docs/limits.md` and
  `.github/SECURITY.md` describe them and are not re-litigated here as
  findings.
