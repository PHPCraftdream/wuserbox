# Sandbox security review — 2026-09-19 — round 2

Independent adversarial review at `2db4d455a8475a78adc82e7d5feeef5495a97e62`
(`Carry a caller's real console input across the account boundary too`), the
tip of `main` at review time. This is the eleventh round of review on this
codebase. It reads `docs/reviews/sandbox-security-review-2026-09-19.md`
(round 1, `f0fb913`) and `docs/reviews/release-review-P-2026-09-18-round9.md`
as a map of what has already been adversarially tested, and does not repeat
that work. Per the task brief, this round's whole budget goes to the two
commits that landed after round 1 and have not been through an adversarial
pass yet: `46980f6` (`internal/win/proc/elevate.go`, elevated `--init`/`--rm`
now runs with `SW_SHOWNORMAL` instead of the implicit `SW_HIDE`) and `2db4d45`
(`internal/win/proc/logon.go`, the new `duplicateInput`/`inputBridge`
stdin-forwarding mechanism, plus the `noInherit`/`SetHandleInformation` fix
for round 1's P2-1).

**Summary.** No P0, P1, P2 or P3 finding against either of the two reviewed
commits. `git log 50c8db4..2db4d45` confirms these are the only two commits
since round 1, so this is the whole delta in scope. The new `inputBridge`
mechanism was traced end to end — every `close()`/`start()` path, every error
branch in `runAsAccount`, the defer-ordering around `streams`/`bridge`/`input`,
and the handle-hygiene calls — and no use-after-close, double-close, handle
leak that crosses the account boundary, or race was found; the five new tests
in `internal/win/proc/stdin_bridge_test.go` (including the ConPTY-based
`TestStdinBridgeCarriesRealConsoleInput`) were run in this session and pass,
which turns the commit message's claims from assertion into a locally
reproduced measurement. Round 1's P2-1 (no positive non-inheritance boundary
on the bridge pipes' parent-side ends) is confirmed closed, both by reading
`noInherit`'s call sites and by running `TestNoInheritStripsTheInheritFlag`,
`TestBridgePipeReadEndIsNotInheritable` and
`TestInputBridgePipeWriteEndIsNotInheritable` directly against
`GetHandleInformation`. `elevate.go`'s `SW_SHOWNORMAL` change was checked
against the specific hazard classes a newly-visible privileged window could
plausibly open — credential/secret exposure on screen, keyboard-focus
hijacking into an unintended confirmation prompt, and a widened
attack surface for the sandboxed account through the very
`RunAsAccountWithLease` call `--init`'s `ProveItStarts` makes from inside
that now-visible console — and none of them materialize given how this
codebase actually generates, seals and never prints its account passwords,
and given that `--init`/`--rm` have no interactive confirmation prompt to
hijack. `go build ./...` and `go vet ./...` are clean at the reviewed commit.
**Verdict: no release-blocking or otherwise actionable finding from this
round.** As in round 1: this is a negative result on a narrow, fresh slice of
the codebase, not a certification of the whole tool, and should be weighted
accordingly — ten rounds before this one each found something a prior round
missed.

## P0

None found in this round.

## P1

None found in this round.

## P2

None found in this round.

## P3

None found in this round.

## Checked and found sound

### The `inputBridge`/`duplicateInput` handle lifecycle (`internal/win/proc/logon.go:245-327`, `:429-464`, `:519-526`)

Traced every path through `runAsAccount` (`logon.go:406-550`) with `input`
(the `*inputBridge` `duplicateInput` returns) in each of its three states —
`nil` (stdin not a console), built-but-never-started, and started:

- **`duplicateInput` fails inside `inputBridgePipe`** (`logon.go:296-299`):
  returns before touching `handles.input`, so `streams.close()` in the
  caller's error path (`logon.go:430-436`) closes exactly the handles that
  exist, nothing more, nothing less.
- **`duplicateInput` succeeds, a later step before `CreateProcessWithLogonW`
  fails** (encoding `commandLine`/`env`/`password` at `logon.go:469-480`):
  `input != nil`, `inputStarted` is still `false`, so the deferred cleanup at
  `logon.go:457-464` calls `input.close()`, which closes `b.write` once. No
  other code path holds a reference to `b.write` at this point (it was just
  built by `inputBridgePipe` and wrapped into the struct, `logon.go:302`), so
  this is a plain single close, not a race.
- **`CreateProcessWithLogonW` itself fails** (`r == 0`, `logon.go:516-518`):
  `streams.close()` has already run explicitly just before this check
  (`logon.go:515`), and `inputStarted` is still `false` (the `input.start()`
  call at `logon.go:523-526` is textually after the `r == 0` check), so the
  same single `input.close()` path runs. Verified `streams.close()` at this
  point closes `streams.input`, which is the pipe-read-end duplicate that
  never got a chance to cross (the failed call created no child to inherit
  it) — no leak.
- **`CreateProcessWithLogonW` succeeds, `input.start()` runs, and a later
  step fails** (`j.assign`, `lock.PassTo`, or `narrowBeforeResume`, each
  followed by `procTerminateProcess.Call` then `return -1, err`,
  `logon.go:530-546`): `inputStarted` is now `true`, so the deferred cleanup
  is a no-op by design — ownership of `b.write` has passed to the goroutine
  started at `logon.go:265-270`, which alone closes it once `io.Copy` returns
  (on `os.Stdin` EOF/error, or once the terminated child's copy of the pipe's
  read end is released and a subsequent `Write` fails). No other code path
  ever calls `input.close()` after `inputStarted` is set, so there is no
  double-close of `b.write` on this path either. This is the same
  "abandoned, not joined" shape the commit message describes, applied
  uniformly regardless of which later step fails — not a divergent bug on
  any one of those paths.
- **Full success**: `j.waitOrStop(created.Process)` is the function's last
  statement; the deferred input/bridge/streams cleanups still run during
  unwind, in the same order verified above.

No path found where `b.write` is closed twice, used after close, or where a
handle that should have been freed survives past the point `streams.close()`
or `input.close()`/the goroutine's own close should have freed it.

### Ambient-inheritance hygiene, i.e. round 1's P2-1 (`logon.go:229-243`, `:179-200`, `:310-327`)

Read `noInherit` and both call sites (`bridgePipe`'s `read`, the output
bridge's parent-side end; `inputBridgePipe`'s `write`, the input bridge's
parent-side end) and confirmed the ordering in each: `os.Pipe()` →
`noInherit` on the end that stays →`duplicateInheritable` on the end that
crosses → close the original of the crossing end. The crossing end is
deliberately left inheritable (it has to be, to reach the child via
`STARTUPINFO`); only the parent-side end is stripped. This is symmetric with
what round 1 asked for and what `lock.PassTo` already does
(`internal/base/lock/slot.go:177-187`).

Ran the tests that measure this directly rather than trusting the comments:

```
go test ./internal/win/proc/... -run "TestNoInheritStripsTheInheritFlag|TestBridgePipeReadEndIsNotInheritable|TestInputBridgePipeWriteEndIsNotInheritable|TestDuplicateInputLeavesARedirectedStdinAlone|TestStdinBridgeCarriesRealConsoleInput" -v
```

All five pass, including the ConPTY-based
`TestStdinBridgeCarriesRealConsoleInput`, which re-execs the test binary
attached to a real Windows pseudo console and proves a byte string written to
the pseudo console's input side arrives through `duplicateInput`'s bridge at
the exact handle value the account process would inherit. Also ran the whole
`internal/win/proc` package (`go test ./internal/win/proc/... -v`, 9.4s, all
pass) — nothing else in the package regressed.

The residual caveat round 1 already recorded — whether
`CreateProcessWithLogonW` copies more than the three named `STARTUPINFO`
handles from the caller's ambient handle table is still not confirmed or
ruled out by a live two-account experiment — is unchanged by this commit and
is not re-litigated as a new finding; the commit closes the concrete gap
(inheritable parent-side pipe ends) round 1 could name, which is what it set
out to do.

### `SW_SHOWNORMAL` (`internal/win/proc/elevate.go:33-43`, `:65`) — specific hazard classes checked

- **Does the visible elevated console expose the sandbox account's
  password?** Traced `GeneratePassword` (`internal/account/secret.go:65-79`)
  to its one call site, `internal/sandbox/init.go:230`, inside
  `ensureAccount`, which only runs from `sandbox.Init`, which only runs from
  `setup.Init` (`internal/cli/setup/prepare.go:310-375`) *after* the
  `token.IsAdmin()` check has already passed (`prepare.go:318-326`) — i.e.
  the password is generated, handed to `acct.Add` (`NetUserAdd`, a Win32 API
  call, not console I/O — `internal/account/account.go:166-177`), and sealed
  with `acct.Protect` (DPAPI, `internal/account/secret.go:95-101`) entirely
  *inside* the already-elevated process, and is never passed as a command-line
  argument to that process (`rebuildOptions(...).Args()` /
  `options.Args()`, `internal/cli/setup/options.go:33-57`, carry `--dir`,
  `--rw`, `--ro`, flags — no secret) and never printed
  (grepped `fmt.Print`/`os.Stdout`/`os.Stderr`/`fmt.Fprint` across
  `internal/cli/setup/prepare.go`, `internal/account/account.go`,
  `internal/account/secret.go`: the only hits are progress lines like
  `"wuserbox: creating sandbox %s"` and the final `group\tdir` summary, none
  of which include the password). So `SW_SHOWNORMAL` makes that console
  visible, but nothing sensitive is ever written to it.
- **Does the visible, focus-stealing window (`SW_SHOWNORMAL` activates and
  restores) let a stray keystroke intended for the operator's original
  terminal land in the elevated process and get treated as an unintended
  confirmation?** Read `setup.Init` and `setup.Rm` end to end
  (`internal/cli/setup/prepare.go:310-375`, `internal/cli/setup/rm.go:27-73`,
  `:97-157`): neither reads from stdin for a yes/no confirmation or any other
  purpose outside of the `RunAsAccountWithLease` call discussed next; grepped
  `os.Stdin` across `internal/` and found it only in
  `internal/win/proc/logon.go` and its own tests, and in
  `internal/e2e/account_test.go`'s test fixture — never in
  `internal/cli/setup`. There is no prompt to hijack.
- **Does `--init`'s own `ProveItStarts` call — which also goes through
  `RunAsAccountWithLease` → `duplicateInput`, and would see a real console on
  both stdin and stdout the moment the elevated process has one, window
  hidden or not — forward the operator's keystrokes from the now-visible,
  focused elevated console to the (lower-privileged) sandbox account in a way
  that account could capture?** `exec.ProveItStarts`
  (`internal/sandbox/exec/stub.go:168-195`) calls `StubLine(self, s.SID, "")`
  with an empty command line, which produces a two-element argument list
  (`internal/sandbox/exec/stub.go:137-150`). Inside `Stub`
  (`internal/sandbox/exec/stub.go:58-122`), `len(args) == 2` makes the stub
  return immediately after `proc.Shield()` (`stub.go:106-108`) — `proc.Run`,
  the only place inside the stub that would read from its inherited stdin, is
  never reached. So even when the input bridge is genuinely built for this
  call, nothing on the far end of the pipe ever reads from it; any bytes the
  goroutine copied in are discarded, unread, when the stub exits a moment
  later. This holds regardless of whether the console is hidden (`46980f6`'s
  predecessor) or shown (`46980f6` itself) — the window-visibility change
  does not add a new reader, only a new place for the operator to notice the
  window exists. (Separately: this exact "keystrokes typed into a freshly
  focused window instead of the one the user meant to type into" property is
  generic to any newly-shown, activated foreground window on Windows — every
  UAC consent prompt already has it — and is not particular to this
  codebase.)
- **Interruption mid-operation.** A visible window has a close button a
  hidden one does not present, which is a more discoverable way to interrupt
  `--init`/`--rm` mid-flight than before (Task Manager could always do this
  regardless of window visibility, so this is not a new *capability*, only a
  more accessible trigger for an old one). Checked whether interruption here
  is unsafe: `internal/sandbox/init.go` and `internal/cli/setup/prepare.go`
  both carry explicit crash-recovery design for exactly this —
  `ensureAccount`'s comment on why the record is saved immediately after
  `NetUserAdd` commits the password (`internal/sandbox/init.go:200-208`), and
  `s.FinishPending()` (`internal/cli/setup/prepare.go:140-143`) recovering a
  record left ahead of the file system by an earlier stopped command — so an
  abrupt kill mid-`--init`/`--rm` is an already-designed-for case, not a new
  one this commit exposes.
- **Documentation staleness.** Grepped `docs/limits.md`, `.github/SECURITY.md`
  and `docs/design/*.md` for claims that elevated `--init`/`--rm` runs
  hidden; the only `CREATE_NO_WINDOW`/"no window" references in the design
  docs are about the sandbox stub (`internal/win/proc/job.go` /
  `internal/sandbox/exec/stub.go`'s process, a different mechanism entirely,
  unaffected by this commit), not about `Elevate`. No stale claim found.

### Everything else

Per the task's scope, the rest of the codebase was not re-walked this round;
`git log 50c8db4..2db4d45` shows the two commits above are the entire delta
since round 1, and round 1's own "Checked and found sound" /
"Not independently re-verified" sections (covering the ACL sweep
parallelization, the pinned-path preflight filter, the `Reapply`
skip-if-fresh optimization, `pathid.Within`, restricted-token construction,
`internal/cli/setup/rm.go` and `run.go`, and `internal/account/restrict.go`)
still describe the state of that code, unchanged since then.

## Not independently re-verified in this round

- The full existing test suite was not run — only `internal/win/proc`, the
  package touched by both reviewed commits, and only as a read-only
  verification step (no product code was changed by this review).
  `go build ./...` and `go vet ./...` were run against the whole module and
  are clean.
- Round 1's own residual caveat on `CreateProcessWithLogonW`'s ambient
  handle-inheritance behavior (whether it copies more than the three named
  `STARTUPINFO` handles) still has not been confirmed with a live two-account
  experiment; unchanged by this round's two commits, not re-litigated as a
  new finding.
- `TestTheStreamsComeBackFromInsideTheSandbox`
  (`internal/e2e/streams_test.go:69-87`) is the one test that exercises
  `duplicateInput` across a real account crossing (administrator rights, a
  real second account), and it does so with `os.Stdin` substituted by a pipe
  (`internal/e2e/account_test.go:197-198`), never a real console — confirmed
  by reading the fixture. So the real-console path
  (`TestStdinBridgeCarriesRealConsoleInput`) and the real-account-crossing
  path (`TestTheStreamsComeBackFromInsideTheSandbox`) are each measured
  separately; no single test in this repository measures both at once, which
  the commit message itself discloses and this review confirms rather than
  treats as an oversight to flag.
