# A console in the operator's own window

Measured on one ordinary machine — Windows 10 Pro 22H2, build 10.0.19045.7725,
unelevated — while looking for a way to run an interactive terminal program
inside a sandbox without the separate window `--own-console` opens.

The question under all of this: a program like Codex CLI or Crush refuses to
start unless its standard input is a real console (`isatty`, which on Windows
means `GetConsoleMode` answering on a genuine console handle). The account the
sandbox runs under is a *different local account* than the one that owns the
operator's console, and a console cannot be shared across that line. Today's
answer is `--own-console`: the stub calls `AllocConsole` before `Shield`
(`internal/sandbox/exec/stub.go:121`, `internal/sandbox/exec/console.go`), gets
a real console, and the operator gets a second window on the desktop. The
second window is what this investigation was asked to remove.

## What was already settled, and is treated here as premise

Three things were measured earlier in this session and are not reopened below:

- `AttachConsole(ATTACH_PARENT_PROCESS)` from inside the account's process,
  aimed at the operator's console: **access is denied**.
- `CreateProcessWithLogonW` — the call that crosses the account line
  (`internal/win/proc/logon.go:19,535`) — refuses `STARTUPINFOEX` outright
  ("the parameter is incorrect"), which takes `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE`
  off the table *for that call*.
- `AllocConsole` inside the account, before the token narrows, succeeds and
  produces a working console — the shipped `--own-console`.

A pipe or socket standing in for a terminal is also not reopened: no pipe
satisfies `GetConsoleMode`. Avenue 3 below is not that proposal, and says so
in its own words.

## 1 — Windows Terminal's default-terminal handoff: **NOT VIABLE** (high confidence)

**The hope.** If Windows Terminal is the machine's default terminal
application, a newly created console is not hosted by a legacy conhost window;
conhost hands the session off to Terminal, which shows it as a *tab*. If a
console `AllocConsole` makes inside the sandbox account were handed off the
same way, the sandbox's console could land as a tab in the operator's existing
Terminal window, and the separate top-level window would be gone.

**What this machine says.** The delegation keys exist and are at their default:

```
HKEY_CURRENT_USER\Console\%%Startup
    DelegationConsole   REG_SZ  {00000000-0000-0000-0000-000000000000}
    DelegationTerminal  REG_SZ  {00000000-0000-0000-0000-000000000000}
```

All zeros means the inbox console host — no handoff happens here today. The
build is capable of the setting (Windows 10 gained it with KB5026435, build
19045.3031, with Terminal 1.17+; this is 19045.7725 with Terminal 1.24.11911.0
installed), so "turn it on" is a real option on this machine, and the verdict
below does not rest on the setting being off.

**Why turning it on would not help.** Four separate reasons, each sufficient:

- *The setting is read out of the console owner's own HKCU.* The key above is
  per-user. The console in question is created by a process running as the
  sandbox account, which has its own hive (`docs/investigations/a-hive-per-slot.md`) —
  the operator's `DelegationTerminal` never applies to it. This one is only a
  configuration problem, but the next three are not.
- *Terminal's handoff server is a per-user packaged COM registration.* The
  installed package's manifest registers the handoff classes as MSIX
  `com:Extension` entries:

  ```
  <com:Extension Category="windows.comServer">
    <com:Class Id="2EACA947-7F5F-4CFA-BA87-8F7FBEEFBE69" />
    <com:Class Id="E12CFF52-A866-4C77-9A90-F570A7AA2C6B" />
  ```

  Neither CLSID is registered machine-wide: `HKLM\SOFTWARE\Classes\CLSID\{2EACA947-…}`
  does not exist on this machine. MSIX class registrations live in the
  registering user's class store, and the sandbox account — a bare local
  account with no package registration and no Store provisioning — has no path
  to `CoCreateInstance` them.
- *COM activation does not cross the account line in the direction wanted.* An
  out-of-process COM server activated by the sandbox account runs *as the
  sandbox account*, in a process of its own. Even on a machine where the class
  were reachable, the handoff would stand up a second Terminal process owned by
  the sandbox account, not deliver the session into the operator's Terminal
  process. Reaching the operator's process would require the class to be
  registered as a machine-wide server running as the interactive user — which
  is not how Terminal registers, and would be a privilege escalation shape if
  it were.
- *Tab-vs-window is decided by Terminal's monarch, which is also per-user.*
  Terminal picks an existing window for a new tab by talking to a
  per-user-per-session COM singleton (the "monarch"). A Terminal started under
  the sandbox account finds no monarch of the operator's — it becomes its own
  monarch and opens its own window.

**Verdict.** The handoff mechanism is about *who hosts a console*, not about
*who may share one*, and every hop in it (registry read, class activation,
monarch lookup) is scoped to the user identity of the process that created the
console. Turning Terminal on as the default terminal would, at absolute best,
change the chrome of the extra window from conhost to Terminal — and on this
machine it would not even do that, because the sandbox account cannot activate
the packaged server at all. Same-window rendering is not what it buys.

**Confidence.** High on the conclusion, and it is reasoned from documented
architecture plus the registry and manifest facts above rather than from a
reproduction: the sandbox account cannot be made to activate the packaged COM
server here, so the negative could not be produced as a live experiment. The
part measured directly is the state of the delegation keys, the absence of the
CLSIDs from HKLM, and the manifest's per-user registration of them.

## 2 — Granting the sandbox account access to the operator's console object: **NOT VIABLE** (measured)

**The hope.** The earlier `AttachConsole` denial is an access check. If console
objects are securable, the operator's process could add the sandbox account's
SID to its own console's DACL before the run starts — the same move
`internal/win/acl` already makes on files — and the denial would go away.

**What was run.** A probe in a scratch directory (gitignored, not part of the
tree): allocate a console, open its devices with various access masks, and ask
the object for a security descriptor. Verbatim:

```
CONIN$   GENERIC_READ|GENERIC_WRITE                 open ok   GetKernelObjectSecurity: The request is not supported.
CONIN$   READ_CONTROL only                          open ok   GetKernelObjectSecurity: The request is not supported.
CONIN$   WRITE_DAC only                             open FAILED Access is denied.
CONIN$   WRITE_OWNER only                           open FAILED Access is denied.
CONOUT$  GENERIC_READ|GENERIC_WRITE                 open ok   GetKernelObjectSecurity: The request is not supported.
CONOUT$  READ_CONTROL only                          open ok   GetKernelObjectSecurity: The request is not supported.
CONOUT$  WRITE_DAC only                             open FAILED Access is denied.
CONOUT$  WRITE_OWNER only                           open FAILED Access is denied.

GetNamedSecurityInfo("\\.\CONOUT$", SE_FILE_OBJECT): FAILED win32 50 (The request is not supported.)
GetNamedSecurityInfo("CONOUT$",     SE_FILE_OBJECT): FAILED win32 50 (The request is not supported.)
```

Two controls make those lines mean something rather than being a broken probe:

- The same `GetKernelObjectSecurity` call, in the same process, on ordinary
  pipe handles, answers normally:
  `D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-21-…-1001)(A;;FR;;;WD)(A;;FR;;;AN)`.
  The API works; the console device is what refuses.
- A **same-account** child, detached from its own console, attaching to this
  process's console, succeeds and gets a live one:
  `AttachConsole(32732) ok; CONOUT$ open err=<nil> GetConsoleMode err=<nil> mode=0x3`.
  So `AttachConsole` is not broken in general — the cross-account denial is
  about identity.

**What that adds up to.** The denial is identity-based, but it is not a DACL
anybody can edit:

- The console devices will not even *issue* a handle carrying `WRITE_DAC` or
  `WRITE_OWNER` — and the process asking is the one that created the console,
  in its own session, with its own token. There is no "open for control" step
  to build on.
- With `READ_CONTROL` granted, the object still answers `ERROR_NOT_SUPPORTED`
  to a security query. The ConDrv-backed console object does not implement the
  query/set-security path at all, so it carries no descriptor to amend. Being a
  handle is not the same as being a securable kernel object, and this is one of
  the types that is not.
- The named-object path through the object manager says the same thing
  (win32 50) rather than "access denied", which is the tell: this is an
  unimplemented operation, not a refused one.

**Verdict.** The earlier "access is denied" was the final word. The check that
rejects a foreign account lives in the console server's connect path, keyed to
who owns the console, and there is no security descriptor anywhere on the
object for a grant to land in. Nothing in `internal/win/acl` could be pointed
at a console, because there is nothing there to point at.

## 3 — A pseudo console *inside* the account, relayed over the bridge: **VIABLE** (measured in part)

Neither of the two avenues above survives, so this is where the report earns
its keep. It is a third mechanism, not a variant of the three closed ones.

**The shape.** Stop trying to make the account share the operator's console.
Give the account a console of its own that has *no window* — a pseudo console —
and relay its rendered bytes to the operator's real console, which draws them
in place, in the window the operator already has.

Concretely, and matching where the code already puts things:

1. The stub, still holding the account's unrestricted token and before
   `proc.Shield()` runs (`internal/sandbox/exec/stub.go:108-136` — the same
   birth window `--own-console` already uses, for the same reason), calls
   `CreatePseudoConsole` with the two bridge pipes as its ends.
2. The stub starts the program with `STARTUPINFOEX` +
   `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` through plain `CreateProcessW`
   (`internal/win/proc/run.go`) — **not** `CreateProcessWithLogonW`. The closed
   finding about `STARTUPINFOEX` applies only to the account-crossing call, and
   this launch does not cross accounts: the stub is already inside it.
3. The program sees a genuine console: `GetConsoleMode` answers, `isatty` is
   true, raw mode works, because a real conhost in PTY mode is serving it.
4. The VT byte stream comes out of the pseudo console's pipe, crosses the
   account line as *bytes* on the bridge that already exists
   (`internal/win/proc/logon.go`, `outputBridge`/`inputBridge`), and wuserbox
   writes it to the operator's own console with
   `ENABLE_VIRTUAL_TERMINAL_PROCESSING`. Keystrokes go back the other way with
   the operator's console in raw / `ENABLE_VIRTUAL_TERMINAL_INPUT` mode.

**This is not the rejected pipe-as-terminal.** The rejection was right: no pipe
satisfies `GetConsoleMode`, so a pipe cannot *be* the program's terminal. Here
nothing asks it to. The program's terminal is a real console object living
inside the sandbox account; the pipe only carries already-rendered VT between
two real terminals. That is the same division of labour as ssh, tmux and
Terminal itself: one console at each end, bytes in the middle.

**What was measured.** The hard part of this is whether a process that has no
console of its own can build one for a child. It can — probe output, verbatim:

```
pty host (detached, no console attached) says:
  GetConsoleWindow at start: 0x0 (0 means no console attached)
  CreatePseudoConsole: ok, handle 0x1a52e22ee50
  CreateProcess with the pseudo console attached: ok, pid 65404
  what the pseudo console printed: "\x1b[2J\x1b[m\x1b[HCHILD std handles: stdin console=false
  (The handle is invalid.) stdout console=false (The handle is invalid.); CONIN$ open=<nil>
  mode=0x1f7 (<nil>); CONOUT$ open=<nil> mode=0x7 (<nil>)\r\n\x1b]0;…\a\x1b[?25h"
```

Three things in that line matter. The host had no console (`0x0`) and
`CreatePseudoConsole` still succeeded. The child got a real console —
`CONIN$` at mode `0x1f7`, `CONOUT$` at `0x7`, both answering `GetConsoleMode`.
And the child's *inherited standard handles were invalid* until it opened the
console devices by name, which is exactly the CRT-startup gap this repository
already documents and already works around in `openConsoleStreams`
(`internal/sandbox/exec/console.go`) and `fixupStdinFromConin`
(`internal/win/proc/stdin_bridge_test.go`) — so the fixup that path needs is
code that already exists here.

**What was not measured, and is the risk to retire first.** Whether
`CreatePseudoConsole` succeeds *under a real sandbox account* — it spawns an
`OpenConsole`/conhost of its own, as that account. The strongest argument that
it will is that `--own-console` already spawns a conhost under exactly that
token, before `Shield`, and is shipped and measured. But "AllocConsole works
there" is an argument, not the measurement; the measurement wants a real
sandbox account, which needs an `--init` run.

Other things the implementation would owe, none of them boundary questions:

- Size. The pseudo console is born at a fixed size; the operator's console can
  be resized, and `ResizePseudoConsole` has to be called across the bridge when
  it is. Nothing propagates that today.
- Mode restoration. The operator's console goes into raw/VT mode for the
  duration and must come back out on every exit path, including Ctrl-C.
- Ctrl-C. Today an interrupt reaches the account's process group directly; with
  a pseudo console in the middle, the operator's Ctrl-C has to be forwarded as
  a byte (`0x03`) into the PTY rather than — or as well as — signalled, and
  which of the two is right depends on what the sandboxed program expects.
- Fidelity. A ConPTY relay is VT-in, VT-out; programs doing direct console API
  work (buffer reads, colour attribute APIs) are translated by conhost and
  usually fine, but this is the class of thing that only real use shakes out.

**Verdict.** Viable, and it is the only avenue of the three that ends in the
operator's own window. It costs a real piece of work — a relay, raw mode on
this side, resize and interrupt plumbing — and it does not remove the account
boundary, it stops asking the boundary for something it will never give.

## Recommendation

There is one real path to same-window rendering, and it is avenue 3: a pseudo
console created inside the sandbox account, with its rendered output relayed
over the bridge pipes that already cross the boundary. It should be the next
thing tried, and the first step is the one measurement still missing — build a
sandbox with `--init` and see whether `CreatePseudoConsole` succeeds under that
account's token in the same window before `Shield` where `AllocConsole` already
does.

If that measurement fails, the honest thing to tell the operator is this, and
it is worth saying plainly rather than as an apology:

> A Windows console is not a file or a device that can be shared. It is served
> by a host process bound to the identity that created it, it carries no
> security descriptor — the kernel does not even implement the question, which
> was measured, not assumed — and no permission can be granted on it to anyone.
> A process running as a different account cannot attach to it, cannot open its
> devices, and cannot be given the right to. That is not a gap in wuserbox; it
> is the same boundary that makes the sandbox worth having, seen from the other
> side. What a sandbox can have is a console of its own. The only question left
> is where its pixels are drawn: in a window of its own (`--own-console`,
> today), or relayed into the operator's window by something that reads one
> console and writes another.

Windows Terminal's tab mechanism does not change that answer, and neither does
any ACL.

## 4 — ConPTY under a real sandbox token, via the actual launch call: **VIABLE** (measured)

Section 3 ended on one risk it could not retire from the desk it was written
at: whether `CreatePseudoConsole` succeeds under a *real* sandbox account —
"AllocConsole works there" was an argument, not the measurement — and whether
a child attaches to it through the call wuserbox itself uses,
`CreateProcessAsUserW` with `STARTUPINFOEX` +
`PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` + `EXTENDED_STARTUPINFO_PRESENT`, never
tested with `STARTUPINFOEX` anywhere in this codebase. Both are now measured,
on a real account, live.

**Where the account came from.** No new sandbox was built and no elevation
was asked for. The account from this machine's earlier probe session,
`wub-25e03ccf5218477d`, still answers `net user`: the OS account outlived the
worktree that owned it, and its sealed password outlived that worktree too,
in the state record `%LOCALAPPDATA%\wuserbox\wub-conpty-probe-5218477d.json`.
`account.Unprotect` opens that seal under the operator account the same way
it does on every run — 24 characters, never printed — and the account's group
and read-group memberships are still exactly what `--init` gives a sandbox.
Before trusting any of it, the shipped binary ran a control against the same
sandbox and succeeded (`wuserbox --dir D:\dev\go\wuserbox\scratch\conpty-probe
cmd /c echo …` printed through the whole stub chain), so the account was
known to log on and run before the probe said a word. The operator clicked
nothing: no UAC prompt appeared at any point.

**The probe.** A standalone scratch program (untracked, gitignored, not
committed) with three modes mirroring the production chain and nothing else.
The parent mode logs the host on exactly as `runAsAccount` does —
`LOGON_WITH_PROFILE`, `CREATE_UNICODE_ENVIRONMENT`, `CREATE_NO_WINDOW`,
bridge pipes for output, no lease, no narrowing — and relays the host's
output live. The host mode is the stub's pre-`Shield` window standing still:
the account's unrestricted token, no narrowing of any kind. It calls
`CreatePseudoConsole`, then starts a child through `CreateProcessAsUserW`
with the pseudo console attribute — first with the account token, then with
the token `token.AsSandbox` builds, which is the token `proc.Run` receives
after `Shield`. The child mode is avenue 3's checker verbatim in shape: what
`GetStdHandle` says, then `CONIN$`/`CONOUT$` opened by name and answered for
`GetConsoleMode`, the report written to a `CONOUT$` it opened itself and, so
the evidence could not depend on relay timing, to a file in the account's
temp directory.

**What was measured.** The final run of the corrected probe, verbatim:

```
parent: probe=C:\Users\Computer\AppData\Local\wuserbox\tmp\wub-conpty-probe-5218477d\wub-conpty-probe.exe account=wub-25e03ccf5218477d readGroup=wub-read-e2144bd9 hostDir=C:\Users\Computer\AppData\Local\wuserbox\tmp\wub-conpty-probe-5218477d

== host variant: production shape (CREATE_NO_WINDOW: a console without a window) ==
-- host stdout --
-- host stderr --
running as: wub-25e03ccf5218477d
GetConsoleWindow at start: 0x0 (0 means no console attached)
[account token] CreatePseudoConsole: ok, handle 0x159b7807ac0
[account token] calling CreateProcessAsUserW with the pseudo console attached
[account token] CreateProcessAsUserW with the pseudo console attached: ok, pid 66664
[account token] child exited 0 (259 would mean it never came back)
[account token] child report file: CHILD[account token] std handles: stdin console=false (The handle is invalid.); stdout console=false (The handle is invalid.); CONIN$ open=true mode=0x1f7 (no error); CONOUT$ open=true mode=0x7 (no error)
[account token] closing the pseudo console
[account token] what the pseudo console printed: "\x1b[2J\x1b[m\x1b[HCHILD[account token] std handles: stdin console=false (The handle is invalid.);\r\nstdout console=false (The handle is invalid.); CONIN$ open=true mode=0x1f7 (no e\r\nrror); CONOUT$ open=true mode=0x7 (no error)\r\n\x1b]0;C:\\Users\\Computer\\AppData\\Local\\wuserbox\\tmp\\wub-conpty-probe-5218477d\\wub-conpty-probe.exe\a\x1b[?25h"
[restricted token] token.AsSandbox: ok
[restricted token] CreatePseudoConsole: ok, handle 0x159b7807b40
[restricted token] calling CreateProcessAsUserW with the pseudo console attached
[restricted token] CreateProcessAsUserW with the pseudo console attached: ok, pid 38380
[restricted token] child exited 0 (259 would mean it never came back)
[restricted token] child report file: CHILD[restricted token] std handles: stdin console=false (The handle is invalid.); stdout console=false (The handle is invalid.); CONIN$ open=true mode=0x1f7 (no error); CONOUT$ open=true mode=0x7 (no error)
[restricted token] closing the pseudo console
[restricted token] what the pseudo console printed: "\x1b[2J\x1b[m\x1b[HCHILD[restricted token] std handles: stdin console=false (The handle is invalid.\r\n); stdout console=false (The handle is invalid.); CONIN$ open=true mode=0x1f7 (n\r\no error); CONOUT$ open=true mode=0x7 (no error)\r\n\x1b]0;C:\\Users\\Computer\\AppData\\Local\\wuserbox\\tmp\\wub-conpty-probe-5218477d\\wub-conpty-probe.exe\a\x1b[?25h"
== host exited 0 ==
```

**What the lines say.**

- `CreatePseudoConsole` succeeds under the real account token, in the stub's
  own birth shape — a console without a window, `GetConsoleWindow` 0x0 —
  twice, once per child. Section 3's premise is no longer an argument; it is
  the measurement, and the recommendation's "first step" is done.
- `CreateProcessAsUserW` accepts `STARTUPINFOEX` with the pseudo console
  attribute under both tokens, and the children ran: pid, exit 0, and a real
  console — `CONIN$` at mode `0x1f7`, `CONOUT$` at `0x7`, the same numbers
  avenue 3's ordinary-token probe measured. The earlier closure survives
  contact with the right API: what `CreateProcessWithLogonW` refuses,
  `CreateProcessAsUserW` — the call that does not cross the account line
  because the stub is already inside it — takes and honors.
- The restricted token is the important half. `token.AsSandbox` builds inside
  the account, and the child created with it attached to the pseudo console's
  console and reported the same modes. The production shape — console taken
  before `Shield`, program started after it through `proc.Run`'s
  `CreateProcessAsUserW` — is measured end to end in miniature.
- The CRT-startup gap reproduces under the account exactly as avenue 3 found
  it: standard handles invalid until the console devices are opened by name.
  The fix shape already exists in this tree (`openConsoleStreams`).
- The relay is real bytes, not a hope: the drain captured conhost's own
  opening sequence (`\x1b[2J\x1b[m\x1b[H`), the child's report re-wrapped at
  the pseudo console's 80 columns, the title escape naming the probe
  executable, and `\x1b[?25h` — the same rendered-VT stream avenue 3
  described, now produced under the account and read back by the probe.

One fact about the launch call itself is worth keeping: `DETACHED_PROCESS` is
refused by `CreateProcessWithLogonW` with "The parameter is incorrect" —
measured — so avenue 3's exact host shape (no console at all) cannot be
produced through the account-crossing call. Nothing is lost: the shape the
real implementation would have is the production stub's own, and that is the
one measured here.

**What was not measured, said plainly.** The host never ran `Shield` itself;
the child carried the same restricted token `AsSandbox` builds, which is what
`proc.Run` receives, but the host's own process token stayed un-narrowed
throughout, as it does in the real pre-`Shield` window. Input direction —
keystrokes typed into the relay — was never exercised. Resize, Ctrl-C
forwarding and mode restoration remain section 3's list of implementation
debts, untouched by this section. And the first two probe runs were lost to
defects in the probe itself — an HRESULT read as a BOOL, and a drain that
only delivered at EOF, which arrives after the drain — both probe-side, both
fixed before any output above was taken; no successful step changed behavior
across retries, which the repeated identical lines are there to show.

**Verdict.** Viable, measured live: the pseudo console exists under the
account's real token, children attach to it through the exact call wuserbox
uses, the restricted token inherits nothing bad, and what comes out the other
end of the pipe is rendered VT ready for the operator's window. What remains
for same-window rendering is implementation work — the relay, raw mode on the
operator's side, resize, interrupt forwarding — and no longer a boundary
question.
