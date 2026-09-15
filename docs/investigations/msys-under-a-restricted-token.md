# MSYS2 programs will not start under the restricted token

**Status:** open, under investigation. First seen 2026-09-15 on wuserbox
`3385448`.

## The problem

`bash.exe` from Git for Windows — and everything else built on MSYS2 or
Cygwin — dies during startup inside a sandbox. Nothing is wrong with the file
permissions; the failure is on kernel objects the C runtime needs before it
reaches `main`.

This is not a corner. Claude Code's Bash tool *is* `bash.exe`, so an agent
started under wuserbox has no shell at all, and the tool cannot do the job it
exists for. A user meets it as a coding agent reporting that every command
fails:

```
EPERM: operation not permitted, uv_spawn 'C:\Program Files\Git\bin\bash.exe'
```

## What was measured

Inside a live sandbox, on a real machine, these all **work**:

| | |
| --- | --- |
| `cmd.exe /c ver` | runs |
| `rg --version` | runs |
| `git --version` | runs — `git.exe` in Git for Windows is a native build, not an MSYS one |
| a plain Go binary | runs |
| creating a named pipe, a named section, a named mutex, a named event, an anonymous pipe | all five succeed |

These **fail**, both with Win32 error 5, `ERROR_ACCESS_DENIED`:

```
bash.exe: *** fatal error - CreateFileMapping <user-sid>.1, Win32 error 5. Terminating.
```

and, for a copy of `bash.exe` and `msys-2.0.dll` placed in an unrelated
directory so that Cygwin derives a fresh installation key and starts with an
empty object namespace of its own:

```
bash.exe: *** fatal error - couldn't create signal pipe, Win32 error 5
```

The same copy runs normally outside the sandbox.

PowerShell fails too, but for a different and already documented reason:
`Requested registry access is not allowed`. `HKEY_CURRENT_USER` is read-only in
a sandbox and PowerShell writes to it while starting. That one is a known
limit, not this investigation.

## What has been ruled out

- **A stale shared region.** The obvious explanation was that an unsandboxed
  MSYS process already holds Cygwin's shared memory section, whose permissions
  name only the user, so the sandboxed one cannot open it. The fresh copy
  disproves it: with its own namespace it gets past the section and fails later,
  on the signal pipe.
- **Cygwin's own switches.** `CYGWIN=nontsec`, `MSYS=nontsec` and
  `CYGWIN=noglob` change nothing. `nontsec` no longer exists in modern Cygwin.
- **A blanket denial of the object namespace.** The sandbox creates named
  pipes, sections, mutexes and events without trouble, so whatever is denied is
  narrower than "named objects".
- **File permissions.** Every file involved grants `BUILTIN\Users` read and
  execute, and that identity is in the restricting list. `bash.exe` starts far
  enough to print its own error.

## The mechanism

An earlier note here guessed that Cygwin opens the NPFS root directory,
`\Device\NamedPipe\`, and creates its pipes relative to that handle, and that
opening the root was what got denied. **That guess was wrong**, and it is
recorded rather than deleted because it is the kind of guess worth not making
twice: it was plausible, it explained the symptom, and it was not what was
happening.

What actually happens is simpler and worse. The MSYS runtime creates its signal
pipe with `CreateNamedPipe`, passing a security descriptor **it builds itself**
naming the user, `SYSTEM` and `Administrators` — and no other identity. It then
opens the other end of its own pipe with `CreateFile`. Creating succeeds;
opening is a fresh access check, the restricted token is checked twice as
always, and the second check finds nothing in that descriptor that the
restricting list carries. Access denied, and the runtime dies before `main`.

The token's default DACL, which wuserbox sets so that objects a sandbox creates
are reachable, does not help: it applies only where a program passes no
descriptor of its own, and this one does.

Measured directly, in a probe under a live sandbox, which creates a pipe and
then opens its own other end:

| Permission list on the pipe | Result |
| --- | --- |
| the user alone | created; **opening its own end denied** |
| `Everyone` | created; opened |
| the user and the sandbox group | created; opened |

Outside a sandbox all three succeed. The `CreateFileMapping` failure is the
same story one object earlier: the runtime names its shared section after the
user's SID, so an ordinary run meets a section an unsandboxed MSYS process
already made, with a descriptor of the same shape.

The last row matters: the object becomes reachable the moment the sandbox's own
identity appears in the list. A process under a restricted token can read that
identity out of its own token — `GetTokenInformation(TokenRestrictedSids)`
returned it in the probe — so a program that wanted to cooperate could. The MSYS
runtime does not, and cannot be told to.

## Why the obvious fixes are not fixes

- **Adding the user's own SID to the restricting list** would certainly work
  and would delete the boundary entirely: the second check would pass wherever
  the first one does, which is the whole point of the first one.
- **Adding `Authenticated Users`** is probably too broad. Ordinary files on a
  real profile carry `NT AUTHORITY\Authenticated Users:(I)(M)`, so the sandbox
  would gain write access to them — the very thing being prevented. Anyone
  proposing it has to measure what it opens up first.
- **Falling back to a write-restricted token** would let Cygwin through and
  give back the hole this design replaced it to close: `DELETE` and
  `FILE_DELETE_CHILD` fall outside the mapping a write-restricted token checks
  a second time, so a sandbox could delete wherever the user's own account
  already may.

- **Adding `SYSTEM` or `Administrators`**, the two other identities the MSYS
  descriptor names, is worse than it looks. The files wuserbox protects — the
  rules file, the bookkeeping, the credentials in the profile root — are
  written with a list that gives both of those Full Control, on purpose,
  so that the machine's owner can still repair them. Putting either in the
  restricting list hands the sandbox the very files the boundary exists to
  keep it away from.

Narrow identities — `INTERACTIVE`, the logon session, something per-sandbox —
are the direction worth measuring, but none of them appears in the descriptor
the runtime writes, so none of them can help with this particular object.

## Two directions, and what rules one of them out

**Patch the runtime.** Ship an MSYS runtime that reads the sandbox identity out
of its own token and adds it to the descriptors of the objects it makes. It
would work, and it costs a fork of `msys-2.0.dll` to carry forever, a matching
set of MSYS binaries, and a way to make every MSYS program load that copy
rather than the one Git for Windows installed. Selecting it through one coding
agent's own setting would be quicker and is not acceptable: wuserbox must not
be tied to a particular agent, and a fix that works only for the shell one
product happens to spawn is not a fix for the tool.

**Give the sandbox an identity of its own.** Run the program as a local account
per project rather than as the user under a restricted token. Then the runtime
builds its descriptors around an identity that really is the process's own, and
every one of these failures disappears at the source — MSYS, the registry,
anything else that reasons about "the user". Reading is not lost with it:
`wub-read`, the machine-wide group with no members that the profile already
grants read to, becomes an ordinary membership instead of a restricting
identity.

What that costs has to be worked out before it is chosen: a local account per
project and its password, files created under a different owner, a separate
`HKEY_CURRENT_USER`, and the user's stored credentials no longer reachable from
inside. The last is the one to think hardest about, because an agent that
cannot use the credentials you use is a different tool from the one described
at the top of the README.

## Status

The mechanism is settled and measured. The direction is not. Nothing in the
program has been changed for it.

## What a fix has to keep

The twenty-five tests named one by one in `.github/workflows/ci.yml`. They are
the property the tool exists for: a sandbox writes and deletes only inside what
it was granted, and never reaches another sandbox. A change that makes `bash`
start and costs one of those is not a fix.

## Reproducing it

No administrator rights are needed and no consent prompt should appear.
`CreateRestrictedToken` on a copy of your own token needs no privilege, and
`CreateProcessAsUser` with the result works unprivileged, so a standalone
harness can build the token, vary the restricting list, launch
`bash.exe --version` under each variant and report which ones start.

Against an existing sandbox it is one line:

```
wuserbox "C:\Program Files\Git\bin\bash.exe" --version
```
