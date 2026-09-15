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

## The leading hypothesis, not yet tested

The probe above created its pipe with Win32 `CreateNamedPipeW`, which opens by
full path. Cygwin does it differently: it opens the NPFS **root directory**,
`\Device\NamedPipe\`, once with `NtOpenFile`, caches that handle, and creates
each pipe with `NtCreateNamedPipeFile` relative to it. Opening that root as a
directory is an access the probe never performed, and a restricted token is
checked against it twice like everything else.

If that is the mechanism, the question becomes which identity
`\Device\NamedPipe` grants, and whether one of them can join the restricting
list without opening the file boundary.

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

Narrow identities — `INTERACTIVE`, the logon session, something per-sandbox —
are the direction worth measuring.

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
