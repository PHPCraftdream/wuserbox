# The window before the shield

Measured on one ordinary machine, unelevated, while deciding how to close the
escape a concurrent run gets at a newborn stub. The design that came out of it
is [one stub for a sandbox](../design/one-stub-for-a-sandbox.md); this is the
evidence under it, kept because three of the conclusions are the opposite of
what was believed before the probe was written.

The probe models a run the way `internal/win/proc/middle_test.go` does: the
driver's own token stands in for the account's unrestricted one, and
`token.AsSandbox` with a group nothing is a member of stands in for the
restricted one. A directory granted to `INTERACTIVE` and nobody else is the
payload — something a run's own token cannot write and a stolen unrestricted
one can — so that "the door is open" and "the door leads somewhere" are
separate questions.

What it settled:

- **Token theft is not the mechanism.** A restricted process duplicates the
  unrestricted token and wears it only at identification level, which writes
  nothing. The control, the same attack from an unrestricted process, reaches
  impersonation level and writes. So the live door is code injection —
  `PROCESS_VM_WRITE`, `PROCESS_CREATE_THREAD`, `THREAD_SET_CONTEXT` — where the
  unrestricted token is the process's own and nothing is worn at all.
- **An integrity label closes every door and kills MSYS**, which extends
  [MSYS under a restricted token](msys-under-a-restricted-token.md): bash dies
  on `\BaseNamedObjects`, which is Medium and machine-wide.
- **Taking the account's SID out of the restricting list closes it and kills
  MSYS and PowerShell** — and, incidentally, closes `WRITE_DAC` too, which is
  the measurement showing why `sid.OwnerRights` is load-bearing while that SID
  stays in the list.
- `CreateProcessWithLogonW` refuses `STARTUPINFOEX`, and a job can no longer
  filter the token of what is assigned to it.

The transcript follows verbatim.

```
the driver's own integrity: S-1-16-8192

=== lowering a directory's mandatory label, unelevated ===
  wrote S:(ML;OICI;NW;;;LW) onto D:\system_artefact\Temp\wuserbox-probe-2882314759\low

the victim (unrestricted, medium integrity) is pid 41724, one of its threads is 32896

=== the control: the same attack from an unrestricted process ===
  OPEN    OpenProcess(PROCESS_ALL_ACCESS)
  OPEN    OpenProcess(PROCESS_DUP_HANDLE)
  OPEN    OpenProcess(PROCESS_VM_WRITE)
  OPEN    OpenProcess(PROCESS_CREATE_THREAD)
  OPEN    OpenProcess(WRITE_DAC)
  OPEN    OpenProcess(WRITE_OWNER)
  OPEN    writing the INTERACTIVE-only directory, own token
  OPEN    OpenProcess(PROCESS_QUERY_INFORMATION)
  OPEN    OpenProcessToken(TOKEN_DUPLICATE|IMPERSONATE)  its integrity is S-1-16-8192
  OPEN    DuplicateTokenEx(impersonation)                restricted=false
  OPEN    wearing its token and writing INTERACTIVE-only worn at impersonation level (2)
  OPEN    CreateProcessAsUser(its token)
  OPEN    OpenThread(THREAD_SET_CONTEXT|SUSPEND_RESUME), known id
  OPEN    OpenThread(WRITE_DAC), known id
  OPEN    OpenThread(THREAD_SET_CONTEXT|SUSPEND_RESUME)
  OPEN    OpenThread(WRITE_DAC)
  OPEN    control: opening its own process by name

=== a run as it is today: restricted token, medium integrity ===
  (the prowler ran at integrity S-1-16-8192)
  OPEN    OpenProcess(PROCESS_ALL_ACCESS)
  OPEN    OpenProcess(PROCESS_DUP_HANDLE)
  OPEN    OpenProcess(PROCESS_VM_WRITE)
  OPEN    OpenProcess(PROCESS_CREATE_THREAD)
  OPEN    OpenProcess(WRITE_DAC)
  OPEN    OpenProcess(WRITE_OWNER)
  closed  writing the INTERACTIVE-only directory, own token
  OPEN    OpenProcess(PROCESS_QUERY_INFORMATION)
  OPEN    OpenProcessToken(TOKEN_DUPLICATE|IMPERSONATE)  its integrity is S-1-16-8192
  OPEN    DuplicateTokenEx(impersonation)                restricted=false
  closed  wearing its token and writing INTERACTIVE-only worn at identification level (1)
  closed  CreateProcessAsUser(its token)                 A required privilege is not held by the client.
  OPEN    OpenThread(THREAD_SET_CONTEXT|SUSPEND_RESUME), known id
  OPEN    OpenThread(WRITE_DAC), known id
  OPEN    OpenThread(THREAD_SET_CONTEXT|SUSPEND_RESUME)
  OPEN    OpenThread(WRITE_DAC)
  OPEN    control: opening its own process by name

=== the same restricted token at low integrity ===
  (the prowler ran at integrity S-1-16-4096)
  closed  OpenProcess(PROCESS_ALL_ACCESS)
  closed  OpenProcess(PROCESS_DUP_HANDLE)
  closed  OpenProcess(PROCESS_VM_WRITE)
  closed  OpenProcess(PROCESS_CREATE_THREAD)
  closed  OpenProcess(WRITE_DAC)
  closed  OpenProcess(WRITE_OWNER)
  closed  writing the INTERACTIVE-only directory, own token
  closed  OpenProcess(PROCESS_QUERY_INFORMATION)
  closed  OpenThread(THREAD_SET_CONTEXT|SUSPEND_RESUME), known id
  closed  OpenThread(WRITE_DAC), known id
  closed  listing its threads                            none found
  OPEN    control: opening its own process by name

=== medium integrity, with the account's own SID out of the restricting list ===
  (the prowler ran at integrity S-1-16-8192)
  closed  OpenProcess(PROCESS_ALL_ACCESS)
  closed  OpenProcess(PROCESS_DUP_HANDLE)
  closed  OpenProcess(PROCESS_VM_WRITE)
  closed  OpenProcess(PROCESS_CREATE_THREAD)
  closed  OpenProcess(WRITE_DAC)
  closed  OpenProcess(WRITE_OWNER)
  closed  writing the INTERACTIVE-only directory, own token
  closed  OpenProcess(PROCESS_QUERY_INFORMATION)
  closed  OpenThread(THREAD_SET_CONTEXT|SUSPEND_RESUME), known id
  closed  OpenThread(WRITE_DAC), known id
  closed  OpenThread(THREAD_SET_CONTEXT|SUSPEND_RESUME)
  closed  OpenThread(WRITE_DAC)
  OPEN    control: opening its own process by name

=== what a run's token can do TODAY ===
  cmd.exe                                        ok
  writing into the low-labeled directory         ok
  writing into the unlabeled (medium) directory  ok
  reading C:\Windows                             ok
GNU bash, version 5.2.37(1)-release (x86_64-pc-msys)
Copyright (C) 2022 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>

This is free software; you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
  bash --version                                 ok
git version 2.53.0.windows.2
  git --version                                  ok
  powershell -NoProfile                          ok
v24.12.0
  node --version                                 ok

=== the same token lowered to low integrity ===
  cmd.exe                                        ok
  writing into the low-labeled directory         ok
Access is denied.
  writing into the unlabeled (medium) directory  exit 1
  reading C:\Windows                             ok
      0 [main] bash (32596) C:\Program Files\Git\bin\..\usr\bin\bash.exe: *** fatal error - NtCreateDirectoryObject(\BaseNamedObjects\msys-2.0S5-1888ae32e00d56aa): 0xC0000022
  bash --version                                 exit 3221225794
git version 2.53.0.windows.2
  git --version                                  ok
  powershell -NoProfile                          ok
v24.12.0
  node --version                                 ok

=== the same token with the account's own SID out of the restricting list ===
  cmd.exe                                        ok
  writing into the low-labeled directory         ok
  writing into the unlabeled (medium) directory  ok
  reading C:\Windows                             ok
      0 [main] bash (36596) C:\Program Files\Git\bin\..\usr\bin\bash.exe: *** fatal error - CreateFileMapping S-1-5-21-716976243-447150123-4053037466-1001.1, Win32 error 5.  Terminating.
  bash --version                                 exit 256
git version 2.53.0.windows.2
  git --version                                  ok
The shell cannot be started. A failure occurred during initialization:
Requested registry access is not allowed.
  powershell -NoProfile                          exit 4294901760
v24.12.0
  node --version                                 ok

=== does CreateProcessWithLogonW take the extended startup information ===
  plain STARTUPINFO                            started=false, The user name or password is incorrect.
  STARTUPINFOEX + EXTENDED_STARTUPINFO_PRESENT started=false, The parameter is incorrect.

=== can a job still filter the token of what is put into it ===
  JobObjectSecurityLimitInformation            accepted=false, The request is not supported.

=== does a job count what its member's own job holds ===
  the outer job counts 2 active of 2 ever started; 2 means the program inside the stub's own job is counted too
```
