# A hive per slot, one folder between them

**Status:** measured 2026-09-16, on wuserbox `6948d54`, Windows 10.0.19045.7725.
It feeds the one open number in [one stub for a sandbox](../design/one-stub-for-a-sandbox.md)
— how many accounts a sandbox's slot pool should have by default. The probe and
its full transcript are kept in `probe/` (`probe/twohives/main.go`,
`probe/out/transcript.txt`; the two aborted starts before the clean run are left
at the top of that transcript). Every quote below is from the transcript.

The design gives each concurrent run of one sandbox an account of its own from a
small pool, while the profile *directory* stays shared through the sandbox
group. That has one consequence it states out loud:

> `HKEY_CURRENT_USER` becomes per slot -- the profile directory is shared
> through the group, so files are shared, but two concurrent runs will not see
> each other's registry, and anything keeping state there will look forgetful.

This is the measurement of that consequence, and of the assumption it rests on:
that the environment block alone decides which profile a sandboxed program
sees. The probe built the design's shape for n=2 and held it against the tools
the sandbox is for: `cmd`, `powershell`, `bash`, `git`, `node`, `npm`.

## The shape that was measured

Two local accounts (`wub--regcost-1`, `wub--regcost-2`, SIDs `-1050`/`-1051`),
built by the product's own fixtures: `account.Add`, membership, hidden from
sign-in, remote logon denied; each with a per-slot profile directory seeded by
`account.MakeProfile` and registered by `account.RegisterProfile`
(`internal/account/ownprofile.go`). One shared directory, ACL'd to the group,
holding `AppData\Local`, `AppData\Roaming`, `Temp`. The environment block handed
to every run was `exec.childEnv`'s override set (`internal/sandbox/exec/run.go`)
with the profile-rooted variables pointing at the *shared* directory. Runs went
through `proc.RunAsAccount` (`internal/win/proc/logon.go`), so
`CreateProcessWithLogonW` with `LOGON_WITH_PROFILE`, the exact call a run uses.
Commands ran directly as the account, without the stub's restricted token — the
token is derived from the account's own and includes its SID, so nothing here
turns on that difference; but it is a difference, and it is named.

One wiring was measured because the design must avoid it, not use it: both
accounts' `ProfileList` entries pointing at the *same* directory (one
`NTUSER.DAT` for both). The brief's rule was to check the assumption rather
than inherit it, and that wiring is what the assumption, taken literally,
produces.

## The finding that changes the question

**The hive wuserbox seeds is read-only for the account it was seeded for.**
Both slots were denied writing into their own loaded hive, by the same three
words the registry gives any access check:

```
  slot1 y2-a1: (exit 1)
    | ERROR: Access is denied.
  slot1 y2-a2: (exit 1)
    | ERROR: The system was unable to find the specified registry key or value.
  slot2 y2-b2: (exit 1)
    | ERROR: Access is denied.
```

(`reg add HKCU\Software\wub-probe`, then querying it back — the query finds
nothing because the write never landed.) PowerShell hits the same wall on the
key it is best known for:

```
  slot1 y7-ps-1: (exit 0)
    | Set-ExecutionPolicy : Access to the registry key
    | 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' is denied. To change the execution
    | policy for the default (LocalMachine) scope, start Windows PowerShell with the "Run as administrator" option. To
    | change the execution policy for the current user, run "Set-ExecutionPolicy -Scope CurrentUser".
    | Undefined
```

Reads work — `reg export HKCU` succeeded for both slots — and writes to
`HKCU\Software\Classes` succeed, because `Classes` is not the seeded hive: it is
`UsrClass.dat`, created by the profile service itself on first load, and it
accepted `reg add HKCU\Software\Classes\wub-probe` (`exit 0`) even while the
other slot's PowerShell was running. In the naive wiring, the account whose SID
the shared hive was tightened *for* was denied too (`slot1 x4a: ERROR: Access is
denied.`), while a substitute hive the profile service fell back to was
writable. The denial therefore travels with wuserbox's seeded `NTUSER.DAT`
specifically, not with accounts or profiles in general.

**This is not a slot-pool cost. It is one account, today.** Nothing in the
transcript suggests the pool changes it: one slot hits it exactly as two do.
The design's framing — that per-slot hives make state "look forgetful" —
presumes the state can be written at all. Measured on this machine, it cannot;
`n = 1` and `n = 2` have the same empty registry.

What caused it is **not isolated**. Two steps in `MakeProfile` are candidates:
the hive is created with `RegLoadAppKey` (`ownprofile.go:163`) and its root
list is then replaced by `tightenHive` (`ownprofile.go:177`). The probe that
would separate them — same seeding against an untightened `RegLoadAppKey` hive
and against a `C:\Users\Default`-derived hive — errored out before its worker
started and did not run. Until it does, the mechanism is a hypothesis, and the
fix is unknown.

## Does anything break outright

Under the design's shape (per-slot hive directories, shared visible directory),
sequentially and as concurrent pairs, from both accounts:

```
  slot1 y0-1-ver: (exit 0)        Microsoft Windows [Version 10.0.19045.7725]
  slot1 y0-1-powershell: (exit 0) wub--regcost-1 / 5.1.19041.7725
  slot1 y0-1-git: (exit 0)        git version 2.53.0.windows.2
  slot1 y0-1-node: (exit 0)       v24.12.0
  slot2 y0-2-powershell: (exit 0) wub--regcost-2 / 5.1.19041.7725
  slot2 y0-2-git: (exit 0)        git version 2.53.0.windows.2
  slot2 y0-2-node: (exit 0)       v24.12.0
  pair git:  both exit 0;  pair node: both exit 0
```

`cmd`, `powershell`, `git` and `node` started and printed versions from both
accounts, one after the other and simultaneously. Two things broke, and both
break with one account just as they break with two:

- **npm** dies before doing anything, in both slots:
  ```
    slot1 y0-1-npm: (exit 5)
      | C:\Program Files\nodejs\\node.exe: OpenSSL configuration error:
      | D4930000:error:80000005:system library:BIO_new_file:Input/output error:openssl\crypto\bio\bss_file.c:67:calling fopen(C:\Users\Computer\scoop\apps\openssl\current\bin\cnf\openssl.cnf, rb)
  ```
  `childEnv` inherits everything it does not explicitly replace, so the
  caller's OpenSSL configuration path reaches the sandbox, and the sandbox
  account cannot read the caller's profile. Whether dropping
  `OPENSSL_CONF`/`OPENSSL_MODULES` from the block fixes it was not measured.
- **bash** could not be judged at all. Every bash invocation failed inside the
  probe's own command wrapper before bash started:
  ```
    slot1 y0-1-bash: (exit 1)
      | 'C:\Program' is not recognized as an internal or external command,
      | operable program or batch file.
  ```
  This is a probe artifact, not a sandbox result, and it is the largest gap in
  this measurement: bash is the tool an agent's shell actually is. Under *one*
  sandbox account it is covered by `TestAShellStartsInsideARealAccount`
  (`internal/e2e/account_test.go`), which runs on CI. Under the pool's shape —
  two accounts, one shared directory, simultaneously — it is unmeasured.

## Does anything quietly forget

**Wiring X — one registered profile directory for both accounts — does not
error. It silently substitutes.** The first account loaded the seeded hive
(bare, so `HKCU\Environment` does not exist in it); the second account, logged
on with the same `ProfileList` path, reported no failure anywhere and got a
*different* HKCU — one that has the `Environment` key Windows puts into a
freshly built profile:

```
  X1 slot1 first load of the shared hive:
  slot1 x1: (exit 1)
    | ERROR: The system was unable to find the specified registry key or value.
  X2 slot2 logon while slot1 keeps the hive loaded:
  X2 slot2: started, exit 0
    | HKEY_CURRENT_USER\Environment
    | Path    REG_EXPAND_SZ    %USERPROFILE%\AppData\Local\Microsoft\WindowsApps;
    | TEMP    REG_EXPAND_SZ    %USERPROFILE%\AppData\Local\Temp
    | TMP    REG_EXPAND_SZ    %USERPROFILE%\AppData\Local\Temp
```

That second account could write its HKCU (`exit 0`), and its own next logon
found nothing there:

```
  slot2 x3a: (exit 0)
    | The operation completed successfully.
  slot2 x4q: (exit 1)
    | ERROR: The system was unable to find the specified registry key or value.
```

So the naive wiring gives every run after the first a throwaway hive, without
one error message. One honesty note: slot1's long-lived process was meant to
hold the hive for 25 seconds and died at once (`X2 slot1 ping ended (exit 1)`),
so the transcript does not prove the substitute arose *during* a live load —
only that a second registration on the same directory produced a different,
non-persistent hive. The design must register each slot's hive path
separately; "point both at one directory" is not a shortcut, it is a silent
failure.

**Credentials do not carry between slots.** The Credential Manager follows the
loaded profile, not the environment block: slot1 stored a credential
successfully, slot2 saw none of it,

```
  slot1 y5-add1: (exit 0)      CMDKEY: Credential added successfully.
  slot2 y5-list2: (exit 0)
    | Currently stored credentials:
    | * NONE *
```

and the files landed in each slot's *own* registered profile directory, not in
the shared one the environment pointed at (`slot1\AppData\Roaming\Microsoft\Credentials\...`,
426 bytes, in the accounting listing; `shared\AppData\Microsoft\Credentials`
did not exist at all — the probe's walk of it failed with "cannot find the
path"). This is the design's "quietly forgets", realized and measured: a
credential entered in one concurrent run is invisible to the other, with no
error in either.

**File-carried state carries.** The one file-backed setting measured went
through the shared directory both ways, because `HOME` is overridden to it:

```
  slot1 y7-git1: (exit 0)      git config --global user.name slot1
  slot2 y7-git2: (exit 0)      -> slot1
  slot2 y7-git3: (exit 0)      git config --global user.name slot2
  slot1 y7-git4: (exit 0)      -> slot2
```

That is the "files are shared" half of the design holding, for the tool agents
actually configure.

**PowerShell's per-user folders do not resolve, for either slot.** With a bare
seeded hive, `$PROFILE` and `[Environment]::GetFolderPath('MyDocuments')` came
back empty in both slots, while `ApplicationData`/`LocalApplicationData`
returned the *shared* directory (the environment was honored there). So
PowerShell's startup data file landed in the shared directory
(`StartupProfileData-NonInteractive` appears there in the first-run listing)
and its profile-script machinery resolves to nothing — identically for both
slots, which is a hole today, not a divergence the pool adds.

## Does sharing one profile directory hold

What ran, held. slot1 created a file in the shared directory; slot2 appended
to it, then overwrote it, each `exit 0`; both slots' PowerShell wrote into
shared `AppData\Local` without a complaint; the exclusive-handle and
concurrent-append tests were voided by probe artifacts (the append loop wrote
0 of an expected 500 lines per side — `race.txt counts: a=0 b=0` — and the
handle-holding step never confirmed it held anything), so **concurrent
same-file contention between two accounts is unmeasured**. One ambiguous
datum: the cross-account delete step reported `Could Not Find` while exiting 0,
so the clean cross-account delete is not claimed. No lock error, ownership
error or lost write appeared in anything that actually ran.

## What --rm would have to undo, counted

Per slot account, from the accounting and drill sections:

- 1 SAM entry (`net user` full record in the transcript; memberships: the
  intrinsic `Users` plus the sandbox group `wub-regcost`).
- 1 `ProfileList` key under HKLM, written by `RegisterProfile`
  (`ownprofile.go:357`). Whether a real logon also makes a
  `ProfileService\References` entry is **unmeasured** — both queries died on a
  probe-side syntax error — and `RemoveProfileServiceReference`
  (`ownprofile.go:400`) clears it best-effort either way.
- 22 files, about 2.9 MB, in the slot directory, in five families: the
  `NTUSER.DAT` family (hive, two logs, `ntuser.ini`, transaction files), a
  *stale* `NTUSER.DAT.partial` family left beside it by `MakeProfile`'s
  build-elsewhere-and-rename step (five files, ~1.2 MB, dead weight every slot
  carries), the `UsrClass.dat` family the profile service builds on first
  load (~1.2 MB), and DPAPI's `Protect` (`CREDHIST`, a master key, a
  `Preferred`) plus one `Credentials` file.
- A lock that outlives the account's last process: after the last slot
  process exited, the shared wiring's `NTUSER.DAT` could not be deleted for
  the full 60-second retry window (`shared hive files STILL PRESENT after
  60s: [NTUSER.DAT]`) and only went away at teardown once the accounts were
  deleted. Precise unload latency was not measured (the dedicated drill's
  long-lived process died instantly), but the order --rm needs is confirmed:
  processes first, then a wait the probe's own e2e fixture already warns
  about, then `DeleteProfile` (measured: `DeleteProfileW` refuses the seeded
  profile and the `RegDeleteKey` fallback ran, as `internal/account/profile.go`
  documents), then `account.Delete`, then the directory.
- Files a deleted account leaves in the *shared* directory stay deletable:
  after `account.Delete`, a file owned by the orphaned SID was deleted
  without trouble by the elevated caller.

Per sandbox, not per slot: 1 group, 1 shared profile directory, the slot-lease
files. `n` slots multiplies only the per-slot list.

## The recommendation

**Two slots as the default, with two preconditions; one slot if either cannot
be met.** The escape closes at `n = 1` already — the design says so, and the
lease is the same code with a different number in it — so the only question
this measurement answers is whether `n = 2` breaks the tools. It did not:
`cmd`, `powershell`, `git` and `node` ran from both accounts, sequentially and
simultaneously; the one file-backed setting carried; the one measured
per-slot cost is the credential split, which is real and silent but survivable
(re-enter, or keep nothing credential-shaped in a sandbox).

The preconditions come out of the same transcript:

1. **Each slot gets its own registered profile path.** One registered profile
   directory for two accounts does not fail — it silently hands the second
   logon a different, non-persistent hive. This is a wiring rule, not an
   open problem.
2. **The seeded hive's write refusal is fixed, or its cause found, before the
   pool ships.** It is a today bug that the pool neither causes nor fixes;
   shipping `n = 2` on top of it means shipping a registry that is read-only
   twice over, and it makes every later claim about HKCU behavior unmeasurable.

And the gap that guards the number: **bash under the pool's exact shape is
unmeasured.** If the team wants a number today, two is what the evidence
supports; the first thing to do after the write refusal is understood is to
re-run this probe with the bash step fixed, because bash is the one tool whose
failure would reverse this.

## What was not measured

- `bash` from two slots against one shared directory (probe artifact; quoted above).
- The mechanism of the seeded hive's write refusal: `RegLoadAppKey`'s hive
  versus `tightenHive`'s list versus the hive's origin. The differential probe
  did not run.
- Concurrent same-file contention between two accounts (append race and
  exclusive handle — both voided by probe artifacts), and a clean cross-account
  delete.
- `ProfileService\References` after real logons, and the owners of files the
  slots left in the shared directory (`dir /q` wrapper failed).
- Hive-unload latency after a genuinely long-lived process; only the
  lower bound "still locked 60 seconds after exit" is measured.
- Whether npm recovers when the caller's OpenSSL environment is dropped from
  the block.
- Everything here, on one machine, with the elevated probe's token. Nothing
  was run inside the stub's restricted token.

## Reproducing it

The probe is `probe/twohives`; it builds and removes its own accounts, group
and directories, and its transcript is the artifact:

```
go build -o probe/twohives.exe ./probe/twohives
admin probe/twohives.exe -mode all -root <abs>/probe/rig -out <abs>/probe/out/transcript.txt
```

It needs administrator rights (account creation), pops one UAC prompt, and
verifies its own teardown — the run quoted here ended:

```
  sid.Lookup(wub--regcost-1): gone (account "wub--regcost-1" not found)
  net user wub--regcost-1 gone: true
  sid.Lookup(wub--regcost-2): gone (account "wub--regcost-2" not found)
  net user wub--regcost-2 gone: true
  sid.Lookup(wub-regcost): gone (account "wub-regcost" not found)
  RESULT: clean — nothing left behind
```

## A hypothesis from reading the seeding, 2026-09-17, not measured

Written down as a hypothesis so it can be refuted rather than assumed;
nothing in the seeding has been changed. The measurement that can settle it
now runs in CI, and is named at the end.

**`tightenHive`'s permission list names no subkeys.** The three
`EXPLICIT_ACCESS` entries `setHiveSecurity` builds carry no inheritance
flags, and on a registry key that means *this key only*: after tightening,
the root grants the account, `SYSTEM` and the administrators full control of
the root and nothing under it. Every key that turns up in the hive later
therefore takes its permissions from somewhere else — and a key whose parent
offers it nothing to inherit takes its *creator's* default list. Windows
documents that fallback for new objects, and the registry follows it. So the
transcript above arranges itself:

- `HKCU\Software` was created during the first load, as `SYSTEM` — nothing in
  the seeding creates it. On this hypothesis its list is SYSTEM's default,
  which does not name the account: writes refused, reads perhaps not, which
  is what both slots got and what PowerShell hit on its own settings key.
- `HKCU\Software\Classes` accepts writes because it is `UsrClass.dat`, whose
  root the profile service permissions itself, naming the account. That is
  the profile service's work, not the seeded hive's — which is also why the
  denial travels with the seeded `NTUSER.DAT` and not with accounts in
  general, the control the naive wiring gave.
- The substitute hive in wiring X accepted writes because the profile service
  built it whole, as it builds every hive of its own.

This is also why the differential probe proposed when the finding was
written — same seeding against an untightened `RegLoadAppKey` hive — could
not have settled anything on its own: neither the tightened nor the
untightened hive refuses a write *at its root*, so a probe writing into the
hive directly would have found both writable and concluded there was nothing
to find. The refusal lives one level down, on keys a logon creates in the
account's absence. If the hypothesis is right it predicts, specifically:
**a write to the root itself succeeds**, and a subkey the account creates
directly under the root accepts further writes, while `HKCU\Software`
refuses, and its list, read out, names `SYSTEM` and the administrators and
no account.

Ranked against the evidence: it accounts for every measured fact above
without contrivance, including both controls. What it does not pin down is
which step of the first load creates `Software` — the profile service's
classes mounting is the likely author, but that is a hypothesis inside the
hypothesis, and the descriptor read out of `Software` will name whoever it
was regardless. What would refute the whole shape: the root itself refusing
a write from the account. Nothing measured so far tests that.

The measurement now runs where the rights are:
`TestWhereTheSeededHiveRefusesItsOwnAccount`
(`internal/account/ownprofile_hive_test.go`) builds a real account, seeds
the hive the way `MakeProfile` does, registers it, and asks reg.exe — one
logon per probe, the way a run starts everything — to write at the root, at
`Software`, at a fresh subkey of each, and at `Software\Classes`. It then
loads the hive itself and reports, in words, who owns the root, `Software`
and `Software\Classes` and what each permission list grants, the key that
refuses beside the key that accepts. It asserts only what the transcript
above already measured — `Software` refuses, `Software\Classes` accepts,
reads work — so that when the picture changes, because the defect was fixed
or because this hypothesis is wrong, the test goes red with the new
descriptors attached, and this section and `docs/limits.md` are the two
things to update in the same change.
