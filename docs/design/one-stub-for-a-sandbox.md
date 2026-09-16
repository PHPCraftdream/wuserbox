# One stub for a sandbox

**Status:** designed, not built. It closes a reproduced escape and it is a
large change to the shape of a run, so the reasoning is written down before
any of it is typed.

Follows [a sandbox with an account of its own](an-account-of-its-own.md),
which established why a run is two processes rather than one.

## The escape it closes

A run starts a stub — wuserbox again, as the sandbox's own account — and the
stub restricts its own token and starts the program under it. The stub exists
because a restricted token can only be made by a process already running as
that account; wuserbox, running as the user, cannot make one and hand it over.

From the moment `CreateProcessWithLogonW` returns until the stub's own code
reaches `Shield`, the stub is an ordinary process of that account: the
account's unrestricted token, and the default security descriptor, which
grants its owner everything. Anything already running as that account can open
it in that window with `PROCESS_ALL_ACCESS`.

**What it does with that is put code inside the stub, not wear the stub's
token.** This was measured after being got wrong twice, here and in a review,
and the correction matters because it says which door has to be shut. A
restricted process can duplicate the unrestricted token — that part works —
but wearing it gets it only to *identification* level, which answers "who is
this" and opens nothing: measured against a directory granted to `INTERACTIVE`
and nobody else, the restricted attacker wrote nothing, and the same attack
from an unrestricted process reached impersonation level and wrote. Handing
the stolen token to `CreateProcessAsUser` is refused for want of a privilege.

So the live mechanism is `PROCESS_VM_WRITE`, `PROCESS_CREATE_THREAD` and
`THREAD_SET_CONTEXT`: the attacker's code runs *inside* the newborn stub,
where the unrestricted token is the process's own and nothing has to be worn
at all. That is exactly the door `narrowBeforeResume` cannot shut, and the
doors it does shut were the weaker half.

Two things make it unfixable where it stands. `CreateProcessWithLogonW` takes
no `lpProcessAttributes`, so the initial descriptor is not ours to set. And a
handle keeps the access it was granted at the moment it was opened, so
shielding afterwards does not take back what the window gave away.

What is needed for the attack is a process of that account already running.
There is exactly one way to have one: **a second concurrent run of the same
sandbox**, whose program is running while the second stub is being born.

## What was measured before choosing

The privileges of the token a run actually runs under, unelevated, on the
machine this was written on:

- `SeImpersonatePrivilege` — **absent**. So `CreateProcessWithTokenW`, which
  would let wuserbox start the stub already holding a restricted token and
  close the window with a few lines, is not available. This was the cheap
  answer and it is not there.
- `SeAssignPrimaryTokenPrivilege` — present but disabled, so enableable by
  the process itself. That would make `CreateProcessAsUser` usable with a
  token from `LogonUser`, which takes `lpProcessAttributes` and does inherit
  handles, and would remove the need for a stub at all.

The second one cannot be designed around. "Replace a process level token" is
granted by default to `LOCAL SERVICE` and `NETWORK SERVICE` and not to
interactive users; its presence here is this machine's configuration, not
Windows'. A design that works only where somebody has granted that right is a
design that fails on the machines it was written for.

A third thing was measured while narrowing the window from the parent, and it
is the reason narrowing cannot be pushed further. The parent can apply the
shut list to the **process** object while the stub is still suspended, and
that closes every door ending in the token: opening it for everything,
duplicating its handles, duplicating its token, wearing it. It cannot apply
the same to the stub's **threads**, and not for want of trying — doing so
breaks every real run. `Shield`'s own thread pass reopens each thread with a
fresh `OpenThread(WRITE_DAC)`, and once the parent has denied that access to
the same identity, `Shield` is refused on the thread it is trying to lock.
Narrowing the token's own default DACL breaks it the same way, for every
thread Go's runtime starts before `Shield` is reached.

So one door stays open in that window, and it is enough on its own:
`THREAD_SET_CONTEXT` on a thread of the stub redirects it into code of the
attacker's choosing, inside a process still holding the unrestricted token.
**The escape is narrowed, not closed.** The narrowing is worth having — it
takes the window down from milliseconds of Go start-up to the width of one
syscall in the parent — but a run is not safe from a concurrent run until the
rest of this document is built.

So the stub stays, and the escape is closed by removing the thing the attack
needs: **a stub is never created while a program of that sandbox is running.**

## The shape

A process that already holds the restricted token can create a new process
with it. `CreateProcessAsUser` with a token derived from the caller's own
needs no privilege, which is what `proc.Run` already does when it starts the
program. A process born that way is born restricted: there is no window at
all, because there is no moment at which it holds anything wider.

So the second run does not create a stub. It asks the first one.

- **The first run of a sandbox creates the stub.** That creation is safe, and
  for a reason that has to be stated rather than assumed: no process of that
  account is running, so there is nobody who could open the newborn stub.
- **A later run, while the first is still going, creates nothing.** It hands
  its command line to the stub that is already there, and the stub starts the
  program with the token it is already holding.
- **When the last program ends, the stub ends.** The account is then back to
  having no processes, so the next run may create a stub again, safely.

The stub is therefore resident for as long as a sandbox is in use and not one
moment longer. It is not a service, it is not started at logon, and nothing
has to clean it up.

## The invariant the safety rests on

*No stub alive implies no process of that account alive.*

Without it, "there is no stub, so creation is safe" is a guess. It holds
because of a mechanism that is already there rather than one this design adds:
the job object the stub puts the program into is created with
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, and the stub holds the only handle to
it. However the stub ends — cleanly, killed, or crashed — Windows closes that
handle and the job takes the program with it.

This must be tested and not merely argued, because the whole design is
downstream of it.

## What residency costs, and the tension it creates

Today a run is a chain of two jobs: the user's wuserbox holds a job containing
the stub, and the stub holds a job containing the program. Killing wuserbox
outright therefore kills everything, which is the safety net for the case
where nobody gets to run any cleanup.

A resident stub cannot be inside the first run's job, or the first run's
wuserbox exiting would kill a stub the second run is still using. Residency
and that safety net pull against each other, and the resolution is to move the
net rather than drop it:

- The stub is **not** in any wuserbox's job.
- Each program gets its own job **inside the stub**, one per run.
- The stub watches the connection belonging to each run. When a connection
  drops — because that wuserbox exited, cleanly or not — the stub closes that
  run's job, and the program goes with it.

The net is the same net: a run's program does not outlive the wuserbox that
asked for it. What changed is who notices, and the pipe breaking is a signal
that arrives whether or not anybody was able to run cleanup code.

## The connection, and the hazard in it

The two processes have to talk, and the obvious mechanism carries a real
danger that has to be designed against rather than discovered.

A named pipe's name belongs to whoever creates it first. If the **stub** were
the server, a program inside the sandbox could create a pipe of that name
before the stub did, and the next run's wuserbox — running as the user —
would connect to it. A pipe server can call `ImpersonateNamedPipeClient`. A
sandboxed program that can impersonate the user is a worse escape than the one
this design exists to close.

So the direction is fixed: **wuserbox is the server, the stub is the client.**
A sandboxed program squatting the name then only denies service to itself, and
the impersonation goes the harmless way — wuserbox may impersonate the
sandbox, which it already can.

Two further rules follow, and both must be in the code rather than in this
document only:

- The server verifies who connected, by `GetNamedPipeClientProcessId` against
  the process id it created. A connection from anything else is refused.
- The pipe's own security descriptor names the user and the sandbox account
  and nobody else.

The remaining question is how a **second** run reaches a stub whose server
belongs to the **first** run's wuserbox, which will exit before the stub does.
The answer is that the stub is the one holding the rendezvous: it publishes a
pipe of its own for control only, after it is shielded, and a shielded stub is
not something a sandboxed program can impersonate — it has already refused the
account everything on itself. That refusal is what makes the second pipe safe
where the first would not have been, and it is why the order matters: the
control pipe is created after `Shield`, never before.

## What this does not close

A sandbox is still one identity. Two concurrent runs of one sandbox share an
account, a group, a profile and a set of granted directories, and nothing here
changes that: they can reach each other's files, because they were always
meant to. What they can no longer do is reach a token wider than their own.

## What it also fixes

The program's output has never reached the terminal wuserbox was started from.
`CreateProcessWithLogonW` cannot inherit handles, so the stub gets a console of
its own, and until this was noticed that console came with a window that
appeared and took the keyboard — several times a second under a test run. That
window is gone (`CREATE_NO_WINDOW`), which leaves the output going nowhere
visible rather than somewhere useless.

The connection this design adds is the thing that carries it back. That is not
a bonus feature to be added later: a run that cannot show its program's output
is not finished, and the mechanism is the same mechanism.

## What else was measured, and why nothing else is left

Four other ways out were tried with a probe rather than argued about. All four
are closed, and two of them are closed by something worth knowing on its own.

**`STARTUPINFOEX` is not accepted.** `CreateProcessWithLogonW` refuses the
extended form before it even reaches the logon — the plain call gets as far as
"the user name or password is incorrect" against a nonexistent account, the
extended one is rejected with "the parameter is incorrect". So there is no
`PROC_THREAD_ATTRIBUTE_*` of any kind here: no job list, no parent process, no
security capabilities, and no pseudo-console either.

**A job cannot filter the token of what is put into it.**
`SetInformationJobObject(JobObjectSecurityLimitInformation)` answers "the
request is not supported". `JOB_OBJECT_SECURITY_FILTER_TOKENS` would have
restricted the stub at assignment, before it was ever resumed. It is gone.

**An integrity label closes every door, and takes MSYS with it.** Lower the
program's token below Medium and the newborn stub becomes untouchable —
mandatory policy denies write-up before the list is consulted, and ownership
does not override it. Every door measured shut, the thread included, with no
window at all because the label is on the token at birth. Then: the same token
at low integrity cannot start bash, which dies on
`NtCreateDirectoryObject(\BaseNamedObjects\msys-2.0…)` because that directory
is Medium and machine-wide. Making it work would mean labeling
`\BaseNamedObjects`, which is weakening the machine to strengthen one tool on
it. An account is what made MSYS start in the first place; an integrity label
takes it straight back.

**Taking the account's own SID out of the restricting list closes it, and
takes MSYS and PowerShell.** bash dies on `CreateFileMapping … Win32 error 5`,
PowerShell on "requested registry access is not allowed". The account SID has
to stay. One fact fell out of that measurement and is worth keeping: with the
account SID *not* a restricting one, `WRITE_DAC` closed too — the owner's
implicit `READ_CONTROL|WRITE_DAC` does not survive the restricted second
check. That is precisely why `sid.OwnerRights` is load-bearing today.

So the statement of the problem is exhaustive rather than a list of things
tried:

> A run is safe from a concurrent run if and only if either no process of that
> account can execute during the window, or the newborn's account is not the
> account any running program holds.

Serializing and the resident stub are the first branch. A separate account per
concurrent run is the second. There is no third.

## The recommendation: lease a slot

Give each concurrent run **an account of its own from a small pool the sandbox
already owns**, and arbitrate with one exclusive file handle.

`--init` creates `wub-<8hex>` and `wub-<8hex>-1..n`, all in the sandbox group
and the read group, all hidden from sign-in. A run leases a slot by opening
`%LOCALAPPDATA%\wuserbox\<group>.slot<n>` with no sharing; the first opener
wins, and the kernel releases it when that process dies by any cause, so there
is no stale state and nothing to time out. It lives in the user's own profile,
where the sandbox reads and cannot write, so unlike a pipe or a `Local\` object
it cannot be squatted.

**The closure is structural rather than timed.** Run A's program holds
`{group, Everyone, Users, logonA, account-1, read group}`. Run B's newborn stub
is owned by account-2 and carries account-2's default list, which names
`SYSTEM` and account-2 and not the group. The first access check fails on
membership; the owner grant fails because the owner is not the attacker's user.
There is no window to be early for and no invariant to maintain across a
process death.

**And it is one mechanism, not two.** `n = 1` *is* "serialize whole runs". The
smallest correct step is to ship the lease with one slot, which closes the
escape; raising `n` later is `--init` creating more accounts and a loop over
slot files. The two candidates weighed above turn out to be the same code with
a different number in it.

What it costs, plainly: `n` local accounts per sandbox, and `--rm` has `n` of
everything to undo. `HKEY_CURRENT_USER` becomes per slot — the profile
directory is shared through the group, so files are shared, but two concurrent
runs will not see each other's registry, and anything keeping state there will
look forgetful. A cap: run `n+1` waits. `--check` and `access.Check` have to
name a slot rather than "the account". And it does not fix output.

## Where the resident-stub design above is wrong

Kept rather than deleted, because the three errors are each worth not making
again.

**The invariant is stated on the wrong quantity.** "No stub alive implies no
process of that account alive" is true only once the job has finished killing.
The stub exits, the handle closes, the job terminates the program — and for
that interval a new run sees no stub while a program still lives. The decision
has to be made on *no process of the account*, under a lock taken before the
check. Which is the lease, so the resident design needs it too.

**The pipe reasoning does not hold.** `Shield` protects the stub *from* the
account and says nothing about who may impersonate a pipe client. What actually
protects it is that a restricted process cannot impersonate above
identification level — measured — and that the client can insist with
`SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`. Build the second; do not
rest on the first.

**The control pipe puts the squat back.** Making wuserbox the server fixed
squatting on the run pipe. On the control pipe the stub is the server, and a
squatting sandboxed program is *the same account* as the real stub: same SID,
so a connecting wuserbox cannot tell them apart. The name would have to be an
unguessable nonce minted by the user and passed on the stub's command line —
not in the sandbox record, which is readable from inside.

## Output, which is separable after all

The design above claimed the resident's connection is what carries a program's
output back. It is not the only thing that can, and tying the two together was
an argument for the resident that does not survive.

wuserbox creates two named pipes with nonce names *before* starting the stub —
so it is the server and the name cannot be squatted — and passes the names on
the command line; the stub opens them as a client and hands them to the program
as its standard handles. That works under a slot pool, under serialization and
under a resident alike, and it keeps the output path out of the thing being
contained. A real ConPTY would have to be built by the stub from those pipes,
since the pseudo-console attribute is unreachable here.
