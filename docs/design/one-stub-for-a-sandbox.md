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
it in that window with `PROCESS_ALL_ACCESS`, duplicate the unrestricted token,
and wear it. A reviewer reproduced every step.

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
