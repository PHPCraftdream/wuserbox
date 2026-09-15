# A sandbox with an account of its own

**Status:** decided, not built. Follows
[the MSYS investigation](../investigations/msys-under-a-restricted-token.md),
which established that no change to the restricting list can let MSYS2
programs start, because the only identities that would work are the user's own
by another name.

## What changes

A sandbox stops being *your* token with its rights cut down, and becomes a
local account of its own. The group per project stays and keeps doing what it
does — it is what NTFS entries name — and the account becomes its only member.

That single change removes the whole class of failures the investigation found.
The objects a program builds around "the current user" are then the sandbox's
own objects: the MSYS runtime's signal pipe, its per-user shared section, its
rewritten default list, and the registry a shell wants to write to. None of
them needs a restricted token to be talked out of refusing.

## What the profile is

**Ultra-thin, and built by us.** Not the profile Windows would create on first
logon, and not yours. A directory of our own, handed to the process as its
`USERPROFILE`, `HOME`, `APPDATA` and `LOCALAPPDATA`, holding nothing except
what was put there on purpose.

This is the part that makes the design better than what it replaces rather than
merely different. Today a sandbox is handed `~/.claude`, `~/.config` and their
neighbours whole, so an agent reads and writes the real ones — every project's
history, every tool's settings, all of it. With a thin profile it gets a copy
of what is listed and nothing else.

## How the profile is made

Measured, because the obvious two shapes are both wrong. Starting the program
without loading a profile leaves the account with no `HKEY_CURRENT_USER` at all
— the hive does not exist and writing to it is refused — and letting Windows
make one puts it in `C:\Users\<account>` with everything copied from the
default profile, which is neither thin nor ours.

There is a third way, and it works: **tell Windows the profile is already
there, at our path.** Before the first run, `--init` writes under
`HKLM\...\ProfileList\<sid>` three values — `ProfileImagePath`, `Sid` and
`State` set to zero — and puts an empty `NTUSER.DAT` in the directory. Windows
then honours the path and copies nothing, because there is already a hive to
load. Seeding fewer values than that was measured to be ignored outright: the
entry is rewritten and a full profile appears in `C:\Users` regardless.

What Windows adds next to that hive is about 2.2 MB, nearly all of it six
fixed-size registry transaction logs, plus `UsrClass.dat`, a DPAPI master key
and a handful of empty directories under `AppData`. They can be deleted between
runs and are made again; the tools do not care. So "thin" means about two and a
half megabytes per sandbox rather than nothing, and that is the honest number.

**The hive's own permissions are the part that matters.** A hive created with
`RegLoadAppKey` comes out granting `Everyone` full control, and once the profile
service loads it as that account's `HKEY_CURRENT_USER` the permission is
enforced for real: measured, an ordinary user wrote into a sandbox's registry
from outside, which means one sandbox could write another's. So `--init`
tightens it — load it under a temporary name, set the list to the account,
`SYSTEM` and the administrators, unload — before it is ever used. Doing it from
inside on the first run also works and leaves a window open while it happens,
which is a worse answer for the sake of one elevated call that is already
being made.

Everything a sandbox needs was measured to work against an empty hive: the MSYS
shell, `git` including `config --global` and a commit, `node`, `npm`,
PowerShell, and a coding agent. Known folders resolve from the environment
rather than from the registry. What starts blank is anything that expected the
default profile's own settings — locale and the like — which is inferred rather
than measured.

The cost in time is tens of milliseconds: about fifty to ninety for the very
first run of a sandbox, twenty-five to a hundred to load the hive on a cold run
afterwards, and a few milliseconds when it is already warm. Nothing pauses for
seconds.

Removal is three steps, one of them needing the elevated prompt that creation
already needs: the directory can be deleted unprivileged because our own entry
is on it, then `DeleteProfileW` clears the `ProfileList` entry and
`NetUserDel` the account, and the reference the profile service keeps has to go
with them.

## What is copied in

Before each run, the files and directories named in the rules file are copied
from your profile into the sandbox's. That is where an agent's credentials and
settings come from.

The list lives in the rules file and is **pre-filled** when that file is
created, so the common agents work without anybody writing a list by hand. It
has to be a list rather than a fixed set in the program: agents appear faster
than releases do.

## Copying back is not part of this

Nothing travels from the sandbox to your profile. A sandbox that could write
back into the files its own credentials come from would be able to rewrite
them, which is the shape of hole this tool exists to close.

The cost is real and has to be said plainly: an agent that refreshes a token
inside the sandbox refreshes a copy, and the next run starts from the original
again. Where that means logging in every run, the answer is to log in once
outside the sandbox so the refreshed file is in your own profile, not to open a
path back.

## What it costs

- **A local account per project**, with a password wuserbox generates and keeps.
  `--init` already asks for administrator rights to make the group; making an
  account is the same prompt, not a new kind of one.
- **Your stored credentials are no longer reachable from inside.** Credential
  Manager, DPAPI secrets and mapped drives belong to your account, and the
  sandbox is not you any more. The README says a sandbox runs with "your
  environment, your `HKEY_CURRENT_USER` and your credentials"; that sentence
  has to become narrower and honest.
- **`HKEY_CURRENT_USER` becomes the sandbox's own**, which is what lets a shell
  and a registry-writing tool work at all, and means nothing of yours is read
  from there.
- **Files the sandbox creates are owned by the sandbox account.** You need to
  keep being able to delete them, so the project directory has to carry an
  inheritable entry for you.

## What has to keep working

The twenty-five boundary tests named in `.github/workflows/ci.yml`, unchanged
in meaning: a sandbox writes and deletes only inside what it was granted, and
never reaches another sandbox. The mechanism underneath them changes
completely; the properties do not.

And the promise at the top of the README, in its narrowed form: the sandbox
still reads what you can read, through membership of `wub-read` rather than
through a restricting identity.

## What was measured before building any of it

The design holds. Under a throwaway local account, made and removed for the
purpose:

- **The shell starts.** `bash --version` from Git for Windows printed its
  banner and exited 0, with none of the fatal errors the investigation
  recorded. `git` and `powershell -NoProfile` ran too. That is the whole reason
  for the change, and it is confirmed rather than argued.
- **Starting the program needs no administrator rights.**
  `CreateProcessWithLogonW` is the one call that is guaranteed to work from an
  ordinary user, and it takes the account's password — which is why where that
  password lives is now a question the design has to answer rather than a
  detail. `LogonUser` with `CreateProcessAsUser` happened to work here only
  because this account is in `Administrators`; on a plain account it would not.
- **Reading works as intended.** `BUILTIN\Users` covers `C:\Windows` and
  `C:\Program Files` — neither grants `Everyone` — and membership of
  `wub-read` covers the user's own files, which grant no `Users` entry at all.
- **Without a Windows-made profile**, which is what the thin profile wants,
  `USERPROFILE` points at `C:\Users\Default`, there is no `HKEY_CURRENT_USER`
  hive, and writing to it fails. Reading the registry still works, and
  PowerShell still ran. So a shell works without a profile; anything that saves
  settings in the registry will not, which is what the README already says
  about sandboxes today.
- **Nothing extra had to be granted** to start the process: no window station
  or desktop permission was needed.

## Open questions

- Where the account password lives, and what protects it. This one grew:
  `CreateProcessWithLogonW` needs the password on every run, not only at
  creation.
- Whether `Ctrl+C` from a keypress reaches a program running as another
  account. This was reported as broken and the report does not establish it:
  the same measurement fails identically for a program started by the *same*
  account, so it was measuring its own method rather than the account
  boundary. Sending the event the documented way — a child in its own process
  group, signalled by that group's id — ends the child with
  `STATUS_CONTROL_C_EXIT`, within one account at least.

  It is also no longer a question that can stop the design. wuserbox holds the
  child's handle, so if a keypress does not cross the boundary by itself, the
  parent can catch it and stop the child — through a job object, which reaches
  grandchildren too. Today the parent deliberately ignores `Ctrl+C` because the
  shared console delivers it directly; that would become an explicit hand-off
  instead of a property relied upon.
- What happens to sandboxes made by the current version when a new one meets
  them.
- Whether the copy is made afresh each run or only where the source is newer.

## Building one as a standard user: not done, and how it would work

A standard user's consent prompt asks for *another* administrator's
credentials, and `ShellExecuteEx` with `runas` has nowhere to put an
environment block — the service that starts the elevated process builds one
from whoever answered. So the elevated half runs as that administrator, and
two things land in the wrong place at once:

- `%LOCALAPPDATA%` is theirs, so the record goes into their profile.
- `CryptProtectData` seals under their account, so even a record that
  somehow reached the right person could not be opened by them.

Today wuserbox detects this after the fact — the elevated run reports
success and the record is not where this process looks — refuses instead of
asking for elevation again, and says what was left on the machine. That is
honest and it is not a fix.

The fix is to split the elevated half down to only what actually needs
administrator rights, and hand the rest back:

1. The unelevated parent passes its own account identifier — public
   information, safe on a command line — and the paths it wants used.
2. The elevated child makes the group, the account and the profile, and
   writes the generated password into a file whose permission list names
   exactly that one account and nobody else.
3. The parent reads it, seals it with its own DPAPI, writes the record into
   its own state directory, and deletes the file.

The password crosses a process boundary in the clear, on disk, for as long
as those two steps take. That is the part to measure rather than reason
about: the permission list has to be right before the bytes are written,
not after, and the file has to go even where the parent dies in between.
None of it can be measured on a machine whose only user is an
administrator, which is why it is written down here instead of built.

## Acceptance

A coding agent started with `wuserbox` in a project can run `bash`, `git` and
its own tooling; it sees the credentials the rules file lists and nothing else
of yours; it cannot write or delete outside the project and what was granted;
and a second sandbox cannot touch the first. Measured, not argued.
