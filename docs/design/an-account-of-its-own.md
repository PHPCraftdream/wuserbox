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

## Open questions

- Where the account password lives, and what protects it.
- Whether a process started as another account can keep this console, its
  standard handles and Ctrl+C. This decides whether the design is usable at
  all, and it is the first thing to measure.
- What happens to sandboxes made by the current version when a new one meets
  them.
- Whether the copy is made afresh each run or only where the source is newer.

## Acceptance

A coding agent started with `wuserbox` in a project can run `bash`, `git` and
its own tooling; it sees the credentials the rules file lists and nothing else
of yours; it cannot write or delete outside the project and what was granted;
and a second sandbox cannot touch the first. Measured, not argued.
