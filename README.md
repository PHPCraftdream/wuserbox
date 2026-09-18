# wuserbox

[![tests](https://github.com/PHPCraftdream/wuserbox/actions/workflows/ci.yml/badge.svg)](https://github.com/PHPCraftdream/wuserbox/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/PHPCraftdream/wuserbox?sort=semver)](https://github.com/PHPCraftdream/wuserbox/releases)
[![go](https://img.shields.io/github/go-mod/go-version/PHPCraftdream/wuserbox)](https://go.dev)
[![platform](https://img.shields.io/badge/platform-windows-0078d4)](https://github.com/PHPCraftdream/wuserbox)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](LICENSE)

Run a command on Windows so that it **reads what its own account and your
read group can reach — not everything you can read**, but **changes nothing
the machine does not already let every local account change, anywhere you
did not allow it to**. Your files, another sandbox's
files and anything named to its owner alone are out of a sandbox's reach; a
directory the machine already leaves open to everybody — `C:\ProgramData` on
many installations — is not, and `wuserbox --audit` lists those. That
exception is the whole of it, and it is
[explained in full](docs/limits.md) rather than left to be discovered.

Intended for AI coding agents: they need your whole toolchain and
configuration, and they must not be able to damage anything outside the
project.

```
wuserbox claude
```

Running is what wuserbox does unless the first word is one of its commands, so
that line is complete. Options belong to wuserbox and come before the program;
everything from the program onwards belongs to the program.

## Installing

With [Scoop](https://scoop.sh), which also keeps it up to date:

```
scoop bucket add wuserbox https://github.com/PHPCraftdream/scoop-bucket
scoop install wuserbox
```

With npm, handy when the agents themselves are installed that way:

```
npm install -g wuserbox
```

From source, if you have Go:

```
go install github.com/PHPCraftdream/wuserbox/cmd/wuserbox@latest
```

Or take the archive from [Releases](https://github.com/PHPCraftdream/wuserbox/releases)
and put `wuserbox.exe` on your PATH. Keep the `ktav_cabi-windows-*.dll` beside
it: that is the configuration parser, and with it in place the first run needs
no network.

Wherever it ends up, it has to be somewhere **every account can read and
execute** — `C:\Program Files` or a shared tools directory, rather than a
folder inside your own profile. A run starts wuserbox again as the sandbox's
own account, and that account is not you. `wuserbox --init` starts it once and
says so plainly if it could not.

## How it works

Two Windows mechanisms, nothing else:

1. **A local group per project.** The folder name plus a hash of its full path
   become a group such as `wub-wuserbox-d6e9a21f`. The group's comment stores
   the full path, so the mapping works in both directions with no database.
   Every permission wuserbox grants is an ordinary NTFS entry naming this
   group, and the group is what decides what the sandbox may touch.

2. **A local account per project**, the group's only member, such as
   `wub-4c2f8a1bd6e9a21f`. The current name carries a second hash so two
   groups with the same legacy suffix cannot share an account; older sandboxes
   keep their shorter account name through migration. The command runs as
   *that account* — not as you. It cannot
   log on at the sign-in screen and cannot log on remotely. Your own Full
   Control over your own profile is not something it carries, because it is
   not you.

3. **A token restricted to that account's own identities.** Every access is
   then checked twice — once against what the account is, once against a short
   list: the project's group, `Everyone`, `BUILTIN\Users`, your read group,
   and the account itself. Both checks have to allow it, so an entry naming
   anything else reaches nothing, whoever the machine hands it to.

   A token can only be narrowed from inside the account it belongs to, which
   is why a run is two processes: wuserbox starts as the account, cuts its own
   token down, and starts your program under it.

So an access succeeds only where the group, or one of the few identities a
sandbox needs in order to function at all, has a permission of its own.
Reading stays open because `Everyone` and `BUILTIN\Users` between them cover
the system, and your own read group covers your own profile — a group nothing
but your own sandbox accounts ever joins.

Nothing is emulated or intercepted. The kernel enforces it, child processes
inherit it, and a sweeping `rm -rf` stops at the same boundary as everything
else.

### What the sandbox gets instead of your profile

Because it is not you, it does not have your profile. It gets one of its own:
a directory wuserbox builds, holding an empty registry hive and three folders,
handed to the program as its `USERPROFILE`, `HOME`, `APPDATA`, `LOCALAPPDATA`
and `TEMP`. It costs about two and a half megabytes.

The files named in the `profile:` section of the rules file are **copied in**
from your profile before each run — that is where an agent's credentials and
settings come from. The list is pre-filled when the rules file is created
with the credential and settings **files** of the agents found on the
machine: `~/.claude.json`, `~/.claude/.credentials.json`, `~/.codex/auth.json`
and their neighbours. On the machine this was written on that comes to 17
entries and 254 KB.

Histories, logs, caches and databases are deliberately left behind. The
default named whole state directories once, and that was 72,320 files and
19 GB per sandbox per run, almost none of it credentials. So a sandbox starts
logged in and configured, with a blank history — which is also the better
answer: one project's transcripts have no business inside another project's
sandbox.

Nothing on the sensitive list — `~/.ssh`, `~/.netrc`, `~/.npmrc`,
`~/.gitconfig` — is in that default, and neither is anything inside those
directories. Add what you need by hand; that is you choosing, which is the
whole difference.

The real directories themselves are never handed over: a sandbox reaches
`~/.claude` only through the copy in its own profile, and a legacy grant left
by an older version of wuserbox is taken back the first time `--init` or an
ordinary run reconciles the sandbox, whichever comes first.

**Nothing is copied back.** A sandbox able to write into the files its own
credentials came from could rewrite them, which is the shape of hole this
exists to close. The cost is real — an agent that refreshes a token inside
the sandbox refreshes a copy, and the next run starts from your original
again. Where that means logging in every run, log in once outside the
sandbox so the refreshed file is in your own profile.

The sandbox has a profile of its own because it has an account of its own, and
it has an account of its own because MSYS2 programs — `bash` and everything
built on it — could not start under a restricted copy of *your* token. The
whole measurement is in
[docs/investigations](docs/investigations/msys-under-a-restricted-token.md),
and what it led to in
[docs/design](docs/design/an-account-of-its-own.md).

## Commands

| Command | Effect |
| --- | --- |
| `wuserbox [options] <program> [args...]` | run a program sandboxed for the current directory |
| `wuserbox --init` | create the group and apply permissions |
| `wuserbox --grant <dir> [--ro]` | allow one more directory |
| `wuserbox --revoke <dir>` | take an allowance back |
| `wuserbox --add-dir <dir> [--ro]` | remember a directory in the rules and grant it |
| `wuserbox --remove-dir <dir>` | forget a directory and revoke it |
| `wuserbox --name [dir]` | show the group for a directory |
| `wuserbox --path <group>` | show the directory behind a group |
| `wuserbox --list` | list sandboxes |
| `wuserbox --rm` | delete group, permissions and temp directory |
| `wuserbox --explain` | what this sandbox may touch, and why |
| `wuserbox --check <path> --operation write` | ask whether one thing would be allowed |
| `wuserbox --config show\|path\|validate` | read and check the rules file |
| `wuserbox --audit [depth]` | list directories writable by Everyone or `BUILTIN\Users` |
| `wuserbox --version` | show the release this build came from |
| `wuserbox --help [command]` | the overview, or the full entry for one command |
| `wuserbox --help --all` | the whole manual: every entry, the rules file and the environment |

A command carries a dash, and that is what tells it from a program:
`wuserbox --list` asks wuserbox, `wuserbox list` starts a program called list.
Nothing without a dash is a command, so a program is never shadowed by one —
help included: `wuserbox help` tries to run a program called help, and
`wuserbox --help` or `-h` is what asks.

Every command carries its own entry: `wuserbox --help grant` prints what it
does, which options it reads, what it returns in its exit code, whether it asks
for administrator rights and a few examples. `wuserbox --grant --help` prints
the same thing. The overview is written for a coding agent that has just been
refused a write: it says where the boundary is and which command to ask the
user for.

`wuserbox --help --all` prints all of it at once — every entry in full,
followed by the format of the rules file and the environment wuserbox sets and
reads. Nothing in it is written twice: the manual, the overview and the single
entries are all rendered from one list, and a test holds each command's
documented options to the flags it really registers, so the manual cannot fall
behind the program.

Running and configuring are separate. Starting a program takes the sandbox as
it stands and changes nothing, so a run has no options that decide what may be
written: `--dir <d>` picks the project and that is all. What a sandbox may
write is decided by `--init`, `--grant` and `--add-dir` — `--rw <d>`, `--ro
<d>`, `--no-ai` and `--home-writes` belong to `--init`, and to the rules file
the other two write. The answer is therefore in one place, readable
afterwards with `wuserbox --explain`, rather than depending on which command
line happened to start the program.

`--dry-run` shows what a command would change without changing it, taking both
the rules file and the permissions the sandbox holds into account, `--json`
gives the diagnostic commands machine-readable output — a failure under
`--json` is reported as JSON too, so a script meets one shape either way —
`--quiet` drops the progress messages, and `--non-interactive` fails instead
of raising a consent prompt, so a script never stops at a dialog nobody can
click.

A directory handed over with `--grant`, `--add-dir` or `--init --rw` stays
available on later runs too, until `wuserbox --revoke` takes it back. Nothing
is given up when the process ends: a permission that vanished whenever a run
was interrupted would be a promise the tool could not keep.

What you ask for outranks the agent preset. Narrowing one of the directories
the preset hands over, say `wuserbox --grant ~/.claude --ro`, stays narrow:
later runs apply the preset again and leave that decision alone.

Directory names are taken as written when they name something that exists, so
a project called `build$STAGE` is that project and not `build`.

Directories may be written in any usual form, and the option order does not
matter:

```
C:\tools    c:/tools    /c/tools    /mnt/c/tools    /cygdrive/c/tools
~/tools     %USERPROFILE%\tools     $HOME/tools     ..\tools
```

Deciding what a sandbox may write to needs administrator rights, so `--init`,
`--rm`, `--grant`, `--revoke`, `--add-dir` and `--remove-dir` raise a consent
prompt. Starting a program does not, unless the sandbox does not exist yet, in
which case it is built first.

## Standing rules

`~/.wuserbox.ktav` records the directories a project always gets:

```
projects: [
    {
        dir: C:/Users/name/projects/app
        rw: [
            C:/Users/name/projects/tools
            C:/Users/name/projects/logs
        ]
    }
]
```

Edit it with `wuserbox --add-dir <dir>` and `wuserbox --remove-dir <dir>`, or
by hand. Paths are stored with forward slashes, because ktav reads a backslash as
an escape, but every spelling above is accepted when the file is read, in the
`dir` key as well as in the lists.

## Environment

Set for the program running inside a sandbox:

| Variable | Holds |
| --- | --- |
| `WUSERBOX_DIR` | the project directory the sandbox belongs to |
| `WUSERBOX_GROUP` | the name of the sandbox, which is also its group |
| `TEMP`, `TMP` | the sandbox's own temporary directory, which `--rm` deletes |

Read by wuserbox itself:

| Variable | Effect |
| --- | --- |
| `WUSERBOX_CONFIG` | the rules file to read, instead of the one in the profile root |
| `WUSERBOX_NON_INTERACTIVE` | set by `--non-interactive`, and passed on, so a command that re-runs itself with more rights never stops at a dialog |

A program can tell it is inside a sandbox by `WUSERBOX_DIR` being set. What it
may write is not in the environment and cannot be changed from there;
`wuserbox --explain` is how to read it, from outside.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | what was asked was done |
| 1 | something went wrong |
| 2 | the command line was wrong |
| 3 | the answer is no: a refused access check, or a sandbox asking for more |
| 4 | administrator rights are needed and prompts are switched off |
| 5 | the rules file does not parse or contradicts itself |
| 6 | what was named does not exist |

A run is the exception: it returns whatever the program inside
returned, so the code you read after it is the sandboxed program's own.

## Further reading

- [What a sandbox may touch](docs/what-a-sandbox-may-touch.md) — what is
  writable without being handed anything, the delete boundary itself, and
  keeping your own settings out of reach.
- [Limits worth knowing](docs/limits.md) — everything a sandbox does not
  stop, said plainly.
- [Working on wuserbox](docs/working-on-wuserbox.md) — the layout, the tests,
  and cutting a release.
- [docs/design](docs/design) — why the sandbox is built out of a local
  account and a restricted token, what fills its profile, and why a run
  leases its sandbox before it starts anything.
- [docs/investigations](docs/investigations) — the measurements those
  decisions were made from, including the ones that came back the opposite of
  what was believed.

## License

Dual licensed: use it under the Apache License, Version 2.0, or the MIT
license, whichever suits you. Both texts are in [LICENSE](LICENSE).

    SPDX-License-Identifier: MIT OR Apache-2.0

Contributions come in under the same two licenses.
