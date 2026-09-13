# wuserbox

[![tests](https://github.com/PHPCraftdream/wuserbox/actions/workflows/ci.yml/badge.svg)](https://github.com/PHPCraftdream/wuserbox/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/PHPCraftdream/wuserbox?sort=semver)](https://github.com/PHPCraftdream/wuserbox/releases)
[![go](https://img.shields.io/github/go-mod/go-version/PHPCraftdream/wuserbox)](https://go.dev)
[![platform](https://img.shields.io/badge/platform-windows-0078d4)](https://github.com/PHPCraftdream/wuserbox)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](LICENSE)

Run a command on Windows so that it **reads everything you can read**, but
**writes only where you allow**. Intended for AI coding agents: they need your
whole toolchain and configuration, and they must not be able to damage anything
outside the project.

```
wuserbox run -- claude
```

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

## How it works

Two Windows mechanisms, nothing else:

1. **A local group per project.** The folder name plus a hash of its full path
   become a group such as `wub-wuserbox-d6e9a21f`. The group's comment stores
   the full path, so the mapping works in both directions with no database. The
   group has no members and cannot log on.

2. **A write-restricted token.** The command runs under *your* account, with
   your environment, your `HKEY_CURRENT_USER` and your credentials, but the
   token carries a list of restricting identifiers. Reads are checked once,
   against you. Writes are checked twice: against you *and* against that list.
   A write therefore succeeds only where the project's group has a permission
   of its own, which wuserbox grants as ordinary NTFS entries.

Nothing is emulated or intercepted. The kernel enforces it, child processes
inherit it, and a sweeping `rm -rf` stops at the same boundary as everything
else.

## Commands

| Command | Effect |
| --- | --- |
| `wuserbox run -- <cmd>` | run a command sandboxed for the current directory |
| `wuserbox init` | create the group and apply permissions |
| `wuserbox grant <dir> [--ro]` | allow one more directory |
| `wuserbox revoke <dir>` | take an allowance back |
| `wuserbox add-dir <dir> [--ro]` | remember a directory in the rules and grant it |
| `wuserbox remove-dir <dir>` | forget a directory and revoke it |
| `wuserbox name [dir]` | show the group for a directory |
| `wuserbox path <group>` | show the directory behind a group |
| `wuserbox list` | list sandboxes |
| `wuserbox rm` | delete group, permissions and temp directory |
| `wuserbox explain` | what this sandbox may touch, and why |
| `wuserbox check <path> --operation write` | ask whether one thing would be allowed |
| `wuserbox config show\|path\|validate` | read and check the rules file |
| `wuserbox audit [depth]` | list directories writable by Everyone |
| `wuserbox version` | show the release this build came from |
| `wuserbox help [command]` | the overview, or the full entry for one command |

Every command carries its own entry: `wuserbox help grant` prints what it
does, which options it reads, whether it asks for administrator rights and a
few examples. `wuserbox grant --help` prints the same thing. The overview is
written for a coding agent that has just been refused a write: it says where
the boundary is and which command to ask the user for.

Options: `--dir <d>` picks the project, `--rw <d>` and `--ro <d>` hand over
another directory, `--no-ai` withholds the agent directories, `--home-writes`
opts into writing in the profile root.

`--dry-run` shows what a command would change without changing it, taking both
the rules file and the permissions the sandbox holds into account, `--json`
gives the diagnostic commands machine-readable output, `--quiet` drops the
progress messages, and `--non-interactive` fails instead of raising a consent
prompt, so a script never stops at a dialog nobody can click.

A directory handed over with `--rw` or `--ro` stays available on later runs
too, until `wuserbox revoke` takes it back. Nothing is given up when the
process ends: a permission that vanished whenever a run was interrupted would
be a promise the tool could not keep.

Directories may be written in any usual form, and the option order does not
matter:

```
C:\tools    c:/tools    /c/tools    /mnt/c/tools    /cygdrive/c/tools
~/tools     %USERPROFILE%\tools     $HOME/tools     ..\tools
```

Creating or deleting a group needs administrator rights, so `init` and `rm`
raise a consent prompt once. `run` does not, unless the sandbox does not exist
yet.

## What is writable by default

* the project directory;
* a private temp directory, which `TEMP` and `TMP` point at;
* the state directories of AI agents found on the machine: `~/.claude`,
  `~/.codex`, `~/.crush`, `~/.rush`, `~/.gemini`, `~/.grok`, `~/.qwen`,
  `~/.factory`, `~/.continue`, opencode, Goose and others, plus
  `~/.claude.json` as a single file.

The profile root itself is **read-only**. Handing it over would make every
dotfile already in it writable, because Windows pushes an inherited permission
down to the files that are already there. Agents that rewrite a dotfile in the
profile root through a temporary file and a rename need `--home-writes`; with
that flag every sensitive file there is refused one by one.

## Protecting your settings

Code running in the sandbox must not be able to widen its own permissions:

* `~/.wuserbox.ktav` and the per-sandbox bookkeeping get a fixed permission
  list with inheritance switched off. They cannot be changed or deleted from
  inside, even if a permission is later granted on the directory around them.
* The shell startup files and credential directories in the profile root get
  the same treatment: `.bashrc`, `.profile`, `.gitconfig`, `.npmrc`, `.netrc`,
  `.ssh`, `.gnupg`, `.aws` and their neighbours.
* `init`, `rm`, `grant`, `revoke`, `add-dir` and `remove-dir` refuse to run
  from inside a sandbox, and wuserbox never asks for administrator rights from
  there. The check reads the kernel's restricted-token flag, which sandboxed
  code cannot clear.
* Sensitive entries that do not exist yet are taken as empty placeholders under
  the same locked permissions before the profile root is handed over, so a
  sandbox cannot claim one of those names first. A name is taken as whatever it
  is meant to be: `.ssh` becomes a directory, not an empty file that would
  break every tool reading it. The one case that cannot be
  reserved is a shell startup file whose presence would hide another that is
  really there; wuserbox says so instead of creating it.
* Each project has its own group and its own temp directory, so one sandbox
  cannot write into another's project.

## Standing rules

`~/.wuserbox.ktav` records the directories a project always gets:

```
projects: [
    {
        dir: C:/Users/Computer/Desktop/pc/wuserbox
        rw: [
            C:/Users/Computer/Desktop/pc/tools
            C:/Users/Computer/Desktop/pc/logs
        ]
    }
]
```

Edit it with `wuserbox add-dir <dir>` and `wuserbox remove-dir <dir>`, or by
hand. Paths are stored with forward slashes, because ktav reads a backslash as
an escape, but every spelling above is accepted when the file is read, in the
`dir` key as well as in the lists.

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

`wuserbox run` is the exception: it returns whatever the command inside
returned, so the code you read after it is the sandboxed program's own.

## Limits worth knowing

* **Reading is not restricted.** The sandbox sees your keys, tokens and browser
  data, and can decrypt whatever your account can. It prevents damage, not a
  determined leak.
* **The network is not restricted.**
* **Directories writable by Everyone stay writable**, because `Everyone` has to
  be one of the restricting identifiers for programs to start at all.
  `wuserbox audit` lists them; there are usually a handful under
  `C:\ProgramData`.
* **`HKEY_CURRENT_USER` is read-only.** Command-line tools rarely care;
  anything that saves settings in the registry will fail to.
* **Interface isolation is weak.** A sandboxed process shares your desktop and
  clipboard.
* **A batch file's arguments still expand variables.** Starting a `.cmd` or
  `.bat` goes through the command interpreter, which replaces `%NAME%` before
  the script runs. Punctuation is quoted, so an argument cannot start a second
  command, but there is no escape for expansion on a command line.
* **The agent directories are shared.** Every sandbox may write `~/.claude` and
  its neighbours, so a poisoned hook there would run with full rights the next
  time you start an agent outside wuserbox. Use `--no-ai` if that matters.
* **Renaming the project directory** changes the group, leaving the old sandbox
  behind. `wuserbox list` shows it, `wuserbox rm --dir <old>` removes it.

## Layout

```
cmd/wuserbox      the executable
internal/win      Windows calls: identifiers, permissions, tokens, processes, groups
internal/policy   what a sandbox is allowed: grants, presets, rules, bookkeeping
internal/sandbox  identity, creation, execution
internal/cli      the commands
internal/exit     the exit codes every failure maps to
internal/e2e      escape attempts against a real sandbox
.github           tests and release workflows, build recipe, npm wrapper
```

## Tests and linting

```
go test ./...
go vet ./...
golangci-lint run --config .github/golangci.yml ./...
```

The linter configuration lives under `.github/` rather than the repository
root, so it has to be named on the command line. It turns on errcheck, govet,
staticcheck, ineffassign, unused, misspell, unconvert, nilerr and errorlint,
and excuses only the Windows calls whose second return value carries nothing:
releasing a handle or a buffer cannot usefully fail.

The end-to-end tests create real permissions under a synthetic identifier and
try to escape: writing outside the project, through a child process, into the
profile, into the registry, and deleting a whole tree. They need no elevation.
The full lifecycle test creates an actual local group, so run it from an
elevated shell:

```
go test ./internal/e2e -run TestCLIFullLifecycle -v
```

## Releasing

A tag starting with `v` triggers the release workflow: it fetches the parser
library, builds both architectures with [GoReleaser](https://goreleaser.com),
publishes the archives and checksums, pushes the Scoop manifest to the bucket
repository and publishes the npm package.

```
git tag v0.1.0 && git push origin v0.1.0
```

Two secrets are needed: `BUCKET_TOKEN`, a token that may push to the Scoop
bucket repository, and `NPM_TOKEN`.

## License

Dual licensed: use it under the Apache License, Version 2.0, or the MIT
license, whichever suits you. Both texts are in [LICENSE](LICENSE).

    SPDX-License-Identifier: MIT OR Apache-2.0

Contributions come in under the same two licenses.
