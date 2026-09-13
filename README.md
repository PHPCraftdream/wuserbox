# wuserbox

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
| `wuserbox audit [depth]` | list directories writable by Everyone |
| `wuserbox version` | show the release this build came from |

Options: `--dir <d>` picks the project, `--rw <d>` and `--ro <d>` add
directories for one invocation, `--no-ai` skips the agent preset,
`--home-writes` opts into writing in the profile root.

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
internal/e2e      escape attempts against a real sandbox
.github           tests and release workflows, build recipe, npm wrapper
```

## Tests

```
go test ./...
```

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
