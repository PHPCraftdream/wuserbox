// Package usage holds the help text, so every command can print it without
// depending on the dispatcher.
package usage

// Text is what `wuserbox help` prints.
const Text = `wuserbox - run a command that reads everything you can read, but writes
only to this directory and the directories you allow.

  wuserbox run [opts] -- <cmd> [args...]  run cmd sandboxed for the current dir
  wuserbox init [opts]                    create the group and apply permissions
  wuserbox grant <dir> [--ro]             allow this sandbox to write to dir
  wuserbox revoke <dir>                   take an allowance back
  wuserbox add-dir <dir> [--ro]           remember dir in ~/.wuserbox.ktav and grant it
  wuserbox remove-dir <dir>               forget dir and revoke it
  wuserbox name [dir]                     show the group name for a directory
  wuserbox path <group>                   show the directory behind a group
  wuserbox list                           list sandboxes
  wuserbox rm [--dir d]                   delete group, permissions and temp directory
  wuserbox audit [depth]                  list directories writable by Everyone
  wuserbox version                        show the release this build came from

options:
  --dir <d>       project directory (default: the current directory)
  --rw <d>        extra writable directory, repeatable
  --ro <d>        extra readable directory, repeatable
  --no-ai         skip the preset for AI agent directories
  --home-writes   let the sandbox create files in the profile root

Directories may be written in any usual form: C:\tools, c:/tools, /c/tools,
/mnt/c/tools, ~/tools, %USERPROFILE%\tools or a relative path.
`
