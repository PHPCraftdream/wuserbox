package usage

// reference is what the manual carries after the entries: the two things
// wuserbox has never said about itself anywhere, and that a reader otherwise
// has to find by reading the source or by experiment.
//
// It is not part of the overview. The overview is read by somebody who has
// just been refused a write and needs to know what to ask for, and every line
// added there is a line between them and that answer. Whoever wants the whole
// of it asks for the whole of it.
const reference = `
THE RULES FILE

  %USERPROFILE%\.wuserbox.ktav holds the directories each project gets on
  every run. "wuserbox --add-dir" and "wuserbox --remove-dir" edit it;
  "wuserbox --config show" prints it and "wuserbox --config validate" checks
  it without applying it.

  One entry per project, naming the project directory and the directories it
  may write to and read:

    projects: [
        {
            dir: C:/projects/app
            ro: [
                C:/reference
            ]
            rw: [
                C:/build/out
                C:/projects/app/logs
            ]
        }
        {
            dir: C:/projects/other
        }
    ]

  Paths are written with forward slashes, because a backslash begins an escape
  in this format. A project with no extra directories still gets its own
  project directory and its own temporary directory; the rule only adds to
  that.

  Two rules for the same project are not merged: only the first is applied and
  the second is silently dropped, which is one of the things validate reports.
  A directory in both rw and ro loses its write access, because the readable
  entry wins, and that is reported too. Set WUSERBOX_CONFIG to read the rules
  from somewhere else.

  A second, project-independent list, "profile", names what is copied from
  the user's own profile into a sandbox's own thin one before a run:

    profile: [
        .claude
        .gitconfig
        AppData/Local/claude-cli-nodejs
    ]

  Each entry is a path relative to the profile root, copied to the same
  relative place under the sandbox's; there is no rw or ro here, because
  copying only ever reads from the user's profile and never writes back to
  it. It is pre-filled when this file is first created, from the agent preset
  and the credentials a coding agent commonly needs, and is otherwise edited
  by hand like the rest of this file. A name missing on this machine is
  simply not copied.

ENVIRONMENT

  Set for the program running inside a sandbox:

    WUSERBOX_DIR      the project directory the sandbox belongs to
    WUSERBOX_GROUP    the name of the sandbox, which is also its group
    TEMP, TMP         the sandbox's own temporary directory, which it may
                      write to and which "wuserbox --rm" deletes

  Read by wuserbox itself:

    WUSERBOX_CONFIG            the rules file to read, instead of the one in
                               the profile root
    WUSERBOX_NON_INTERACTIVE   set by --non-interactive, and passed on, so a
                               command that re-runs itself with more rights
                               does not stop at a dialog nobody can click

  A program can tell it is inside a sandbox by WUSERBOX_DIR being set. What it
  may write is not in the environment and cannot be changed from there:
  "wuserbox --explain" is how to read it, from outside.
`
