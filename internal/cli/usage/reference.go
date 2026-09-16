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
        .claude.json
        .claude/.credentials.json
        .codex/auth.json
    ]

  Each entry names a path relative to the profile root, copied to the same
  relative place under the sandbox's; there is no rw or ro here, because
  copying only ever reads from the user's profile and never writes back to
  it. It is pre-filled when this file is first created, with three things
  belonging to the agents found on this machine: their credentials, their
  settings, and the instructions written for them -- the agents, commands
  and skills directories, and files like CLAUDE.md and AGENTS.md. A sandbox
  therefore starts logged in, configured, and knowing what it was taught.

  What the default leaves behind is the histories, logs, caches and session
  databases those same directories hold, and it is left behind on purpose:
  a default that named the agent directories whole measured 72,320 files
  and 19 GB copied into every sandbox on every run, almost none of it worth
  carrying. The default names the useful subdirectories instead, and where
  one of them is mostly cache it carries an exclusion. All of it together
  comes to a few megabytes, against a ceiling of 64 MB that stops a run
  rather than letting a rules file quietly fill a profile with somebody's
  work.

  An entry is either a bare path like the ones above -- copied whole, a file
  as a file and a directory with everything under it, which is still what
  most entries should be -- or an object that puts limits on one:

    {
        path: .codex
        depth: 2
        include: [
            *.json
            *.toml
        ]
        exclude: [
            sessions/**
        ]
    }

  "depth" bounds how far below "path" to descend: 0 copies only the files
  directly in it, and leaving it out means no limit. "include" keeps only
  the files a mask matches; "exclude" drops the files a mask matches and,
  unlike an ordinary copy, leaves alone whatever the sandbox already has
  there -- which is what makes naming a whole directory safe: ".codex" with
  "exclude: [sessions/**]" copies the credentials and the settings, and
  neither copies nor deletes the session history an agent inside the
  sandbox is writing to. A mask in either list may carry a depth of its
  own, overriding the entry's for that one pattern: { mask: *.md, depth: 3 }.

  A mask is "*", "?" or "**" and nothing else, matched without regard to
  case: "*" is any run of characters within one path segment, "?" is one
  character, and "**" is any number of whole segments, including none. A
  mask with no slash in it matches a file's own name, wherever it sits
  within the depth; a mask with a slash matches the path relative to the
  entry's own path.

  A third list, "cleanup", says what should not be sitting in a sandbox's
  own profile when a run starts -- the caches, logs and session stores the
  sandbox itself wrote. Globs relative to the profile root, in the same mask
  language, cleared before anything is copied in:

    cleanup: [
        .codex/sessions/**
        **/*.log
    ]

  It is a separate list rather than part of an entry because it answers a
  different question, and the two overlap only by coincidence: what is worth
  clearing is usually something nothing copies. A glob that would reach
  NTUSER.DAT is refused and the run stops, that file being the sandbox's
  registry rather than a cache -- so "cleanup: [**]" is an error rather than
  a very thorough sweep, which is the honest answer to a line asking for
  something that cannot be granted.

  Nothing on the protected list is in that default and nothing inside one
  either -- no .ssh, .netrc, .npmrc or .gitconfig, which are exactly what
  wuserbox protects from sandboxes. Add what you need by hand, including a
  whole directory if that is what you want. A name missing on this machine
  is simply not copied.

ENVIRONMENT

  Set for the program running inside a sandbox:

    WUSERBOX_DIR      the project directory the sandbox belongs to
    WUSERBOX_GROUP    the name of the sandbox, which is also its group
    USERPROFILE,      the sandbox's own thin profile, not the user's
    HOME, APPDATA,
    LOCALAPPDATA
    TEMP, TMP         a directory inside that profile, which the sandbox may
                      write to and which "wuserbox --rm" deletes with it

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
