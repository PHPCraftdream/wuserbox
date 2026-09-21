#!/usr/bin/env node
// Thin wrapper around the wuserbox executable shipped in this package.
// npm cannot put an .exe on PATH by itself, so it installs this shim and the
// shim hands the arguments straight over, keeping the console attached.
"use strict";

const { spawnSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const executable = path.join(__dirname, "wuserbox.exe");

if (process.platform !== "win32") {
  console.error("wuserbox runs on Windows only: it uses the Windows security APIs.");
  process.exit(1);
}
if (!fs.existsSync(executable)) {
  console.error("wuserbox.exe is missing from this package; reinstall it with `npm install -g wuserbox`.");
  process.exit(1);
}

// child_process defaults windowsHide to false, so this true is load-bearing:
// when node itself has no console (GUI launcher, scheduled task, background
// runner), Windows would hand the child a new console window that steals
// focus. From a terminal nothing changes: with stdio "inherit" the child
// attaches to the console node already has.
const result = spawnSync(executable, process.argv.slice(2), {
  stdio: "inherit",
  windowsHide: true,
});

if (result.error) {
  console.error("wuserbox: " + result.error.message);
  process.exit(1);
}
process.exit(result.status === null ? 1 : result.status);
