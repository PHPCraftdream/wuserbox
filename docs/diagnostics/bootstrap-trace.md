# Bootstrap timing trace

The first start of a sandbox can ask for elevation and perform several
filesystem and account operations. To see where time goes, opt in for one
run:

```powershell
$env:WUSERBOX_TRACE = "1"
$env:WUSERBOX_TRACE_FILE = "$env:TEMP\wuserbox-bootstrap.jsonl"
wuserbox rush
Get-Content $env:WUSERBOX_TRACE_FILE
```

The file is newline-delimited JSON. Each phase has a `start` record and an
end record with `status`, `duration_ms`, and `elapsed_ms`. The trace includes
the elevation request, lock waits, account/profile work, each grant root,
settings protection, profile copying, the startup probe, and command launch.
Errors are recorded on the phase that returned them. Passwords and account
secrets are never written. Paths appear only for the root whose operation is
being measured.

`WUSERBOX_TRACE_FILE=stderr` writes the trace to the current process's stderr.
For an elevated first start, use a file: the elevated child may have a
different console, but appends to the same explicit trace path.

Tracing is disabled unless one of the two variables is set and never changes
normal startup behavior. Remove the variables after the run to turn it off.
