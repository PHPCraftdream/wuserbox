// The close test for the launch-phase split, review P3-2: the umbrella
// phase over a sandboxed run must read as the command's whole life, not as
// the cost of starting it, and the phases underneath must separate the two,
// so a slow program cannot be mistaken for a slow launch.
//
// trace.Current() is a sync.Once singleton, so the run happens in a process
// of its own, the way this package's other subprocess tests re-exec this
// binary: the driver carries WUSERBOX_TRACE and WUSERBOX_TRACE_FILE in its
// environment, calls Run there, and appends every record to the trace file
// this test reads -- once mid-run, while the child is verifiably gated, and
// once after the driver is gone.
//
// The gated child is this binary again, a copy inside the granted directory
// -- the lesson internal/e2e's stubBinary records -- because a restricted
// token cannot start anything from the caller's own temporary home. It
// writes the ready marker the parent's mid-run read waits on.

package exec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PHPCraftdream/wuserbox/internal/base/paths"
	"github.com/PHPCraftdream/wuserbox/internal/base/trace"
	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
)

const (
	traceDriverEnv    = "WUSERBOX_EXEC_TRACE_DRIVER"
	traceDriverDir    = "WUSERBOX_EXEC_TRACE_DIR"
	traceDriverReady  = "WUSERBOX_EXEC_TRACE_READY"
	traceDriverGate   = "WUSERBOX_EXEC_TRACE_GATE"
	traceDriverResult = "WUSERBOX_EXEC_TRACE_RESULT"

	// A SID that belongs to nothing on the machine, the trick internal/e2e's
	// helper uses: access control entries accept it and it grants nothing by
	// itself, so the only writes the gated child can do are the ones this
	// test granted.
	traceDriverSID = "S-1-5-21-1111111111-2222222222-3333333333-737373"

	// createNoWindow is CREATE_NO_WINDOW, spelled out the way job.go and
	// quietexec.go spell it: syscall does not carry the constant.
	createNoWindow = 0x08000000

	// gateChildFlag re-execs this binary as the gated child the driver's run
	// waits out: it says it is in place, then sits behind the gate file
	// until the test opens it.
	gateChildFlag = "-wuserbox-exec-gate"
)

// runTraceDriver is the body this test binary runs as, in a process of its
// own: build the synthetic sandbox, grant it, and send the gated child
// through Run with tracing on, so every record lands in the trace file the
// parent test reads. Failures go into the result file, where the parent can
// quote them, and come back as the exit codes runProbe uses.
func runTraceDriver() int {
	dir := os.Getenv(traceDriverDir)
	ready := os.Getenv(traceDriverReady)
	gate := os.Getenv(traceDriverGate)
	result := os.Getenv(traceDriverResult)
	report := func(format string, args ...any) {
		_ = os.WriteFile(result, []byte(fmt.Sprintf(format, args...)), 0o600)
	}
	if dir == "" || ready == "" || gate == "" || result == "" {
		report("the driver is missing one of its four environment variables")
		return 90
	}
	st := &state.State{Group: "wub-trace-test", SID: traceDriverSID, Dir: dir, Temp: dir}
	if err := st.Add(dir, grant.RW); err != nil {
		report("grant %s: %v", dir, err)
		return 90
	}
	// Not a detail: the restricted token cannot read this process's own
	// temporary home, so the child must be a copy inside the granted
	// directory, measured in e2e as "access is denied" before anything else
	// could be wrong. The copy happens after st.Add, so the grant's
	// inheritable ACE is already on dir and the child file inherits it --
	// the restricted token can read and start it.
	exe, err := os.Executable()
	if err != nil {
		report("finding this binary: %v", err)
		return 90
	}
	from, err := os.ReadFile(exe)
	if err != nil {
		report("reading this binary: %v", err)
		return 90
	}
	child := filepath.Join(dir, "gate-child.exe")
	if err := os.WriteFile(child, from, 0o755); err != nil {
		report("placing the gated child at %s: %v", child, err)
		return 90
	}
	line := syscall.EscapeArg(child) + " " + gateChildFlag + " " + syscall.EscapeArg(ready) + " " + syscall.EscapeArg(gate)
	code, err := Run(st, line)
	if err != nil {
		report("run %s: %v", line, err)
		return 91
	}
	report("code=%d", code)
	return 0
}

// runGateChild is the program the gated child runs: write the ready marker
// -- the one fact the parent test's mid-run read rests on -- then wait for
// the gate file, bounded, so a lost gate cannot leave a process behind. It
// runs under the restricted token, so it touches nothing but the two files
// inside the directory the driver granted: no console work, no registry,
// nothing a restricted list would refuse.
func runGateChild(ready, gate string) int {
	if err := os.WriteFile(ready, []byte("ready"), 0o600); err != nil {
		return 90
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		if _, err := os.Stat(gate); err == nil {
			return 0
		}
		if !time.Now().Before(deadline) {
			return 91
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// readTraceRecords reads a trace file back as records. With
// tolerateBrokenTail, one unparseable last line is skipped silently: the
// driver appends to the file while the test reads it, and a record caught
// mid-write is not a finding. Any other parse failure is.
func readTraceRecords(t *testing.T, path string, tolerateBrokenTail bool) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the trace at %s: %v", path, err)
	}
	var lines []string
	for _, line := range strings.Split(string(raw), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	records := make([]map[string]any, 0, len(lines))
	for i, line := range lines {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			if tolerateBrokenTail && i == len(lines)-1 {
				break
			}
			t.Fatalf("trace line %d of %s does not parse (%v): %s", i+1, path, err, line)
		}
		records = append(records, record)
	}
	return records
}

// findRecord returns the index of the first record naming this phase and
// status, or -1 when there is none.
func findRecord(records []map[string]any, phase, status string) int {
	for i, record := range records {
		if record["phase"] == phase && record["status"] == status {
			return i
		}
	}
	return -1
}

// countRecords counts every record naming this phase and status, across the
// whole file.
func countRecords(records []map[string]any, phase, status string) int {
	n := 0
	for _, record := range records {
		if record["phase"] == phase && record["status"] == status {
			n++
		}
	}
	return n
}

// traceDump renders records back as JSON lines, for quoting in a failure.
func traceDump(records []map[string]any) string {
	lines := make([]string, 0, len(records))
	for _, record := range records {
		line, err := json.Marshal(record)
		if err != nil {
			lines = append(lines, fmt.Sprintf("%v", record))
			continue
		}
		lines = append(lines, string(line))
	}
	return strings.Join(lines, "\n")
}

// waitForFile polls for a file until it is there or the deadline passes.
// internal/win/proc keeps a copy for its own tests, test-file-local there,
// so this file keeps its own rather than reaching across packages.
func waitForFile(path string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestTheLaunchPhasesSeparateStartingFromWaiting pins the split in two
// reads of one trace. First, while the gated child is verifiably running:
// launch is over -- child_create has closed -- and nothing has torn down,
// because the run is still waiting the child out. Then, after the driver
// has ended: every phase of the restricted path exactly once, in the order
// the code emits them, every record the driver's own, under one run
// identifier. The child sits behind the gate until this test opens it, so
// nothing in either read depends on how fast the machine starts a program.
func TestTheLaunchPhasesSeparateStartingFromWaiting(t *testing.T) {
	dir, err := paths.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tracePath := filepath.Join(dir, "trace.jsonl")
	ready := filepath.Join(dir, "child.ready")
	gate := filepath.Join(dir, "child.go")
	result := filepath.Join(dir, "driver.result")

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(),
		traceDriverEnv+"=1",
		traceDriverDir+"="+dir,
		traceDriverReady+"="+ready,
		traceDriverGate+"="+gate,
		traceDriverResult+"="+result,
		trace.Env+"=1",
		trace.EnvFile+"="+tracePath,
	)
	// The window the driver would put on the screen is not hidden; it is
	// never created -- the lesson internal/win/proc's tests recorded.
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	// Killing something already gone is harmless, and a t.Fatal between here
	// and the wait would otherwise leave the driver behind -- the lesson
	// internal/win/proc's driverCommand records about drivers found still
	// running hours later.
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the trace driver: %v", err)
	}

	// Phase A: the launch is done while the child is gated. The ready
	// marker is the child's own write from inside the sandbox, so once it
	// is there the child has verifiably been resumed and is running behind
	// the gate -- and no record of waiting or teardown may exist yet.
	if !waitForFile(ready, 90*time.Second) {
		t.Fatalf("the gated child never wrote its ready marker at %s; driver stderr:\n%s", ready, stderr.String())
	}
	records := readTraceRecords(t, tracePath, true)
	if findRecord(records, "child_create", "ok") < 0 {
		t.Fatalf("no child_create ok in the trace while the child sat gated -- the launch had not closed before the child was released; records:\n%s", traceDump(records))
	}
	for _, phase := range []string{"child_wait", "job_close", "command_lifetime"} {
		if findRecord(records, phase, "ok") >= 0 {
			t.Errorf("%s ok in the trace while the child was still gated -- teardown began before the run had anything to wait out; records:\n%s", phase, traceDump(records))
		}
	}

	// Phase B: the release. Writing the gate ends the child's poll, the run
	// winds down, and the driver reports its exit code.
	if err := os.WriteFile(gate, []byte("go"), 0o600); err != nil {
		t.Fatalf("writing the gate at %s: %v", gate, err)
	}
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	select {
	case waitErr := <-waited:
		if waitErr != nil {
			t.Fatalf("waiting the trace driver out failed: %v; driver stderr:\n%s", waitErr, stderr.String())
		}
	case <-time.After(90 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("the trace driver was still running 90s after the gate was written; driver stderr:\n%s", stderr.String())
	}
	raw, err := os.ReadFile(result)
	if err != nil {
		t.Fatalf("reading the driver's result file at %s: %v; driver stderr:\n%s", result, err, stderr.String())
	}
	if got := strings.TrimSpace(string(raw)); got != "code=0" {
		t.Fatalf("the driver reported %q, want \"code=0\"; driver stderr:\n%s", got, stderr.String())
	}
	records = readTraceRecords(t, tracePath, false)

	for _, want := range [][2]string{
		{"command_lifetime", "start"},
		{"command_lifetime", "ok"},
		{"child_create", "ok"},
		{"child_resume", "event"},
		{"child_wait", "start"},
		{"child_wait", "ok"},
		{"job_close", "ok"},
	} {
		if n := countRecords(records, want[0], want[1]); n != 1 {
			t.Errorf("%s/%s appears %d times in the final trace, want exactly once; records:\n%s",
				want[0], want[1], n, traceDump(records))
		}
	}
	for i, record := range records {
		if status, _ := record["status"].(string); status == "error" {
			t.Errorf("record %d carries status error, want none anywhere: %v", i+1, record)
		}
		if phase, _ := record["phase"].(string); strings.HasPrefix(phase, "stub_") {
			t.Errorf("record %d has phase %q -- this run took the restricted path, where no stub_ phase exists; records:\n%s",
				i+1, phase, traceDump(records))
		}
	}
	order := [][2]string{
		{"command_lifetime", "start"},
		{"child_create", "ok"},
		{"child_resume", "event"},
		{"child_wait", "start"},
		{"child_wait", "ok"},
		{"job_close", "ok"},
		{"command_lifetime", "ok"},
	}
	last := -1
	for _, want := range order {
		at := findRecord(records, want[0], want[1])
		if at <= last {
			t.Errorf("%s/%s first appears at record %d, want strictly after record %d; records:\n%s",
				want[0], want[1], at, last, traceDump(records))
			continue
		}
		last = at
	}
	pid := float64(cmd.Process.Pid)
	runs := map[string]bool{}
	for i, record := range records {
		if got, _ := record["pid"].(float64); got != pid {
			t.Errorf("record %d names pid %v, want the driver's %d; records:\n%s", i+1, record["pid"], cmd.Process.Pid, traceDump(records))
		}
		if run, _ := record["run"].(string); run == "" {
			t.Errorf("record %d carries no run identifier: %v", i+1, record)
		} else {
			runs[run] = true
		}
	}
	if len(runs) != 1 {
		t.Errorf("the trace names %d distinct run identifiers (%v), want one -- every record came from the one driver process; records:\n%s",
			len(runs), runs, traceDump(records))
	}
}
