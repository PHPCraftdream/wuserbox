package trace

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestDisabledTraceWritesNothing(t *testing.T) {
	var out bytes.Buffer
	logger := New(nil)
	logger.Event("bootstrap")
	logger.Phase("prepare")(nil)
	if out.Len() != 0 {
		t.Fatalf("disabled trace wrote %q", out.String())
	}
}

func TestTraceRecordsPhasesAndErrors(t *testing.T) {
	var out bytes.Buffer
	logger := New(&out)
	done := logger.Phase("profile", Field{Key: "root", Value: `C:\profile`})
	done(errors.New("profile failed"))
	text := out.String()
	if strings.Count(text, `"phase":"profile"`) != 2 {
		t.Fatalf("trace has no start/end pair: %s", text)
	}
	if !strings.Contains(text, `"status":"error"`) || !strings.Contains(text, `"error":"profile failed"`) {
		t.Fatalf("trace did not preserve phase error: %s", text)
	}
	if !strings.Contains(text, `"duration_ms"`) || !strings.Contains(text, `"root":"C:\\profile"`) {
		t.Fatalf("trace did not preserve timing and safe metadata: %s", text)
	}
}

func TestFromEnvUsesExplicitTraceFile(t *testing.T) {
	path := t.TempDir() + `\trace.jsonl`
	t.Setenv(Env, "1")
	t.Setenv(EnvFile, path)
	logger := FromEnv()
	defer func() { _ = logger.Close() }()
	logger.Event("prepare")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"phase":"prepare"`) {
		t.Fatalf("trace file has no event: %s", data)
	}
}

func TestEveryRecordNamesItsProcessAndRun(t *testing.T) {
	var out bytes.Buffer
	logger := New(&out)
	logger.Event("bootstrap")
	done := logger.Phase("prepare")
	done(nil)
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected three records, got %d: %s", len(lines), out.String())
	}
	seen := map[string]string{}
	for _, line := range lines {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("unparseable record %q: %v", line, err)
		}
		pid, _ := record["pid"].(float64)
		if int(pid) != os.Getpid() {
			t.Fatalf("record does not name this process's pid: %s", line)
		}
		run, _ := record["run"].(string)
		if run == "" {
			t.Fatalf("record carries no run identifier: %s", line)
		}
		seen[run] = run
	}
	if len(seen) != 1 {
		t.Fatalf("records of one logger disagree about the run: %s", out.String())
	}
}
