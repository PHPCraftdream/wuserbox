package trace

import (
	"bytes"
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
