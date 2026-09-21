// Package trace records opt-in timings for the work behind a sandbox start.
package trace

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// Env enables bootstrap tracing. Any non-empty value enables it. When
// WUSERBOX_TRACE_FILE is absent, a per-process file is created in %TEMP% and
// its name is put into the environment so an elevated child can append to it.
const Env = "WUSERBOX_TRACE"

// EnvFile selects the trace file. The value "stderr" writes directly to the
// process's standard error; a path is opened in append mode.
const EnvFile = "WUSERBOX_TRACE_FILE"

// Field is a deliberately small allow-list for trace data. Callers should add
// only phase metadata needed to explain a delay; secrets never belong here.
type Field struct {
	Key   string
	Value string
}

// Logger writes newline-delimited JSON with elapsed and phase durations.
// A disabled logger is cheap and safe to call from all normal paths.
//
// Every record names its writer: the process's pid plus a per-process run
// identifier. The run identifier is per-process rather than per-run because
// handing one shared identifier across the account boundary would need a
// transport into the sandbox, which is deliberately out of scope; the fields
// are ready for the day a shared identifier does cross.
type Logger struct {
	mu       sync.Mutex
	start    time.Time
	run      string
	output   io.Writer
	file     *os.File
	path     string
	disabled bool
}

var thisPID = os.Getpid()

// newRunID names the logical run every record of one logger belongs to: this
// process's own pid plus the nanosecond reading at the logger's birth. Every
// logger a process builds gets its own, so a trace file fed by more than one
// process -- the caller here, a stub or an elevated child appending to the
// same file -- can have its lines told apart by who wrote them without any
// of the writers knowing about each other. It is a diagnostic aid, not a
// security token, and it carries no secret: a pid and a clock reading are
// exactly what a reader of the file already knows it is looking at.
func newRunID() string {
	return strconv.Itoa(thisPID) + "-" + strconv.FormatInt(time.Now().UnixNano(), 10)
}

// New returns a logger writing to output. A nil output disables it.
func New(output io.Writer) *Logger {
	if output == nil {
		return &Logger{disabled: true}
	}
	return &Logger{start: time.Now(), run: newRunID(), output: output}
}

// FromEnv creates the process logger. It never returns an error: tracing must
// not change whether a sandbox can start. An unavailable file simply disables
// tracing and leaves the ordinary command unchanged.
func FromEnv() *Logger {
	if os.Getenv(Env) == "" && os.Getenv(EnvFile) == "" {
		return New(nil)
	}
	name := os.Getenv(EnvFile)
	if name == "" {
		name = filepath.Join(os.TempDir(), "wuserbox-bootstrap-"+strconv.FormatInt(time.Now().UnixNano(), 10)+".jsonl")
		// ShellExecuteEx does not accept an environment block. Keeping the
		// generated name in the environment lets the elevated child append to
		// the same file on Windows installations where the environment is
		// inherited through consent.
		_ = os.Setenv(EnvFile, name)
	}
	if name == "stderr" {
		return &Logger{start: time.Now(), run: newRunID(), output: os.Stderr, path: name}
	}
	file, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return New(nil)
	}
	return &Logger{start: time.Now(), run: newRunID(), output: file, file: file, path: name}
}

var (
	currentOnce sync.Once
	current     *Logger
)

// Current returns the process-wide opt-in logger.
func Current() *Logger {
	currentOnce.Do(func() { current = FromEnv() })
	return current
}

// Path reports the persisted trace path, if one is in use.
func (l *Logger) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}

// Close releases a trace file. The process-wide logger is normally closed by
// the operating system; tests and embedding callers may close it explicitly.
func (l *Logger) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	return l.file.Close()
}

// Event records an instantaneous event.
func (l *Logger) Event(name string, fields ...Field) {
	l.emit(name, "event", 0, nil, fields...)
}

// Phase records start and completion for one operation. The returned function
// must be called with the operation's error, if any.
func (l *Logger) Phase(name string, fields ...Field) func(error) {
	if l == nil || l.disabled {
		return func(error) {}
	}
	started := time.Now()
	l.emit(name, "start", 0, nil, fields...)
	return func(err error) {
		status := "ok"
		if err != nil {
			status = "error"
		}
		duration := time.Since(started)
		if duration < time.Millisecond {
			duration = time.Millisecond
		}
		l.emit(name, status, duration, err, fields...)
	}
}

func (l *Logger) emit(name, status string, duration time.Duration, phaseErr error, fields ...Field) {
	if l == nil || l.disabled {
		return
	}
	// pid and run name the writer on every record so a trace file fed by
	// more than one process stays attributable; phase-specific metadata
	// still travels the usual way, through Field.
	record := map[string]any{
		"elapsed_ms": time.Since(l.start).Milliseconds(),
		"phase":      name,
		"status":     status,
		"pid":        thisPID,
		"run":        l.run,
	}
	if duration > 0 {
		record["duration_ms"] = duration.Milliseconds()
	}
	if phaseErr != nil {
		record["error"] = phaseErr.Error()
	}
	for _, field := range fields {
		if field.Key != "" && field.Value != "" {
			record[field.Key] = field.Value
		}
	}
	data, err := json.Marshal(record)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = fmt.Fprintf(l.output, "%s\n", data)
}
