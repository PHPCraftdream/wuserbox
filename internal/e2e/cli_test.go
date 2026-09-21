package e2e

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox"
	"github.com/PHPCraftdream/wuserbox/internal/win/quietexec"
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
)

var buildOnce struct {
	sync.Once
	path string
	err  error
}

// binary builds the command once per test run and returns its path.
func binary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "wuserbox-build")
		if err != nil {
			buildOnce.err = err
			return
		}
		buildOnce.path = filepath.Join(dir, "wuserbox.exe")
		out, err := quietexec.Command("go", "build", "-o", buildOnce.path, "github.com/PHPCraftdream/wuserbox/cmd/wuserbox").CombinedOutput()
		if err != nil {
			buildOnce.err = err
			t.Logf("build output: %s", out)
		}
	})
	if buildOnce.err != nil {
		t.Fatalf("building wuserbox: %v", buildOnce.err)
	}
	return buildOnce.path
}

// cli runs the command with a private config file and returns output plus exit code.
func cli(t *testing.T, cwd string, args ...string) (string, int) {
	t.Helper()
	cmd := quietexec.Command(binary(t), args...)
	cmd.Dir = cwd
	cmd.Env = append(os.Environ(), config.EnvPath+"="+filepath.Join(t.TempDir(), "wuserbox.ktav"))
	out, err := cmd.CombinedOutput()
	code := 0
	var failed *exec.ExitError
	if errors.As(err, &failed) {
		code = failed.ExitCode()
	} else if err != nil {
		t.Fatalf("running %v: %v", args, err)
	}
	return string(out), code
}

func TestCLINameMatchesTheLibrary(t *testing.T) {
	dir := t.TempDir()
	out, code := cli(t, dir, "--name")
	if code != 0 {
		t.Fatalf("exit code %d: %s", code, out)
	}
	want, _, err := sandbox.Name(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, want+"\t") {
		t.Errorf("got %q, want it to start with %q", out, want)
	}
}

func TestCLIRejectsUnknownCommands(t *testing.T) {
	out, code := cli(t, t.TempDir(), "frobnicate")
	if code == 0 {
		t.Error("an unknown command should fail")
	}
	if !strings.Contains(out, "unknown command") {
		t.Errorf("unhelpful message: %q", out)
	}
}

func TestCLIRunNeedsACommand(t *testing.T) {
	out, code := cli(t, t.TempDir(), "--run")
	if code == 0 || !strings.Contains(out, "no command given") {
		t.Errorf("exit %d, output %q", code, out)
	}
}

func TestCLIPathReportsUnknownGroup(t *testing.T) {
	out, code := cli(t, t.TempDir(), "--path", "wub-does-not-exist-00000000")
	if code == 0 || !strings.Contains(out, "does not exist") {
		t.Errorf("exit %d, output %q", code, out)
	}
}

func TestCLIListSucceeds(t *testing.T) {
	if _, code := cli(t, t.TempDir(), "--list"); code != 0 {
		t.Errorf("exit code %d", code)
	}
}

func TestCLIAddDirRecordsTheRule(t *testing.T) {
	project := t.TempDir()
	tools := t.TempDir()
	cfgPath := filepath.Join(t.TempDir(), "rules.ktav")

	cmd := quietexec.Command(binary(t), "--add-dir", tools)
	cmd.Dir = project
	cmd.Env = append(os.Environ(), config.EnvPath+"="+cfgPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("add-dir: %v: %s", err, out)
	}
	t.Setenv(config.EnvPath, cfgPath)
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	_, norm, err := sandbox.Name(project)
	if err != nil {
		t.Fatal(err)
	}
	grants := cfg.GrantsFor(norm)
	if len(grants) != 1 || !config.SamePath(grants[0].Path, tools) {
		t.Fatalf("config holds %+v", cfg.Projects)
	}

	// Removing it again leaves the project rule empty.
	cmd = quietexec.Command(binary(t), "--remove-dir", tools)
	cmd.Dir = project
	cmd.Env = append(os.Environ(), config.EnvPath+"="+cfgPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("remove-dir: %v: %s", err, out)
	}
	cfg, err = config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.GrantsFor(norm)) != 0 {
		t.Errorf("rule survived removal: %+v", cfg.Projects)
	}
}

// TestCLIFullLifecycle exercises the real path: a local group, ACLs, a
// sandboxed process and cleanup. Creating a group needs administrator rights,
// so run this from an elevated shell:
//
//	go test ./test/e2e -run TestCLIFullLifecycle -v
func TestCLIFullLifecycle(t *testing.T) {
	if !token.IsAdmin() {
		t.Skip("needs an elevated shell: creating a local group requires administrator rights")
	}
	project := t.TempDir()
	extra := t.TempDir()
	outside := t.TempDir()
	cfgPath := filepath.Join(t.TempDir(), "rules.ktav")
	env := append(os.Environ(), config.EnvPath+"="+cfgPath)

	run := func(args ...string) (string, int) {
		cmd := quietexec.Command(binary(t), args...)
		cmd.Dir = project
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		code := 0
		var failed *exec.ExitError
		if errors.As(err, &failed) {
			code = failed.ExitCode()
		} else if err != nil {
			t.Fatalf("running %v: %v", args, err)
		}
		return string(out), code
	}

	name, norm, err := sandbox.Name(project)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { run("--rm") })

	if out, code := run("--init", "--no-ai"); code != 0 {
		t.Fatalf("init failed: %s", out)
	}
	if out, code := run("--path", name); code != 0 || !strings.Contains(out, norm) {
		t.Errorf("path lookup returned %q (exit %d)", out, code)
	}
	if out, code := run("--list"); code != 0 || !strings.Contains(out, name) {
		t.Errorf("list did not mention the new sandbox: %q", out)
	}

	// The sandbox was built with --no-ai above, and a run takes it as it
	// stands: the flags that say what a sandbox is belong to init.
	inside := filepath.Join(project, "written.txt")
	if out, code := run("cmd.exe", "/c", "echo ok>"+inside); code != 0 {
		t.Errorf("writing inside the project failed: %s", out)
	}
	if _, err := os.Stat(inside); err != nil {
		t.Errorf("file was not created: %v", err)
	}
	blocked := filepath.Join(outside, "escaped.txt")
	if _, code := run("cmd.exe", "/c", "echo ok>"+blocked); code == 0 {
		t.Error("writing outside the sandbox succeeded")
		os.Remove(blocked)
	}

	// A directory added to the config becomes writable on the next run.
	if out, code := run("--add-dir", extra); code != 0 {
		t.Fatalf("add-dir failed: %s", out)
	}
	allowed := filepath.Join(extra, "written.txt")
	if out, code := run("cmd.exe", "/c", "echo ok>"+allowed); code != 0 {
		t.Errorf("writing to the added directory failed: %s", out)
	}

	// And the flags that configure are refused on a run, with the command to
	// use instead.
	if out, code := run("--no-ai", "cmd.exe", "/c", "echo hi"); code == 0 ||
		!strings.Contains(out, "init --no-ai") {
		t.Errorf("configuring on a run was not refused: %q (exit %d)", out, code)
	}

	if out, code := run("--rm"); code != 0 {
		t.Fatalf("rm failed: %s", out)
	}
	if s, err := state.Load(name); err != nil || s != nil {
		t.Errorf("state survived removal: %+v (%v)", s, err)
	}
	if _, code := run("--path", name); code == 0 {
		t.Error("the group survived removal")
	}
}

// TestCLIReportsAFailureAsJSONWhenAsked covers the whole path, because the
// shape of a failure is decided in main rather than in the command that
// failed. A script calling wuserbox with --json has to meet one shape whether
// the command worked or not.
func TestCLIReportsAFailureAsJSONWhenAsked(t *testing.T) {
	command := binary(t)
	output, err := quietexec.Command(command, "nonsense", "--json").CombinedOutput()
	if err == nil {
		t.Fatal("an unknown command should fail")
	}
	var reported struct {
		Error  string `json:"error"`
		Code   int    `json:"code"`
		Status string `json:"status"`
	}
	if jsonErr := json.Unmarshal(output, &reported); jsonErr != nil {
		t.Fatalf("the failure is not JSON: %v (%q)", jsonErr, output)
	}
	if reported.Code != 2 || reported.Status != "usage" {
		t.Errorf("the failure came back as %d/%q", reported.Code, reported.Status)
	}
	if !strings.Contains(reported.Error, "nonsense") {
		t.Errorf("the message does not say what was wrong: %q", reported.Error)
	}

	// Without the flag it stays a line of prose, as it always was.
	plain, err := quietexec.Command(command, "nonsense").CombinedOutput()
	if err == nil {
		t.Fatal("an unknown command should fail")
	}
	if !strings.HasPrefix(string(plain), "wuserbox: ") {
		t.Errorf("the plain failure changed shape: %q", plain)
	}
}

// TestCLIKeepsJSONWhenAFlagIsWrong is the regression guard for a parser that
// reported for itself. flag wrote its complaint and the whole usage text to
// the error stream before the failure reached the one place that decides its
// shape, so a command called with --json answered with prose followed by a
// JSON document.
func TestCLIKeepsJSONWhenAFlagIsWrong(t *testing.T) {
	command := binary(t)
	for _, args := range [][]string{
		{"--check", "--json", "--nonsense"},
		{"--explain", "--json", "--nonsense"},
		{"--list", "--json", "--nonsense"},
		{"--rm", "--json", "--nonsense"},
		{"--config", "show", "--json", "--nonsense"},
		{"--grant", `C:\tools`, "--json", "--nonsense"},
		{"--run", "--json", "--nonsense", "--", "cmd.exe"},
	} {
		output, err := quietexec.Command(command, args...).CombinedOutput()
		if err == nil {
			t.Errorf("%v: an unknown flag should fail", args)
			continue
		}
		var reported struct {
			Error  string `json:"error"`
			Code   int    `json:"code"`
			Status string `json:"status"`
		}
		if jsonErr := json.Unmarshal(output, &reported); jsonErr != nil {
			t.Errorf("%v: the failure is not JSON: %v (%q)", args, jsonErr, output)
			continue
		}
		if reported.Code != 2 || !strings.Contains(reported.Error, "nonsense") {
			t.Errorf("%v: came back as %d %q", args, reported.Code, reported.Error)
		}
	}
}

// TestCLIKeepsJSONWhileWorking is the regression guard for the notes a command
// writes as it goes. Those went to the error stream as prose even under
// --json, so a run that had to build a sandbox first wrote "creating
// sandbox..." before the JSON failure and the stream did not parse.
func TestCLIKeepsJSONWhileWorking(t *testing.T) {
	command := binary(t)
	project := t.TempDir()
	run := quietexec.Command(command, "--run", "--dir", project, "--json", "--non-interactive",
		"--", "cmd.exe", "/c", "echo hello")
	var out bytes.Buffer
	run.Stderr = &out
	run.Stdout = io.Discard
	if err := run.Run(); err == nil {
		t.Skip("this shell can create a sandbox without asking, so nothing is reported here")
	}
	var reported struct {
		Error  string `json:"error"`
		Code   int    `json:"code"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(out.Bytes(), &reported); err != nil {
		t.Fatalf("the error stream is not JSON: %v (%q)", err, out.String())
	}
	if reported.Status != "needs-elevation" {
		t.Errorf("the failure came back as %d/%q", reported.Code, reported.Status)
	}
}

// TestCLIRunsAProgramWithoutBeingTold is the shape the command now has:
// anything that is not a wuserbox command is a program to run in the sandbox
// of the current directory, with no `run` and no separator.
func TestCLIRunsAProgramWithoutBeingTold(t *testing.T) {
	command := binary(t)
	project := t.TempDir()
	out, err := quietexec.Command(command, "--dir", project, "--dry-run", "--quiet",
		"cmd.exe", "/c", "echo", "hello").CombinedOutput()
	if err != nil {
		t.Fatalf("a plain run failed: %v (%s)", err, out)
	}
	if !strings.Contains(string(out), "cmd.exe") {
		t.Errorf("the program was not the one asked for: %q", out)
	}

	// And a word that is neither says which it is not.
	mistyped, err := quietexec.Command(command, "--dir", project, "frobnicate").CombinedOutput()
	if err == nil {
		t.Fatal("a word that is neither a command nor a program should fail")
	}
	if !strings.Contains(string(mistyped), "unknown command") {
		t.Errorf("unhelpful message: %q", mistyped)
	}
}

// TestCLIRefusesToConfigureOnARun covers the same line from outside: the flags
// that say what a sandbox is are not accepted while starting a program.
func TestCLIRefusesToConfigureOnARun(t *testing.T) {
	command := binary(t)
	out, err := quietexec.Command(command, "--dir", t.TempDir(), "--rw", t.TempDir(),
		"cmd.exe", "/c", "echo", "hello").CombinedOutput()
	if err == nil {
		t.Fatal("configuring on a run should fail")
	}
	if !strings.Contains(string(out), "add-dir") {
		t.Errorf("the message does not name the command to use instead: %q", out)
	}
}
