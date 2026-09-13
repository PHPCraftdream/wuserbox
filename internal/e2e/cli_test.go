package e2e

import (
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/PHPCraftdream/wuserbox/internal/policy/config"
	"github.com/PHPCraftdream/wuserbox/internal/policy/state"
	"github.com/PHPCraftdream/wuserbox/internal/sandbox"
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
		out, err := exec.Command("go", "build", "-o", buildOnce.path, "github.com/PHPCraftdream/wuserbox/cmd/wuserbox").CombinedOutput()
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
	cmd := exec.Command(binary(t), args...)
	cmd.Dir = cwd
	cmd.Env = append(os.Environ(), config.EnvPath+"="+filepath.Join(t.TempDir(), "wuserbox.ktav"))
	out, err := cmd.CombinedOutput()
	code := 0
	if exit, ok := err.(*exec.ExitError); ok {
		code = exit.ExitCode()
	} else if err != nil {
		t.Fatalf("running %v: %v", args, err)
	}
	return string(out), code
}

func TestCLINameMatchesTheLibrary(t *testing.T) {
	dir := t.TempDir()
	out, code := cli(t, dir, "name")
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
	out, code := cli(t, t.TempDir(), "run")
	if code == 0 || !strings.Contains(out, "no command given") {
		t.Errorf("exit %d, output %q", code, out)
	}
}

func TestCLIPathReportsUnknownGroup(t *testing.T) {
	out, code := cli(t, t.TempDir(), "path", "wub-does-not-exist-00000000")
	if code == 0 || !strings.Contains(out, "does not exist") {
		t.Errorf("exit %d, output %q", code, out)
	}
}

func TestCLIListSucceeds(t *testing.T) {
	if _, code := cli(t, t.TempDir(), "list"); code != 0 {
		t.Errorf("exit code %d", code)
	}
}

func TestCLIAddDirRecordsTheRule(t *testing.T) {
	project := t.TempDir()
	tools := t.TempDir()
	cfgPath := filepath.Join(t.TempDir(), "rules.ktav")

	cmd := exec.Command(binary(t), "add-dir", tools)
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
	cmd = exec.Command(binary(t), "remove-dir", tools)
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
		cmd := exec.Command(binary(t), args...)
		cmd.Dir = project
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		code := 0
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		} else if err != nil {
			t.Fatalf("running %v: %v", args, err)
		}
		return string(out), code
	}

	name, norm, err := sandbox.Name(project)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { run("rm") })

	if out, code := run("init", "--no-ai"); code != 0 {
		t.Fatalf("init failed: %s", out)
	}
	if out, code := run("path", name); code != 0 || !strings.Contains(out, norm) {
		t.Errorf("path lookup returned %q (exit %d)", out, code)
	}
	if out, code := run("list"); code != 0 || !strings.Contains(out, name) {
		t.Errorf("list did not mention the new sandbox: %q", out)
	}

	inside := filepath.Join(project, "written.txt")
	if out, code := run("run", "--no-ai", "--", "cmd.exe", "/c", "echo ok>"+inside); code != 0 {
		t.Errorf("writing inside the project failed: %s", out)
	}
	if _, err := os.Stat(inside); err != nil {
		t.Errorf("file was not created: %v", err)
	}
	blocked := filepath.Join(outside, "escaped.txt")
	if _, code := run("run", "--no-ai", "--", "cmd.exe", "/c", "echo ok>"+blocked); code == 0 {
		t.Error("writing outside the sandbox succeeded")
		os.Remove(blocked)
	}

	// A directory added to the config becomes writable on the next run.
	if out, code := run("add-dir", extra); code != 0 {
		t.Fatalf("add-dir failed: %s", out)
	}
	allowed := filepath.Join(extra, "written.txt")
	if out, code := run("run", "--no-ai", "--", "cmd.exe", "/c", "echo ok>"+allowed); code != 0 {
		t.Errorf("writing to the added directory failed: %s", out)
	}

	if out, code := run("rm"); code != 0 {
		t.Fatalf("rm failed: %s", out)
	}
	if s, err := state.Load(name); err != nil || s != nil {
		t.Errorf("state survived removal: %+v (%v)", s, err)
	}
	if _, code := run("path", name); code == 0 {
		t.Error("the group survived removal")
	}
}
