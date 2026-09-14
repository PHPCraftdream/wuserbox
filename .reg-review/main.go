package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	osexec "os/exec"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/PHPCraftdream/wuserbox/internal/policy/grant"
	"github.com/PHPCraftdream/wuserbox/internal/win/acl"
	"github.com/PHPCraftdream/wuserbox/internal/win/proc"
	"github.com/PHPCraftdream/wuserbox/internal/win/sid"
	"github.com/PHPCraftdream/wuserbox/internal/win/token"
	"golang.org/x/sys/windows"
)

const a = "S-1-5-21-1111111111-2222222222-3333333333-898101"
const b = "S-1-5-21-1111111111-2222222222-3333333333-898102"

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "child" {
		fmt.Printf("READY %s: ", os.Args[2])
		var err error
		switch os.Args[2] {
		case "read":
			_, err = os.ReadFile(os.Args[3])
		case "write":
			err = os.WriteFile(os.Args[3], []byte("changed"), 0o600)
		case "rename":
			err = os.Rename(os.Args[3], os.Args[3]+".moved")
		case "delete":
			err = os.Remove(os.Args[3])
		case "escalate":
			err = setSD(filepath.Dir(os.Args[3]), "D:P(A;OICI;FA;;;WD)")
			fmt.Printf("set-DACL=%v; ", err)
			if err == nil {
				err = os.Remove(os.Args[3])
			}
		}
		fmt.Printf("error=%v\n", err)
		if err != nil {
			os.Exit(41)
		}
		return
	}
	root, err := os.MkdirTemp("", "wuserbox-regression-review-")
	must(err)
	defer func() { fmt.Printf("cleanup=%v\n", os.RemoveAll(root)) }()
	if len(os.Args) > 1 && os.Args[1] != "probe" {
		tests(root, os.Args[1])
		return
	}
	user, err := sid.CurrentUser()
	must(err)
	base := "D:P(A;OICI;FA;;;" + user + ")(A;OICI;FA;;;SY)(A;OICI;FRFX;;;BU)"
	must(setSD(root, base))
	dir := func(name string) string { p := filepath.Join(root, name); must(os.Mkdir(p, 0o700)); return p }
	file := func(d string) string {
		p := filepath.Join(d, "precious.txt")
		must(os.WriteFile(p, []byte("data"), 0o600))
		return p
	}
	project := dir("project-a")
	must(grant.Apply(a, project, grant.RW))
	try("own-project", a, project, file(project))

	parent := dir("parent-users-modify")
	must(acl.Set(parent, sid.Users, []acl.ACE{{Access: acl.AccessModify, Inheritance: 3}}))
	child := filepath.Join(parent, "project-b")
	must(os.Mkdir(child, 0o700))
	path := file(child)
	must(grant.Apply(b, child, grant.RW))
	try("inherited-root-fixed", a, project, path)
	try("owner-of-fixed-root", b, project, path)

	other := dir("explicit-descendant")
	nested := filepath.Join(other, "nested")
	must(os.Mkdir(nested, 0o700))
	must(acl.Set(nested, sid.Users, []acl.ACE{{Access: acl.AccessModify, Inheritance: 3}}))
	path = file(nested)
	must(grant.Apply(b, other, grant.RW))
	try("unprotected-descendant-still-writable", a, project, path)

	other = dir("crowd-write-dacl")
	must(acl.Set(other, sid.Everyone, []acl.ACE{{Access: 0x40000, Inheritance: 3}}))
	path = file(other)
	must(grant.Apply(b, other, grant.RW))
	show("write-dacl-after-grant", other)
	fmt.Printf("EveryoneWritable=%v UsersWritable=%v\n", acl.EveryoneWritable(other), acl.UsersWritable(other))
	run(a, project, "escalate", path)
	_, err = os.Stat(path)
	fmt.Printf("escalation-target-survived=%v\n", err == nil)

	other = dir("everyone-create-only")
	must(setSD(other, "D:P(A;OICI;FA;;;"+user+")(A;OICI;FA;;;SY)(A;OICI;0x2;;;WD)"))
	path = file(other)
	run(a, project, "read", path)
	must(grant.Apply(b, other, grant.RW))
	show("create-only-became-reading", other)
	run(a, project, "read", path)

	other = dir("outer-writable")
	must(grant.Apply(b, other, grant.RW))
	nested = filepath.Join(other, "inner")
	must(os.Mkdir(nested, 0o700))
	path = file(nested)
	must(grant.Apply(a, nested, grant.RW))
	must(grant.Revoke(b, other))
	try("outer-revoke-after-inner-grant", b, project, path)
}

func setSD(path, text string) error {
	sd, err := windows.SecurityDescriptorFromString(text)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	runtime.KeepAlive(sd)
	return err
}

func show(name, path string) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	must(err)
	fmt.Printf("%s %s\n", name, sd.String())
}

func run(account, dir, op, path string) int {
	exe, err := os.Executable()
	must(err)
	tok, err := token.Restricted(account)
	must(err)
	code, e := proc.Run(tok, syscall.EscapeArg(exe)+" child "+op+" "+syscall.EscapeArg(path), dir)
	_ = tok.Close()
	fmt.Printf("%s exit=%d start-error=%v\n", op, code, e)
	if e != nil {
		panic(e)
	}
	return code
}

func try(name, account, dir, path string) {
	fmt.Printf("CASE %s\n", name)
	show("parent", filepath.Dir(path))
	show("file", path)
	for _, op := range []string{"read", "write", "rename", "delete"} {
		code := run(account, dir, op, path)
		if op == "rename" && code == 0 {
			must(os.Rename(path+".moved", path))
		}
	}
	_, err := os.Stat(path)
	fmt.Printf("survived=%v\n", err == nil)
}

func tests(root, mode string) {
	profile := filepath.Join(root, "profile")
	local := filepath.Join(profile, "local")
	roaming := filepath.Join(profile, "roaming")
	temp := filepath.Join(root, "temp")
	for _, p := range []string{profile, local, roaming, temp} {
		must(os.MkdirAll(p, 0o700))
	}
	data, err := osexec.Command("go", "env", "-json", "GOMODCACHE", "GOCACHE", "GOPATH").Output()
	must(err)
	var vars map[string]string
	must(json.Unmarshal(data, &vars))
	env := os.Environ()
	for k, v := range vars {
		env = append(env, k+"="+v)
	}
	lib := filepath.Join(os.Getenv("LOCALAPPDATA"), "ktav-go", "v0.6.4", "ktav_cabi-windows-amd64.dll")
	env = append(env, "USERPROFILE="+profile, "LOCALAPPDATA="+local, "APPDATA="+roaming, "TEMP="+temp, "TMP="+temp, "KTAV_LIB_PATH="+lib, "WUSERBOX_CONFIG=", "WUSERBOX_NON_INTERACTIVE=1")
	args := []string{"test", "-json", "-count=1", "-p", "2"}
	if mode == "mutation" {
		cwd, err := os.Getwd()
		must(err)
		data, err := json.Marshal(map[string]any{"Replace": map[string]string{filepath.Join(cwd, "internal", "win", "acl", "isolate.go"): filepath.Join(cwd, ".reg-review", "disabled", "isolate.go")}})
		must(err)
		overlay := filepath.Join(root, "overlay.json")
		must(os.WriteFile(overlay, data, 0o600))
		args = append(args, "-overlay", overlay)
	}
	if mode == "suite" {
		args = append(args, "./...", "-skip", "^(TestCLIFullLifecycle|TestLifecycle|TestRefusesWritesToTheRegistry|TestRefusesWritesToPublicAndProgramData|TestReadsTheUserProfile)$")
	} else {
		args = append(args, "./internal/e2e", "./internal/win/acl", "-run", "^(TestOneSandboxCannotReachWhatADirectoryAboveHandedDown|TestIsolateNarrowsSharedWriteHandedDownFromAbove)$")
	}
	cmd := osexec.Command("go", args...)
	cmd.Env = env
	out, runErr := cmd.CombinedOutput()
	for _, line := range bytes.Split(out, []byte{'\n'}) {
		var e struct{ Action, Package, Test, Output string }
		if json.Unmarshal(line, &e) != nil {
			if len(line) > 0 {
				fmt.Println(string(line))
			}
			continue
		}
		if e.Action == "fail" || e.Action == "skip" || (e.Action == "pass" && (e.Test == "" || mode != "suite")) {
			fmt.Printf("%s %s %s\n", e.Action, e.Package, e.Test)
		}
		if mode != "suite" && e.Action == "output" {
			fmt.Print(e.Output)
		}
	}
	if runErr != nil && mode == "suite" {
		fmt.Printf("UNEXPECTED FAILURE\n%s", out)
	}
	fmt.Printf("mode=%s go-test-result=%v\n", mode, runErr)
}
