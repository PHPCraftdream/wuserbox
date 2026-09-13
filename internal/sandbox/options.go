package sandbox

// Options are the per-invocation choices that shape a sandbox.
type Options struct {
	// Dir is the project directory; it is always writable.
	Dir string
	// RW and RO are extra directories for this invocation.
	RW, RO []string
	// NoAI skips the preset for AI agent directories.
	NoAI bool
	// HomeWrites lets the sandbox create files directly in the profile root.
	// Off by default, because the same permission reaches every file already
	// there. When it is on, the sensitive files are refused one by one.
	HomeWrites bool
}

// Args rebuilds these options as an `init` command line, for re-running with
// administrator rights.
func (o Options) Args() []string {
	args := []string{"init", "--dir", o.Dir}
	for _, d := range o.RW {
		args = append(args, "--rw", d)
	}
	for _, d := range o.RO {
		args = append(args, "--ro", d)
	}
	if o.NoAI {
		args = append(args, "--no-ai")
	}
	if o.HomeWrites {
		args = append(args, "--home-writes")
	}
	return args
}
