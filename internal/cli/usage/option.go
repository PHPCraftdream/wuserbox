package usage

// Option is one flag a command accepts.
type Option struct {
	// Name is how it is written, with its value placeholder: "--dir <d>".
	Name string
	// Effect is a single line, in the present tense.
	Effect string
}
