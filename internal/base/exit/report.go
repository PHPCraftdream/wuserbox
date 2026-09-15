package exit

import (
	"encoding/json"
	"fmt"
	"io"
)

// Report writes a failure in the shape the command line asked for.
//
// A command called with --json answers in JSON when it succeeds, and used to
// answer in prose when it failed, so anything reading the output had to handle
// two shapes and tell them apart by whether the run worked. The failure now
// arrives as a document of its own: the message, the exit code, and the name
// that code goes by.
func Report(w io.Writer, err error, asJSON bool) {
	if err == nil {
		return
	}
	code := Of(err)
	if !asJSON {
		_, _ = fmt.Fprintln(w, "wuserbox:", err)
		return
	}
	encoded, marshalErr := json.MarshalIndent(map[string]any{
		"error":  err.Error(),
		"code":   int(code),
		"status": code.String(),
	}, "", "  ")
	if marshalErr != nil {
		// Saying nothing would be worse than saying it plainly.
		_, _ = fmt.Fprintln(w, "wuserbox:", err)
		return
	}
	_, _ = w.Write(append(encoded, '\n'))
}
