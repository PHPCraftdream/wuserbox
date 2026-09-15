package exit

import "fmt"

// Error is a failure that knows which exit code it deserves.
type Error struct {
	Code    Code
	Message string
}

func (e *Error) Error() string { return e.Message }

// Errorf builds an error carrying an exit code.
func Errorf(code Code, format string, args ...any) error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}
