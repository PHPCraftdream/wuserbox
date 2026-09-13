package exit

import "errors"

// Of returns the code an error deserves: the one it carries, or the general
// failure code. A nil error is success.
func Of(err error) Code {
	if err == nil {
		return OK
	}
	var coded *Error
	if errors.As(err, &coded) {
		return coded.Code
	}
	return Failed
}
