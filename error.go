package nucleus

import (
	"errors"

	"github.com/reconquest/hierr-go"
)

// ErrorMultiple is a set of errors that occurred during operations with
// nucleus nodes.
type ErrorMultiple []error

// Error returns string representation of multiple errors
func (err ErrorMultiple) Error() string {
	if len(err) == 1 {
		return err[0].Error()
	}

	top := errors.New("nucleus: multiple errors")
	for _, nested := range err {
		top = hierr.Push(top, nested)
	}
	return top.Error()
}
