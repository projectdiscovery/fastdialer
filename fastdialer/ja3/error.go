package ja3

import "fmt"

// ErrExtensionNotExist is returned when an extension is not supported by the library
type ErrExtensionNotExist string

// Error is the error value which contains the extension that does not exist
func (e ErrExtensionNotExist) Error() string {
	return fmt.Sprintf("Extension does not exist: %s\n", string(e))
}
