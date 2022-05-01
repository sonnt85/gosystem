//go:build appengine
// +build appengine

package gosystem

import (
	"io"
)

func checkIfTerminal(w io.Writer) bool {
	return true
}
