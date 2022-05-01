//go:build js
// +build js

package gosystem

func isTerminal(fd int) bool {
	return false
}
