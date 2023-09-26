//go:build !windows
// +build !windows

package elevate

func DoAsSystem(f func() error) error {
	return nil
}

func DoAsService(serviceName string, f func() error) error {
	return nil
}
