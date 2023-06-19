//go:build !windows
// +build !windows

package gosystem

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"syscall"
	"time"
)

func fileIWriteable(path string) (isWritable bool) {
	isWritable = false
	if file, err := os.OpenFile(path, os.O_WRONLY, 0666); err == nil {
		defer file.Close()
		isWritable = true
	}
	//  else {
	// 	if os.IsPermission(err) {
	// 		return false
	// 	}
	// }

	return
}

func dirIsWritableSimple(path string) (bool, error) {
	file, err := os.CreateTemp(path, "test-*.txt")
	if err != nil {
		return false, err
	}
	defer func() {
		file.Close()
		os.Remove(file.Name()) // Xóa tệp tin tạm sau khi sử dụng
	}()

	// Do something with the temporary file
	return true, nil
}

func dirIsWritable(path string) (isWritable bool, err error) {
	if runtime.GOOS == "darwin" {
		return dirIsWritableSimple(path)
	}
	isWritable = false
	var info fs.FileInfo
	info, err = os.Stat(path)
	if err != nil {
		return
	}

	if !info.IsDir() {
		err = errors.New("path isn't a directory")
		return
	}

	// Check if the user bit is enabled in file permission
	if info.Mode().Perm()&(1<<(uint(7))) == 0 {
		err = errors.New("write permission bit is not set on this file for user")
		return
	}

	var stat syscall.Stat_t
	if err = syscall.Stat(path, &stat); err != nil {
		return
	}

	err = nil
	if uint32(os.Geteuid()) != stat.Uid {
		isWritable = false
		// fmt.Println("User doesn't have permission to write to this directory")
		return
	}

	isWritable = true
	return
}

func hasGroupSudo() bool {
	if isRoot() {
		return true
	}
	cmd := exec.Command("id")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), "(sudo)")
}

func checkRoot() (bool, error) {
	if hasGroupSudo() {
		return true, nil
	}
	return isRoot(), nil
}

func isRoot() bool {
	currentUser, err := user.Current()
	if err != nil {
		cmd := exec.Command("id", "-u")

		output, err := cmd.Output()
		if err != nil {
			return false
		}

		if strings.TrimSpace(string(output)) == "0" {
			return true
		}
		return false
	}
	if currentUser.Uid == "0" {
		return true
	} else {
		return false
	}

}

func isDoubleClickRun() bool {
	return true
}

func writeToFileWithLockSFL(filePath string, data interface{}, truncs ...bool) error {
	res, err, _ := fileGroup.Do(filePath, func() (interface{}, error) {
		file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0755)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		if len(truncs) != 0 && truncs[0] {
			file.Truncate(0)
		}
		syscall.Flock(int(file.Fd()), syscall.LOCK_EX)
		defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)

		switch d := data.(type) {
		case string:
			_, err = file.WriteString(d)
			if err != nil {
				return nil, err
			}
		case []byte:
			_, err = file.Write(d)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unsupported data type")
		}

		return nil, nil
	})

	if err != nil {
		return err
	}
	if res != nil {
		return res.(error)
	} else {
		return nil
	}
}

func symlink(src, dst string) error {
	return os.Symlink(src, dst)
}

func allownetworkprogram(path string, tempTime ...time.Duration) (err error) {
	return nil
	// var b bool
	// if b, err = elevate.IsAdminDesktop(); b {
	// 	script := fmt.Sprintf(`netsh advfirewall firewall add rule name="Allow Network Access" dir=out action=allow program="%s"`, path)
	// 	_, _, err = sexec.ExecCommandShell(script, time.Second*3)
	// }
	// return
}
