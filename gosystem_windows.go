package gosystem

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/sonnt85/gosutils/sexec"
	"github.com/sonnt85/gosystem/elevate"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	// "syscall"
)

// func fileIWriteable(path string) (isWritable bool) {
// 	isWritable = false
// 	err := syscall.Access(path, syscall.O_RDWR)
// 	if err != nil {
// 		return
// 	}
// 	return true
// }

func fileIWriteable(path string) (isWritable bool) {
	isWritable = false
	if file, err := os.OpenFile(path, os.O_WRONLY, 0666); err == nil {
		defer file.Close()
		isWritable = true
	} else {
		if os.IsPermission(err) {
			return false
		}
	}

	return
}

var (
	PERFORMANCE_DATA = "PERFORMANCE_DATA"
	CURRENT_CONFIG   = "CURRENT_CONFIG"
	USERS            = "USERS"
	LOCAL_MACHINE    = "LOCAL_MACHINE"
	CLASSES_ROOT     = "CLASSES_ROOT"
	CURRENT_USER     = "CURRENT_USER"
	_rootkey         = map[string]registry.Key{PERFORMANCE_DATA: registry.Key(syscall.HKEY_PERFORMANCE_DATA),
		CURRENT_CONFIG: registry.Key(syscall.HKEY_CURRENT_CONFIG),
		USERS:          registry.Key(syscall.HKEY_USERS),
		LOCAL_MACHINE:  registry.Key(syscall.HKEY_LOCAL_MACHINE),
		CLASSES_ROOT:   registry.Key(syscall.HKEY_CLASSES_ROOT),
		CURRENT_USER:   registry.Key(syscall.HKEY_CURRENT_USER)}
)

func getRegistry(rootkey string, path string) {
	k, err := registry.OpenKey(_rootkey[rootkey], path, registry.QUERY_VALUE)
	if err != nil {
		log.Fatal(err)
	}
	defer k.Close()

	s, _, err := k.GetStringValue("SystemRoot")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Windows system root is %q\n", s)
}

func dirIsWritable(path string) (isWritable bool, err error) {
	var file *os.File
	file, err = os.CreateTemp(path, "test")
	if err != nil {
		return
	} else {
		if err = file.Close(); err != nil {
			return
		}
		err = os.Remove(file.Name())
		if err == nil {
			isWritable = true
		}
		return
	}

	isWritable = false
	var info fs.FileInfo
	info, err = os.Stat(path)
	if err != nil {
		// fmt.Println("Path doesn't exist")
		return
	}

	err = nil
	if !info.IsDir() {
		err = errors.New("path isn't a directory")
		return
	}

	// Check if the user bit is enabled in file permission
	if info.Mode().Perm()&(1<<(uint(7))) == 0 {
		err = errors.New("write permission bit is not set on this file for user")
		// fmt.Println("Write permission bit is not set on this file for user")
		return
	}

	isWritable = true
	return
}

func checkRoot() (bool, error) {
	return elevate.IsAdminDesktop()
}

func isRoot() bool {
	return elevate.IsElevated()
}

func checkRootOld() (bool, error) {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		return false, fmt.Errorf("sid error: %s", err)
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0)

	member, err := token.IsMember(sid)
	if err != nil {
		return false, fmt.Errorf("token membership error: %s", err)
	}
	return member, nil
}

func isDoubleClickRun() bool {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	lp := kernel32.NewProc("GetConsoleProcessList")
	if lp != nil {
		var pids [2]uint32
		var maxCount uint32 = 2
		ret, _, _ := lp.Call(uintptr(unsafe.Pointer(&pids)), uintptr(maxCount))
		if ret > 1 {
			return false
		}
	}
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
		overlapped := &windows.Overlapped{}
		err = windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 0, 0, overlapped)
		if err != nil {
			return nil, err
		}
		defer windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 0, 0, overlapped)

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
	if srcn, err := syscall.UTF16PtrFromString(src); err != nil {
		return err
	} else if dstn, _ := syscall.UTF16PtrFromString(dst); err != nil {
		return err
	} else {
		return windows.CreateSymbolicLink(srcn, dstn, windows.SYMBOLIC_LINK_FLAG_DIRECTORY)
	}
}

func allownetworkprogram(path string, tempTime ...time.Duration) (err error) {
	var b bool
	if b, err = elevate.IsAdminDesktop(); b {
		namerule := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		script := fmt.Sprintf(`netsh advfirewall firewall add rule name="%s" dir=out action=allow program="%s"`, namerule, path)
		_, _, err = sexec.ExecCommandShellTimeout(script, time.Second*3)
		// Add-MpPreference -ExclusionPath
		//powershell.exe -Command Add-MpPreference -ExclusionPath  "C:\Users\user\AppData\Local\Temp\dir"
		sexec.ExecCommandShellElevatedEnvTimeout("powershell.exe", 0, nil, 0, "-Command", "Add-MpPreference", "-ExclusionPath", path)
		if len(tempTime) != 0 {
			go func() {
				time.Sleep(tempTime[0])
				// netsh advfirewall firewall delete rule name=
				script := fmt.Sprintf(`netsh advfirewall firewall delete rule name="%s"`, namerule)
				_, _, err = sexec.ExecCommandShellTimeout(script, time.Second*3)
				// cmd := exec.Command("powershell.exe", "-Command", "Remove-MpPreference", "-ExclusionPath", path)
				sexec.ExecCommandShellElevatedEnvTimeout("powershell.exe", 0, nil, 0, "-Command", "Remove-MpPreference", "-ExclusionPath", path)

			}()
		}
		// Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
	}
	return
}
