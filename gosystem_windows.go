package gosystem

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/sonnt85/gosutils/sexec"
	"github.com/sonnt85/gosutils/sutils"
	"github.com/sonnt85/gosystem/elevate"
	"github.com/sonnt85/strcase"
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

func getRegistry(rootkey string, path string) (string, error) {
	k, err := registry.OpenKey(_rootkey[rootkey], path, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer k.Close()

	s, _, err := k.GetStringValue("SystemRoot")
	if err != nil {
		return "", err
	}
	return s, nil
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

func isCurrentUserInSudoGroup() bool {
	return elevate.IsElevated()
}

func isCurrentUserRoot() bool {
	return elevate.DoAsSystem(func() error { return nil }) == nil
	// if b, e := elevate.IsAdminDesktop(); e == nil && b {
	// 	return true
	// } else {
	// 	return false
	// }
}

func isCurrentUserInSudoGroupOld() (bool, error) {
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

func splitIntoLines(s string) []string {
	lines := strings.FieldsFunc(s, func(r rune) bool {
		return r == '\n' || r == '\r'
	})
	var result []string

	for _, s := range lines {
		if s != "" {
			result = append(result, s)
		}
	}
	return result
}

// Must be an administrator to view exclusions
func getDefenderExclusions_() ([]string, error) {
	cmd := sexec.Command("powershell", "-WindowStyle", "Hidden", "-Command", "Get-MpPreference | Select-Object -ExpandProperty ExclusionPath")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute PowerShell command: %s", err)
	}

	exclusions := splitIntoLines(strings.TrimSpace(string(output)))
	return exclusions, nil
}
func getDefenderExclusions() (exclusions []string, err error) {
	elevate.DoAsSystem(func() error {
		exclusions, err = getDefenderExclusions_()
		return err
	})
	return
}
func defenderExclusionsHas(path string) bool {
	exlist, err := getDefenderExclusions()
	// slogrus.Infof("%+v -> %s", exlist, path)
	if err == nil && sutils.SlideHasElementInStrings(exlist, path) {
		return true
	}
	return false
}

func firewallHasRule(path string, ruleName ...string) (bret bool) {
	namerule := ""
	if len(path) != 0 {
		namerule = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		namerule = strcase.ToSnake(namerule)
	}

	if len(ruleName) != 0 {
		namerule = ruleName[0]
	}
	if len(namerule) == 0 {
		return false
	}
	if b, e := sexec.Command("netsh", "advfirewall", "firewall", "show", "rule", fmt.Sprintf(`name="%s"`, namerule), "verbose").Output(); e == nil {
		if len(path) == 0 {
			return true
		}
		output := string(b)
		lines := splitIntoLines(string(output))
		for _, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), "Program:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 && strings.TrimSpace(parts[1]) == path {
					return true
				}
				// break
			}
		}
	}
	return
}

func firewallRemoveProgram(path string, ruleName ...string) (err error) {
	if isCurrentUserRoot() {
		var errtmp error
		if len(path) == 0 {
			if path, err = os.Executable(); err != nil {
				return
			}
		}
		pathExclusion := path
		f := func() error {
			namerule := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
			namerule = strcase.ToSnake(namerule)
			if len(ruleName) != 0 {
				namerule = ruleName[0]
				if PathIsFile(path) {
					pathExclusion = filepath.Dir(path)
				}
			}
			if PathIsFile(path) {
				// if firewallHasRule(path, namerule) {
				if sexec.Command("netsh", "advfirewall", "firewall", "show", "rule", fmt.Sprintf(`name="%s"`, namerule)).Run() == nil {
					// script := fmt.Sprintf(`netsh advfirewall firewall delete rule name="%s"`, namerule)
					// _, _, errtmp = sexec.ExecCommandShellTimeout(script, time.Second*30)
					_, _, errtmp = sexec.ExecCommandShellElevatedEnvTimeout("netsh", 0, nil, -1, "advfirewall", "firewall", "delete", "rule", fmt.Sprintf(`name="%s"`, namerule))

					err = errors.Join(err, errtmp)
				}
			}
			if defenderExclusionsHas(pathExclusion) {
				_, _, errtmp = sexec.ExecCommandShellElevatedEnvTimeout("powershell.exe", 0, nil, -1, "-WindowStyle", "Hidden", "-Command", "Remove-MpPreference", "-ExclusionPath", pathExclusion)
				err = errors.Join(err, errtmp)
			}
			return err
			// err = errors.Join(err, errtmp)

		}
		elevate.DoAsSystem(f)
		// f()
	}

	return
}

func firewallAddProgram(path string, dur_rulename ...interface{}) (err error) {
	var errtmp error
	var tempDur time.Duration
	if len(path) == 0 {
		if path, err = os.Executable(); err != nil {
			return
		}
	}
	pathExclusion := path
	if isCurrentUserRoot() {
		f := func() error {
			namerule := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
			namerule = strcase.ToSnake(namerule)
			if len(dur_rulename) != 0 {
				for _, t := range dur_rulename {
					switch v := t.(type) {
					case time.Duration:
						tempDur = v
					case string:
						namerule = v
						if PathIsFile(path) {
							pathExclusion = filepath.Dir(path)
						}
					}
				}
			}

			if !defenderExclusionsHas(pathExclusion) {
				_, _, errtmp = sexec.ExecCommandShellElevatedEnvTimeout("powershell.exe", 0, nil, -1, "-WindowStyle", "Hidden", "-NoLogo", "-NonInteractive", "-Command", "Add-MpPreference", "-ExclusionPath", pathExclusion)
				err = errors.Join(err, errtmp)
			}
			// netsh advfirewall firewall show rule name=all
			if PathIsFile(path) {
				if !firewallHasRule(path, namerule) {
					if firewallHasRule("", namerule) {
						sexec.ExecCommandShellElevatedEnvTimeout("netsh", 0, nil, -1, "advfirewall", "firewall", "delete", "rule", fmt.Sprintf(`name="%s"`, namerule))
					}
					// if errtmp = sexec.Command("netsh", "advfirewall", "firewall", "show", "rule", fmt.Sprintf(`name="%s"`, namerule)).Run(); errtmp != nil {
					// logrus.Info("show rule: ", errtmp)
					// script = fmt.Sprintf(`netsh advfirewall firewall add rule name="%s" dir=out action=allow program="%s"`, namerule, path)
					_, _, errtmp = sexec.ExecCommandShellElevatedEnvTimeout("netsh", 0, nil, -1, "advfirewall", "firewall", "add", "rule", fmt.Sprintf(`name="%s"`, namerule), "dir=out", "action=allow", fmt.Sprintf(`program="%s"`, path))
					// _, _, errtmp = sexec.ExecCommandShellTimeout(script, time.Second*30)
					err = errors.Join(err, errtmp)
					// Add-MpPreference -ExclusionPath
					//powershell.exe -Command Add-MpPreference -ExclusionPath  "C:\Users\user\AppData\Local\Temp\dir"
				}
			}
			if err == nil && tempDur != 0 {
				go func() {
					time.Sleep(tempDur)
					// var script string
					// netsh advfirewall firewall delete rule name=
					if PathIsFile(path) {
						// script = fmt.Sprintf(`netsh advfirewall firewall delete rule name="%s"`, namerule)
						// _, _, errtmp = sexec.ExecCommandShellTimeout(script, time.Second*30)
						_, _, errtmp = sexec.ExecCommandShellElevatedEnvTimeout("netsh", 0, nil, -1, "advfirewall", "firewall", "delete", "rule", fmt.Sprintf(`name="%s"`, namerule))

					}
					// cmd := sexec.Command("powershell.exe", "-Command", "Remove-MpPreference", "-ExclusionPath", path)
					if defenderExclusionsHas(pathExclusion) {
						sexec.ExecCommandShellElevatedEnvTimeout("powershell.exe", 0, nil, -1, "-WindowStyle", "Hidden", "-NoLogo", "-NonInteractive", "-Command", "Remove-MpPreference", "-ExclusionPath", pathExclusion)
					}
				}()
			}

			// Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
			return err
		}
		elevate.DoAsSystem(f)
	}

	return
}

func copyOwnership(srcPath, destPath string) error {
	return nil
	// srcInfo, err := os.Stat(srcPath)
	// if err != nil {
	// 	return err
	// }

	// destInfo, err := os.Stat(destPath)
	// if err != nil {
	// 	return err
	// }

	// // Kiểm tra hệ điều hành
	// switch srcInfo.Sys().(type) {
	// case *syscall.Win32FileAttributeData:
	// 	// Windows
	// 	destSys, ok := destInfo.Sys().(*syscall.Win32FileAttributeData)
	// 	if !ok {
	// 		return fmt.Errorf("Unsupported destination system type")
	// 	}

	// 	// Copy UID
	// 	destSys.FileAttributes |= srcInfo.Sys().(*syscall.Win32FileAttributeData).FileAttributes & syscall.FILE_ATTRIBUTE_DIRECTORY

	// 	// Copy GID
	// 	destSys.Reserved |= srcInfo.Sys().(*syscall.Win32FileAttributeData).Reserved & syscall.FILE_ATTRIBUTE_DIRECTORY
	// default:
	// 	return fmt.Errorf("Unsupported source system type")
	// }

	// return nil
}

func getFileOwnership(path string) (uint32, uint32, error) {
	return 0, 0, nil
	// fileInfo, err := os.Stat(path)
	// if err != nil {
	// 	return 0, 0, err
	// }

	// winFileAttrData, ok := fileInfo.Sys().(*syscall.Win32FileAttributeData)
	// if !ok {
	// 	return 0, 0, fmt.Errorf("Failed to get file attributes")
	// }

	// return winFileAttrData.Uid, winFileAttrData.Gid, nil
}
