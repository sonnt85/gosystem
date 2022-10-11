package gosystem

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/shirou/gopsutil/process"
	"github.com/sonnt85/gosutils/cmdshellwords"
	"github.com/sonnt85/gosutils/goacl"
	"github.com/sonnt85/gosutils/sexec"
	"golang.org/x/term"
)

//func CPULoad() {
//	sexec.ExecCommand()
//}
type fduintptr interface {
	Fd() uintptr
}

type fdint interface {
	Fd() int
}

func IsTerminal(fd uintptr) bool {
	return term.IsTerminal(int(fd))
}

func IsTerminalWriter(w io.Writer) bool {
	return checkIfTerminal(w)
}

func IsTerminalWriter1(w io.Writer) bool {
	if false {
		if fileprr, ok := w.(*os.File); ok {
			return isatty.IsTerminal(fileprr.Fd())
		} else {
			return false
		}
	} else {
		if fw, ok := w.(fduintptr); ok {
			return IsTerminal(fw.Fd())
		} else if fw, ok := w.(fdint); ok {
			term.IsTerminal(fw.Fd())
		}
		return false
	}
}

func GetGoroutineId() int64 {
	return runtime.GetGoroutineId()
}

func Reboot(delay time.Duration) {
	go func() {
		time.Sleep(delay)
		cmd2run := ""
		if runtime.GOOS == "windows" {
			cmd2run = `C:\Windows\System32\shutdown.exe /r /t 3`
		} else {
			cmd2run = "reboot"
			//			syscall.Sync()
			//			syscall.Reboot(syscall.LINUX_REBOOT_CMD_RESTART)
		}
		if _, _, err := sexec.ExecCommandShell(cmd2run, time.Second*10, true); err == nil {
			os.Exit(0)
		}
	}()
	return
}

func RestartApp(appName string, delay ...time.Duration) bool {
	//	if _, _, err := sexec.ExecCommandShell(fmt.Sprintf(`(sleep 3; systemctl restart %s)&>>/tmp/upgrade.log&disown`, appName), time.Second*5); err != nil {
	go func() {
		if len(delay) != 0 {
			time.Sleep(delay[0])
		} else {
			time.Sleep(time.Second * 5)
		}
		//		os.Exit(0)
		if _, _, err := sexec.ExecCommandShell(fmt.Sprintf(`systemctl restart %s`, appName), time.Second*10, true); err != nil {
			log.Println("Can not restart apps", err)
		}
		return
	}()
	return true
}

func AppIsActive(appName string) bool {
	if _, _, err := sexec.ExecCommandShell(fmt.Sprintf(`systemctl is-active --quiet %s`, appName), time.Second*10, true); err != nil {
		return false
	} else {
		return true
	}
}

//(appName, exepath, clickdir string, fullpathflag bool, showterminal bool, args ...string)
func CreateClickTorun(appName, exepath, clickdir string, fullpathflag bool, showterminal bool, args ...string) (err error) {
	pwd, _ := os.Getwd()
	swargs := cmdshellwords.Join(args...)
	exepathwithargs := ""
	GOOS := runtime.GOOS
	if len(exepath) == 0 {
		exepath, _ = os.Executable()
	}
	if !fullpathflag {
		relpath, _ := filepath.Rel(pwd, exepath)
		exepath = relpath
		if GOOS == "windows" {
			exepathwithargs = cmdshellwords.Join(append([]string{relpath}, swargs)...)
		} else {
			exepathwithargs = `sh -c "cd $(dirname %k) && ./` + relpath + " " + swargs + `"`
		}
	} else {
		exepathwithargs = cmdshellwords.Join(append([]string{exepath}, swargs)...)
	}
	clickdir = filepath.Join(clickdir, appName)
	if GOOS == "windows" {
		showterminalOpt := "False"
		if showterminal {
			showterminalOpt = "True"
		}
		vbs := fmt.Sprintf(`Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "%s", 0, %s
`, exepathwithargs, showterminalOpt)
		if err1 := ioutil.WriteFile(clickdir+".vbs", []byte(vbs), os.FileMode(0755)); err1 != nil {
			err = err1
		}
		if err1 := ioutil.WriteFile(clickdir+".bat", []byte(exepathwithargs), os.FileMode(0755)); err1 != nil {
			err = err1
		}
		return
	} else if GOOS == "darwin" {
		//Icon=
		err = ioutil.WriteFile(clickdir+".command", []byte(exepathwithargs), os.FileMode(0755))
		return err
	} else {
		//Icon=
		desktopContent := fmt.Sprintf(`[Desktop Entry]
Name=%sRun
Comment=Click to run
Exec=%s
Terminal=%t
Type=Application
Categories=Utility;Application;Development;`, appName, exepath, showterminal)
		err = ioutil.WriteFile(clickdir+".desktop", []byte(desktopContent), os.FileMode(0755))
		return err
	}
}

func GetProcessFromPid(pidi interface{}) (p *process.Process) {
	var err error
	var pid int
	switch v := pidi.(type) {
	case int:
		pid = int(v)
	case int64:
		pid = int(v)
	case string:
		if pid, err = strconv.Atoi(v); err != nil {
			return
		}
	default:
		return nil
	}
	if p, err = process.NewProcess(int32(pid)); err == nil {
		return
	}
	return
}

func KilPid(pidi interface{}) (err error) {
	//	p, err := process.NewProcess(pid) // Specify process id of parent
	//	if err != nil {
	//		return err
	//	}
	var pid int
	switch v := pidi.(type) {
	case int:
		pid = v
	case int64:
		pid = int(v)
	case string:
		if pid, err = strconv.Atoi(v); err != nil {
			return
		}
	default:
		return nil
	}
	var p *os.Process
	p, err = os.FindProcess(pid)
	if err != nil {
		return err
	}
	//	p.Kill()
	//	p.Children()
	//	if childpids, err := p.Children(); err == nil {
	//		for _, v := range childpids {
	//			errkc := v.Kill()
	//			if errkc != nil { // Kill each child
	//				log.Info("[KilPid]Can not kill child", v, errkc)
	//			}
	//		}
	//		return nil
	//	}
	return p.Kill() // Kill the parent process
}

func InitSignal(cleanup func()) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-c
		if cleanup != nil {

			cleanup()
		}
		os.Exit(1)
	}()
}

func Uptime() string {
	if stdout, _, err := sexec.ExecCommand("uptime", "-p"); err != nil {
		return ""
	} else {
		return strings.TrimRight(string(stdout), "\n")
	}
}

func DirIsWritable(path string) (isWritable bool, err error) {
	return dirIsWritable(path)
}

func FirstDirIsWriteable(paths []string) string {
	for i := 0; i < len(paths); i++ {
		if ok, err := DirIsWritable(paths[i]); err == nil && ok {
			return paths[i]
		}
	}
	return ""
}

func FileIWriteable(path string) (isWritable bool) {
	return fileIWriteable(path)
}

func PathIsWriteable(path string) (isWritable bool) {
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

func FileIsExist(path string) bool {
	if finfo, err := os.Stat(path); err == nil {
		if !finfo.IsDir() {
			return true
		}
	}
	return false
}

func DirIsExist(path string) bool {
	if finfo, err := os.Stat(path); err == nil {
		if finfo.IsDir() {
			return true
		}
	}
	return false
}

func TouchFile(name string) error {
	file, err := os.OpenFile(name, os.O_RDONLY|os.O_CREATE, 0644)
	if err != nil {
		log.Println(err)
		return err
	}
	return file.Close()
	//	return nil
}

func WriteTrucFile(name string, contents string) bool {
	return nil == os.WriteFile(name, []byte(contents), 0755)
}

func GetHomeDir() (home string) {
	home, err := HomeDir() // os.UserHomeDir()
	if err == nil {
		return home
	} else {
		return ""
	}
}

func GetHostname() (hname string) {
	hname, err := os.Hostname()
	if err == nil {
		return hname
	} else {
		return ""
	}
}

func GetUsername() string {
	if user, err := user.Current(); err == nil {
		return user.Username
	} else {
		return ""
	}
}

func Getwd() (pwd string) {
	var err error
	if pwd, err = os.Getwd(); err != nil {
		var f *os.File
		if f, err = os.Open("."); err == nil {
			pwd = f.Name()
			f.Close()
		} else {
			pwd = GetHomeDir()
		}
	}
	return
}

func GetEnvPathValue() string {
	for _, pathname := range []string{"PATH", "path"} {
		path := os.Getenv(pathname)
		if len(path) != 0 {
			return path
		}
	}
	return ""
}

func GetEnvPath() []string {
	envs := GetEnvPathValue()
	if len(envs) != 0 {
		return strings.Split(envs, string(os.PathListSeparator))
	}
	return []string{}
}

// func ExecIsExistsInPathEnv(binpath string) (ebinpath string, err error) {
// 	//		sutils.PATHHasFile(filepath, PATH) && sutils.FileIWriteable(ebinpath)
// 	if ebinpath, err = exec.LookPath(binpath); err == nil && fileIWriteable(ebinpath) {
// 		return
// 	} else {
// 		return func() (ebinpath string, err error) {
// 			if envs := GetEnvPath(); len(envs) != 0 {
// 				for i := len(envs); i >= 1; i-- {
// 					ebinpath = envs[i-1]
// 					var ok bool
// 					if ok, err = dirIsWritable(ebinpath); err == nil && ok {
// 						return
// 						// return filepath.Join(dirpath, binpath)
// 					}
// 				}
// 			}
// 			return "", errors.New("not found")
// 		}()
// 	}
// }

func GetPathDirInEnvPathCanWrite() (ebinpath string) {
	//		sutils.PATHHasFile(filepath, PATH) && sutils.FileIWriteable(ebinpath)
	var err error
	if envs := GetEnvPath(); len(envs) != 0 {
		for i := len(envs); i >= 1; i-- {
			ebinpath = envs[i-1]
			var ok bool
			if ok, err = dirIsWritable(ebinpath); err == nil && ok {
				return
			}
		}
	}
	return ""
}

func GetPathDirInEnvPathCanWriteOrCreateNew(prefixNameForNew string) (ebinpath string, new bool) {
	//		sutils.PATHHasFile(filepath, PATH) && sutils.FileIWriteable(ebinpath)
	var err error
	if envs := GetEnvPath(); len(envs) != 0 {
		for i := len(envs); i >= 1; i-- {
			ebinpath = envs[i-1]
			var ok bool
			if ok, err = dirIsWritable(ebinpath); err == nil && ok {
				return
			}
		}
	}
	new = true
	ebinpath, _ = os.MkdirTemp("", prefixNameForNew)
	return
}

func CheckSudo() (bool, error) {
	return checkRoot()
}

func UserIsRoot() bool {
	return isRoot()
}

func UserHasSudo() bool {
	ok, err := checkRoot()
	return err == nil && ok
}

func SetAllEnv(env []string) {
	os.Clearenv()
	for _, e := range env {
		k, v, ok := strings.Cut(e, "=")
		if !ok {
			continue
		}
		os.Setenv(k, v)
	}
}

func EnrovimentMap() (me map[string]string) {
	me = make(map[string]string)
	env := os.Environ()
	for _, e := range env {
		k, v, ok := strings.Cut(e, "=")
		if !ok {
			continue
		}
		me[k] = v
	}
	return
}

func EnrovimentMapAdd(key, val string) (me map[string]string) {
	me = EnrovimentMap()
	me[key] = val
	return
}

func IsDoubleClickRun() bool {
	return isDoubleClickRun()
}

func Chmod(name string, mode os.FileMode) error {
	return goacl.Chmod(name, mode)
}
