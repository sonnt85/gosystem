package gosystem

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	// _ "go.uber.org/automaxprocs"

	"github.com/fsnotify/fsnotify"
	"github.com/sonnt85/godotenv"
	"github.com/sonnt85/gofilepath"
	"github.com/sonnt85/gogmap"
	"github.com/sonnt85/gosystem/elevate"
	"golang.org/x/sync/singleflight"

	"github.com/sonnt85/gosutils/goreaper"
	"github.com/sonnt85/gosutils/hashmap"
	"github.com/sonnt85/gosutils/ppjson"
	"github.com/sonnt85/gosutils/sregexp"

	"github.com/mattn/go-isatty"
	"github.com/shirou/gopsutil/v4/process"
	"github.com/sonnt85/gosutils/cmdshellwords"
	"github.com/sonnt85/gosutils/goacl"
	"github.com/sonnt85/gosutils/sexec"
	"github.com/sonnt85/gosutils/sutils"

	"golang.org/x/term"
)

//	func CPULoad() {
//		sexec.ExecCommand()
//	}
type fduintptr interface {
	Fd() uintptr
}

type fdint interface {
	Fd() int
}

var NewLine = "\n"

func IsTerminal(fd uintptr) bool {
	if term.IsTerminal(int(fd)) || isatty.IsCygwinTerminal(fd) { //isatty.IsTerminal(fd) ||
		return true
	} else {
		return false
	}
}

func IsTerminalWriter(w io.Writer) bool {
	return checkIfTerminal(w)
}

func init() {
	GOOS := runtime.GOOS
	if GOOS == "windows" {
		NewLine = "\r\n"
	} else if GOOS == "darwin" {
		NewLine = "\r"
	}
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

func GetGoroutineId() uint64 {
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
		if _, _, err := sexec.ExecCommandShellTimeout(cmd2run, time.Second*10); err == nil {
			os.Exit(0)
		}
	}()
	return
}

func RestartApp(appName string, delay ...time.Duration) bool {
	//	if _, _, err := sexec.ExecCommandShellTimeout(fmt.Sprintf(`(sleep 3; systemctl restart %s)&>>/tmp/upgrade.log&disown`, appName), time.Second*5); err != nil {
	go func() {
		if len(delay) != 0 {
			time.Sleep(delay[0])
		} else {
			time.Sleep(time.Second * 5)
		}
		//		os.Exit(0)
		if _, _, err := sexec.ExecCommandShellTimeout(fmt.Sprintf(`systemctl restart %s`, appName), time.Second*10); err != nil {
			log.Println("Can not restart apps", err)
		}
		return
	}()
	return true
}

func AppIsActive(appName string) bool {
	if _, _, err := sexec.ExecCommandShellTimeout(fmt.Sprintf(`systemctl is-active --quiet %s`, appName), time.Second*10); err != nil {
		return false
	} else {
		return true
	}
}

// func AllowNetworkProgram(path string, tempTime ...time.Duration) (err error) {
// 	return firewallAddProgram(path, tempTime...)
// }

func FirewallAddProgram(path string, dur_rulename ...interface{}) (err error) {
	return firewallAddProgram(path, dur_rulename...)
}

func FirewallGetDefenderExclusions() ([]string, error) {
	return getDefenderExclusions()
}
func FirewallHasRule(path string, ruleName ...string) bool {
	return firewallHasRule(path, ruleName...)

}
func FirewallRemoveProgram(path string, ruleName ...string) (err error) {
	return firewallRemoveProgram(path, ruleName...)
}

func DoAsSystem(f func() error) error {
	return elevate.DoAsSystem(f)
}

func DoAsService(serviceName string, f func() error) error {
	return elevate.DoAsService(serviceName, f)
}

// (appName, exepath, clickdir string, fullpathflag bool, showterminal bool, args ...string)
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
		// showterminalOpt := "False"
		// if showterminal {
		// 	showterminalOpt = "True"
		// }
		// 		vbs := fmt.Sprintf(`Set WshShell = CreateObject("WScript.Shell")
		// WshShell.Run "%s", 0, %s
		// `, exepathwithargs, showterminalOpt)
		// 		if err1 := os.WriteFile(clickdir+".vbs", []byte(vbs), os.FileMode(0755)); err1 != nil {
		// 			err = err1
		// 		}
		if err1 := os.WriteFile(clickdir+".bat", []byte(exepathwithargs), os.FileMode(0755)); err1 != nil {
			err = err1
		}
		return
	} else if GOOS == "darwin" {
		//Icon=
		err = os.WriteFile(clickdir+".command", []byte(exepathwithargs), os.FileMode(0755))
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
		err = os.WriteFile(clickdir+".desktop", []byte(desktopContent), os.FileMode(0755))
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
	case uint64:
		pid = int(v)
	case string:
		if pid, err = strconv.Atoi(v); err != nil {
			return
		}
	case int32:
		pid = int(v)
	case uint32:
		pid = int(v)
	default:
		return nil
	}
	if p, err = process.NewProcess(int32(pid)); err == nil {
		return
	}
	return
}

func GetProcessNameFromPid(pidi interface{}) string {
	if p := GetProcessFromPid(pidi); p != nil {
		if pname, err := p.Name(); err == nil {
			return pname
		}
	}
	return ""
}

// ProcessNode định nghĩa một node trong process tree
type ProcessNode struct {
	PID      int32
	Children []*ProcessNode
}

// GetProcessTree builds a process tree from a PID
func GetPocessTree(pid int32) (*ProcessNode, error) {
	proc, err := process.NewProcess(pid)
	if err != nil {
		return nil, err
	}
	node := &ProcessNode{PID: pid}

	children, err := proc.Children()
	if err != nil {
		if err != process.ErrorNoChildren {
			return nil, err
		}
	}

	for _, child := range children {
		childNode, err := GetPocessTree(child.Pid)
		if err != nil {
			return nil, err
		}
		node.Children = append(node.Children, childNode)
	}

	return node, nil
}

// findAllDescendantPIDs finds all descendant PIDs of the rootPID
func GetAllDescendantPIDs(rootPID int32, includeRootPid ...bool) ([]int32, error) {
	descendants := []int32{}
	if len(includeRootPid) > 0 && includeRootPid[0] {
		descendants = append(descendants, rootPID)
	}
	queue := []int32{rootPID}

	for len(queue) > 0 {
		currentPID := queue[0]
		queue = queue[1:]

		proc, err := process.NewProcess(currentPID)
		if err != nil {
			continue
			// return nil, err
		}

		children, err := proc.Children()
		if err != nil && err != process.ErrorNoChildren {
			return nil, err
		}

		for _, child := range children {
			descendants = append(descendants, child.Pid)
			queue = append(queue, child.Pid)
		}
	}

	return descendants, nil
}

func GetAllAncestorProcesses(rootPID int32, includeRootPid ...bool) ([]*process.Process, error) {
	ancestors := []*process.Process{}
	if len(includeRootPid) > 0 && includeRootPid[0] {
		p, err := process.NewProcess(rootPID)
		if err != nil {
			return nil, err
		}
		ancestors = append(ancestors, p)
	}
	queue := []int32{rootPID}

	for len(queue) > 0 {
		currentPID := queue[0]
		if currentPID == 1 {
			break
		}
		queue = queue[1:]

		proc, err := process.NewProcess(currentPID)
		if err != nil {
			return nil, err
		}

		parent, err := proc.Parent()
		if err != nil {
			// if err == process.ErrorNoParent {
			// 	continue
			// }
			return nil, err
			// return ancestors, nil
		}

		ancestor, err := process.NewProcess(parent.Pid)
		if err != nil {
			return nil, err
		}

		ancestors = append(ancestors, ancestor)
		queue = append(queue, parent.Pid)
	}

	return ancestors, nil
}

// GetAllAncestorPIDs finds all ancestor PIDs of the rootPID
func GetAllAncestorPIDs(rootPID int32, includeRootPid ...bool) ([]int32, error) {
	ancestors := []int32{}
	if len(includeRootPid) > 0 && includeRootPid[0] {
		ancestors = append(ancestors, rootPID)
	}
	queue := []int32{rootPID}

	for len(queue) > 0 {
		currentPID := queue[0]
		queue = queue[1:]
		if currentPID == 1 {
			break
		}
		proc, err := process.NewProcess(currentPID)
		if err != nil {
			return nil, err
		}

		parent, err := proc.Parent()
		if err != nil {
			// if err == process.ErrorNoParent {
			// 	continue
			// }
			return nil, err
		}

		ancestors = append(ancestors, parent.Pid)
		queue = append(queue, parent.Pid)
	}

	return ancestors, nil
}

// findAllDescendantPIDs finds all descendant PIDs of the rootPID
func GetAllDescendantProcesses(rootPID int32, includeRootPid ...bool) ([]*process.Process, error) {
	descendants := []*process.Process{}
	if len(includeRootPid) > 0 && includeRootPid[0] {
		p, err := process.NewProcess(rootPID)
		if err != nil {
			return nil, err
		}
		descendants = append(descendants, p)
	}
	queue := []int32{rootPID}

	for len(queue) > 0 {
		currentPID := queue[0]
		queue = queue[1:]

		proc, err := process.NewProcess(currentPID)
		if err != nil {
			return nil, err
		}

		children, err := proc.Children()
		if err != nil && err != process.ErrorNoChildren {
			return nil, err
		}

		for _, child := range children {
			descendants = append(descendants, child)
			queue = append(queue, child.Pid)
		}
	}

	return descendants, nil
}

func KillProcessTree(rootPID int32, signals ...os.Signal) (errret error) {
	var descendantPIDs []int32
	var err error
	currentPid := int32(os.Getegid())
	descendantPIDs, err = GetAllDescendantPIDs(rootPID)
	if err != nil {
		return err
	}
	sig := syscall.Signal(syscall.SIGTERM)
	if len(signals) > 0 {
		sig = syscall.Signal(signals[0].(syscall.Signal))
	}
	var process *os.Process
	for i := len(descendantPIDs) - 1; i >= 0; i-- {
		pid := descendantPIDs[i]
		process, err = os.FindProcess(int(pid))
		if err != nil {
			continue
		}
		if currentPid != pid {
			if err = process.Signal(sig); err != nil {
				errret = errors.Join(errret, err)
			}
		}
	}
	var rootProcess *os.Process
	rootProcess, err = os.FindProcess(int(rootPID))
	if err == nil {
		rootProcess.Signal(syscall.SIGTERM)
		// fmt.Printf("Killed root process with PID %d\n", rootPID)
	} else {
		errret = errors.Join(errret, err)
	}
	return
}

// printProcessTree in cây process
func PrintProcessTree(node *ProcessNode, prefix string) {
	fmt.Printf("%s%d\n", prefix, node.PID)
	for _, child := range node.Children {
		PrintProcessTree(child, prefix+"  ")
	}
}

func SendSignalToAllProcess(sig os.Signal, parrentpid ...int) (errret []error) {
	var processList []*process.Process
	var err error
	if len(parrentpid) > 0 {
		processList, err = GetAllDescendantProcesses(int32(parrentpid[0]), true)
		if err != nil {
			return []error{err}
		}
	} else {
		processList, err = process.Processes()
		if err != nil {
			return []error{err}
		}
	}
	sigcall := syscall.Signal(sig.(syscall.Signal))
	for _, p := range processList {
		if os.Getegid() == int(p.Pid) {
			continue
		}
		if err := p.SendSignal(sigcall); err != nil {
			errret = append(errret, err)
		}
	}
	return
}

func IsSignalForAllProcess(sig os.Signal) bool {
	switch sig {
	case os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT:
		return true
	default:
		sigint := SignalToInt(sig)
		//SIGRTMIN -> SIGRTMAX 34 49-59 64
		if sigint >= 39 && sigint <= 64 {
			return true
		}
		return false
	}
}

func GetKillSignal() os.Signal {
	return syscall.SIGKILL
}

func SendSignalToSelf(sig os.Signal) error {
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		return err
	}
	return p.Signal(sig)
}

func Terminate() error {
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		return err
	}
	return p.Signal(syscall.SIGTERM)
}

func IsExitSignal(sig os.Signal) bool {
	switch sig {
	case syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGHUP:
		return true
	default:
		return false
	}
}

func KilProcessName(name string, isFullname ...bool) error {
	ps, err := process.Processes()
	if err != nil {
		return err
	}
	var pname string
	// found := false
	for _, p := range ps {
		if len(isFullname) != 0 && isFullname[0] {
			pname, err = p.Exe()
		} else {
			pname, err = p.Name()
		}

		if err == nil && pname == name {
			// found = true
			p.Kill()
		}
	}
	return nil
}

func Pgrep(names ...string) (ps []*process.Process) {
	ps, _ = Processes(names...)
	return
}

func PgrepWithEnv(names string, key, val string) (ps []*process.Process) {
	if pst, err := Processes(names); err == nil {
		ps = make([]*process.Process, 0)
		env := fmt.Sprintf("%s=%s", key, val)
		for _, p := range pst {
			if nvs, e := p.Environ(); e == nil {
				for _, v := range nvs {
					if v == env || key == "*" || (val == "*" && strings.HasPrefix(v, fmt.Sprintf("%s=", key))) {
						ps = append(ps, p)
						break
					}
				}
			}
		}
	}
	return
}

func GetMapPidsOpenFile(filePath string) (pidsmap map[int]string) {
	pidsmap = make(map[int]string, 0)
	filepathAbs, err := filepath.Abs(filePath)
	if err != nil {
		return
	}

	processes, err := process.Processes()
	if err != nil {
		return
	}

	for _, p := range processes {
		fds, err := p.OpenFiles()
		if err != nil {
			continue
		}

		for _, fd := range fds {
			if fd.Path == filepathAbs {
				if pname, err := p.Name(); err == nil {
					pidsmap[int(p.Pid)] = pname
				}
			}
		}
	}
	return
}

func Processes(names ...string) (ps []*process.Process, err error) {
	// func Pgrep(name string, isFullname ...bool) error {
	ps, err = process.Processes()
	// if len(names) == 0 {
	// 	return
	// }

	if err != nil {
		return
	}
	var pname string
	// found := false
	retps := make([]*process.Process, 0)
	for _, p := range ps {
		pname, err = p.Name()

		if len(names) == 0 || (len(names) == 1 && names[0] == "*") || (err == nil && sutils.SlideHasElementInStrings(names, pname)) {
			retps = append(retps, p)
		}
	}
	return retps, nil
}

func ProcessesPids(names ...string) (pids []int) {
	pids = make([]int, 0)
	if ps, err := Processes(names...); err == nil {
		for _, v := range ps {
			pids = append(pids, int(v.Pid))
		}
	}
	return
}

func ProcessesOfPid(pid int32) (p *process.Process) {
	var err error
	p, err = process.NewProcess(pid) // Specify process id of parent ;
	if err != nil {
		p = nil
	}
	return p
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

func SignalToInt(s os.Signal) int {
	if i, ok := s.(syscall.Signal); ok {
		return int(i)
	}
	return 0
}

var exitFuncs = make([]func(...interface{}), 0)

func TrapExitAdd(f func(...interface{})) {
	if f != nil {
		exitFuncs = append(exitFuncs, func(args ...interface{}) {
			f(args...)
		})
	}
}

func InitSignal(cleanup func(s os.Signal) int, handleSIGCHILDs ...bool) {
	c := make(chan os.Signal, 1)
	var handleSIGCHILD bool
	if len(handleSIGCHILDs) != 0 {
		handleSIGCHILD = handleSIGCHILDs[0]
	} else {
		handleSIGCHILD = !sutils.IsContainer()
	}
	goreaper.Reap(handleSIGCHILD)
	// goreaper.EnableDebug()
	signal.Notify(c)
	// signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	go func() {
		for {
			s := <-c
			retcode := -1
			// if s.String() != "child exited" {
			// }
			if cleanup != nil {
				retcode = cleanup(s)
			}
			if IsExitSignal(s) {
				for _, f := range exitFuncs {
					if f != nil {
						f()
					}
				}
				if retcode == 0 {
					os.Exit(retcode)
				}
			}
		}
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

func FileDirIWriteable(path string) bool {
	var err error
	var srcinfo os.FileInfo
	if srcinfo, err = os.Stat(path); err == nil {
		if err = os.Chtimes(path, srcinfo.ModTime(), srcinfo.ModTime()); err == nil {
			return true
		}
	}
	return false
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

func CheckExecutablePermission(efile string) bool {
	if _, err := exec.LookPath(efile); err == nil {
		return true
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
		// log.Println(err)
		return err
	}
	return file.Close()
	//	return nil
}

func WriteTrucFile(name string, contents interface{}) bool {
	// return nil == os.WriteFile(name, []byte(contents), 0755)
	return WriteToFile(name, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, contents) == nil

}

// data are string, []byte, io.Reader
func WriteAppendToFile(filePath string, content interface{}) (b bool) {
	return AppendToFile(filePath, content) == nil
}

func FileWriteBytesIfChange(pathfile string, contents []byte) (bool, error) {
	oldContents := []byte{}
	if _, err := os.Stat(pathfile); err == nil {
		oldContents, _ = os.ReadFile(pathfile)
	}

	if !bytes.Equal(oldContents, contents) {
		return true, os.WriteFile(pathfile, contents, 0644)
	} else {
		return false, nil
	}
}

func AppendToFile(filename string, data interface{}) error {
	return WriteToFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, data)
}

// data are string, []byte, io.Reader
func WriteToFile(filename string, flag int, data interface{}, perms ...fs.FileMode) error {
	perm := fs.FileMode(0644)
	if len(perms) != 0 {
		perm = perms[0]
	}
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	defer file.Close()
	var r io.Reader
	switch v := data.(type) {
	case []byte:
		r = bytes.NewBuffer(v)
	case string:
		r = bytes.NewBufferString(v)
	case io.Reader:
		r = v
	default:
		return fmt.Errorf("unsupported data type")
	}
	_, err = io.Copy(file, r)
	// _, err = file.Write(bytes)
	if err != nil {
		return err
	}

	return nil
}

func GetHomeDir() (home string) {
	if cuser, err := user.Current(); err == nil {
		home = cuser.HomeDir
	} else if homet, err := HomeDir(); err == nil {
		home = homet
	}
	return
}

func GetWorkingDir() (wdir string) {
	var err error
	wdir, err = os.Getwd() // os.UserHomeDir()
	if err == nil {
		return wdir
	} else {
		return GetHomeDir()
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

func PathGetEnvPathKey() string {
	for _, pathname := range []string{"PATH", "path"} {
		path := os.Getenv(pathname)
		if len(path) != 0 {
			return pathname
		}
	}
	return ""
}

func PathAddDirs(dirs ...string) {
	for _, v := range dirs {
		os.Setenv(PathGetEnvPathKey(), PathJointList(PathGetEnvPathValue(), v))
	}
}

func PathJointList(path, data string) string {
	//	data = data + string(os.PathSeparator)
	if len(path) == 0 {
		return data
	}
	return path + string(os.PathListSeparator) + data
	//	filepath.ListSeparator
}

func PathGetEnvPathValue() string {
	for _, pathname := range []string{"PATH", "path"} {
		path := os.Getenv(pathname)
		if len(path) != 0 {
			return path
		}
	}
	return ""
}

func PathList() []string {
	envs := PathGetEnvPathValue()
	if len(envs) != 0 {
		return strings.Split(envs, string(os.PathListSeparator))
	}
	return []string{}
}

func PathRemoveDirs(dirs ...string) {
	oldpath := sutils.PathGetEnvPathValue()
	for _, d := range dirs {
		oldpath = sutils.PathRemove(oldpath, d)
	}
	os.Setenv(sutils.PathGetEnvPathKey(), oldpath)
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
	var err error
	for _, ebinpath = range GetEnvPath() {
		var ok bool
		if ok, err = dirIsWritable(ebinpath); err == nil && ok {
			return ebinpath
		}
	}
	return ""
}

func PathIsDir(path string) bool {
	return gofilepath.PathIsDir(path)
	if finfo, err := os.Stat(path); err == nil {
		if finfo.IsDir() {
			return true
		}
	}
	return false
}

func PathIsFile(path string) bool {
	return gofilepath.PathIsFile(path)
	if finfo, err := os.Stat(path); err == nil {
		if !finfo.IsDir() {
			return true
		}
	}
	return false
}

func PATHHasFile(filePath, PATH string) bool {
	execbasename := filepath.Base(filePath)
	baseNameOnly := execbasename == filePath
	for _, val := range strings.Split(PATH, string(os.PathListSeparator)) {
		if (!baseNameOnly && val == filePath) || (baseNameOnly && PathIsFile(filepath.Join(val, execbasename))) {
			return true
		}
	}
	return false
}

func GetPathHasSubpath(subpath, PATH string) string {
	for _, val := range strings.Split(PATH, string(os.PathListSeparator)) {
		if _, err := os.Stat(filepath.Join(val, subpath)); err == nil {
			return val
		}
	}
	return ""
}

func GetPathDirInEnvPathCanWriteOrCreateNew(prefixNameForNew string) (ebinpath string, new bool) {
	//		sutils.PATHHasFile(filepath, PATH) && sutils.FileIWriteable(ebinpath)
	ebinpath = GetPathDirInEnvPathCanWrite()
	if len(ebinpath) != 0 {
		return
	}
	new = true
	ebinpath, _ = os.MkdirTemp("", prefixNameForNew)
	return
}

// Can run the highest right without the admin password
func IsCurrentUserRoot() bool {
	return isCurrentUserRoot()
}

// IsAdminDesktop
// Can run the highest right but with the admin password
func IsCurrentUserInSudoGroup() bool {
	return isCurrentUserInSudoGroup()
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

func EnrovimentMap(envstrings ...string) (me map[string]string) {
	me = make(map[string]string)

	if len(envstrings) == 0 {
		envstrings = os.Environ()
	}

	for _, e := range envstrings {
		k, v, ok := strings.Cut(e, "=")
		if !ok {
			continue
		}
		me[k] = v
	}
	return
}

func EnrovimentMergeMap(evmerge map[string]string) []string {
	return godotenv.EnrovimentMergeWithCurrentEnv(evmerge)
}

func EnrovimentMapToStrings(me map[string]string) (se []string) {
	se = []string{}
	for k, e := range me {
		se = append(se, fmt.Sprintf("%s=%s", k, e))
	}
	return
}

func EnrovimentStringAdd(key, val string, envstrings []string) (se []string) {
	return append(envstrings, fmt.Sprintf("%s=%s", key, val))
}

func EnrovimentMapAdd(key, val string, envstrings ...string) (me map[string]string) {
	me = EnrovimentMap(envstrings...)
	me[key] = val
	return
}

func EnrovimentMergeCurrentEnv(envMap map[string]string) (senv []string) {
	var currentEnvMap = make(map[string]string, 0)
	for _, rawEnvLine := range os.Environ() {
		keyval := strings.Split(rawEnvLine, "=")
		currentEnvMap[keyval[0]] = keyval[1]
	}

	for key, value := range envMap {
		currentEnvMap[key] = value
	}
	for key, value := range currentEnvMap {
		senv = append(senv, fmt.Sprintf("%s=%s", key, value))
	}
	return
}

func EnrovimentMergeCurrentEnvToMap(envMap map[string]string) (me map[string]string) {
	mes := EnrovimentMergeCurrentEnv(envMap)
	return EnrovimentMap(mes...)

}

func IsDoubleClickRun() bool {
	return isDoubleClickRun()
}

func Chmod(name string, mode os.FileMode) error {
	return goacl.Chmod(name, mode)
}

var fileGroup singleflight.Group

func WriteToFileWithLockSFL(filePath string, data interface{}, truncs ...bool) error {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		file, err := os.Create(filePath)
		if err != nil {
			return err
		}
		file.Close()
	}
	return writeToFileWithLockSFL(filePath, data, truncs...)
}

func TempFileCreateInNewTemDir(filename string, prefix ...string) string {
	pref := "system"
	if len(prefix) != 0 {
		pref = prefix[0]
	}
	rootdir, err := os.MkdirTemp("", pref)
	if err != nil {
		return ""
	} else {
		//			defer os.RemoveAll(dir)
	}

	return filepath.Join(rootdir, filename)
}

func TempDirCreateInNewTemDir(dirname string, prefix ...string) (tdir string) {
	pref := "system"
	if len(prefix) != 0 {
		pref = prefix[0]
	}
	rootdir, err := os.MkdirTemp("", pref)
	if err != nil {
		return ""
	}
	tdir = filepath.Join(rootdir, dirname)
	err = os.Mkdir(tdir, 0755)
	if err != nil {
		defer os.RemoveAll(rootdir)
		return ""
	}
	return
}

func TempFileCreateInNewTemDirWithContent(filename string, data []byte, prefix ...string) string {
	pref := "system"
	if len(prefix) != 0 {
		pref = prefix[0]
	}
	rootdir, err := os.MkdirTemp("", pref)
	if err != nil {
		return ""
	}
	fPath := filepath.Join(rootdir, filename)
	err = os.WriteFile(fPath, data, 0755)
	if err != nil {
		os.RemoveAll(rootdir)
		return ""
	}
	return fPath
}

func TempFileCreate(prefix ...string) string {
	pref := "system"
	if len(prefix) != 0 {
		pref = prefix[0]
	}
	if f, err := os.CreateTemp("", pref); err == nil {
		defer f.Close()
		return f.Name()
	} else {
		return ""
	}
}

func TempFileCreateWithContent(data []byte, prefix ...string) string {
	pref := "system"
	if len(prefix) != 0 {
		pref = prefix[0]
	}
	if f, err := os.CreateTemp("", pref); err == nil {
		var n int
		if n, err = f.Write(data); err != nil && n == len(data) {
			f.Close()
			os.Remove(f.Name())
			return ""
		}
		f.Close()
		return f.Name()
	} else {
		return ""
	}
}

// Symlink creates newname as a symbolic link to oldname.
// On Windows, a symlink to a non-existent oldname creates a file symlink;
// if oldname is later created as a directory the symlink will not work.
// If there is an error, it will be of type *LinkError.

func Symlink(oldname, newname string) error {
	return symlink(oldname, newname)
}

func SymlinkRel(oldname, newname string) error {
	relativePath, err := filepath.Rel(filepath.Dir(newname), oldname)
	if err != nil {
		return err
	}
	if b, _ := gofilepath.PathsPointToSameFile(oldname, newname); b {
		return nil
	}
	err = Symlink(relativePath, newname)
	return err
}

func SymlinkRelWithInit(oldname, newname string, force bool, dstisfile bool) (msgs string, err error) {
	var b bool
	var msg []string
	defer func() {
		if len(msg) != 0 {
			msgs = ppjson.ToString(msg, true)
		}
		// else {
		// 	msgs = fmt.Sprintf("Exit SymlinkRelWithInit %s %s %t %t", oldname, newname, force, dstisfile)
		// }
	}()
	if b, _ = gofilepath.PathsPointToSameFile(oldname, newname); b && gofilepath.PathIsSymlink(newname) {
		msg = append(msg, fmt.Sprintf("Created symlink before [%s -> %s]", newname, oldname))
		return
	}
	if gofilepath.PathIsFile(newname) || gofilepath.PathIsFile(oldname) {
		dstisfile = true
	}
	if gofilepath.PathIsExist(newname) || gofilepath.PathIsExist(oldname) {
		force = true
	}

	if (PathIsExist(newname) && !gofilepath.PathIsSymlink(newname)) || force { //!PathIsExist(oldname)
		os.MkdirAll(filepath.Dir(oldname), 0x755)
		if dstisfile { // file
			if PathIsFile(newname) {
				msg = append(msg, fmt.Sprintf("Move file from '%s' -> '%s'", newname, oldname))
				FileMove(newname, oldname)
			} else {
				if !PathIsFile(oldname) {
					msg = append(msg, fmt.Sprintf("Force create target file '%s'", oldname))
					TouchFile(oldname)
				}
			}
		} else {
			if !PathIsDir(oldname) {
				msg = append(msg, fmt.Sprintf("Force create target directory '%s'", oldname))
				os.Mkdir(oldname, 0755)
			}
		}

		lockSufix := ".slocked"
		locked := false
		if PathIsExist(oldname) {
			newnameDir := filepath.Dir(newname)
			oldnameDir := filepath.Dir(oldname)
			srcchange := false
			oldnameBase := filepath.Base(oldname)
			if !PathIsExist(newnameDir) {
				msg = append(msg, fmt.Sprintf("Create new parrent' source (symbolic link) dirs '%s'", newnameDir))
				os.MkdirAll(newnameDir, 0x755)
			}
			if b, _ = gofilepath.PathsPointToSameFile(oldname, newname); b && gofilepath.PathIsSymlink(newname) {
				msg = append(msg, fmt.Sprintf("Created symlink before [%s -> %s]", newname, oldname))
				return
			}
			var lockfile string

			if PathIsDir(newname) {
				lockfile = filepath.Join(oldname, lockSufix)
				if PathIsFile(lockfile) {
					locked = true
					if PathIsExist(newname) {
						msg = append(msg, fmt.Sprintf("Locked target %s, remove all target %s", lockfile, oldname))
						os.RemoveAll(newname)
					}
				}
				lockfile = filepath.Join(newname, lockSufix)
				if PathIsFile(lockfile) {
					locked = true
					srcchange = true
					msg = append(msg, fmt.Sprintf("Locked source (symbolic link) %s, remove all dst %s", lockfile, newname))
					// # rsync -aX --delete-after --inplace --no-whole-file --exclude .slocked "${line[1]}/" "${line[0]}}/"
					// os.RemoveAll(oldname)
					// exec.Command("rm", "--one-file-system", "-rf", oldname).Run()
					if o, e := exec.Command("rm", "--one-file-system", "-rf", oldname).CombinedOutput(); e != nil {
						msg = append(msg, fmt.Sprintf("can not remove  data %s %s", o, e.Error()))
						return
					}
					if e := os.Rename(newname, oldname); e != nil {

					}
				}
				if !locked && PathIsExist(newname) {
					msg = append(msg, fmt.Sprintf("Merge data %s to %s", newname, oldname))
					//  cp -xuarf "${line[1]}/."  "${line[0]}/"
					if o, e := exec.Command("cp", "-xuarf", newname+string(os.PathSeparator)+".", oldname+string(os.PathSeparator)).CombinedOutput(); e != nil {
						msg = append(msg, fmt.Sprintf("can not merge data %s %s", o, e.Error()))
						return
					}
					// os.RemoveAll(newname)
					if o, e := exec.Command("rm", "--one-file-system", "-rf", newname).CombinedOutput(); e != nil {
						msg = append(msg, fmt.Sprintf("can not remove  data %s %s", o, e.Error()))
						return
					}
					srcchange = true
				}

			} else if gofilepath.PathIsFile(newname) { //file
				lockfile = filepath.Join(oldnameDir, "."+oldnameBase+lockSufix)
				if PathIsFile(lockfile) {
					locked = true
					msg = append(msg, fmt.Sprintf("Locked target %s, remove all target %s", lockfile, newname))

					// rm -f "${line[1]}"
					os.Remove(newname)

				}
				lockfile = filepath.Join(newnameDir, "."+oldnameBase+lockSufix)
				if PathIsFile(lockfile) {
					locked = true
					srcchange = true
					msg = append(msg, fmt.Sprintf("Locked source (symbolic link) %s, remove all dst %s", lockfile, oldname))
					os.Remove(oldname)
					os.Rename(newname, oldname)
				}

				if !locked {
					srcchange = true
					os.Rename(newname, oldname)
				}
			}

			if gofilepath.PathIsSymlink(newname) {
				srcsym, _ := os.Readlink(newname)
				msg = append(msg, fmt.Sprintf("Delete broken symbolic link %s [ -> %s]", newname, srcsym))
				os.Remove(newname)
			}
			if err = SymlinkRel(oldname, newname); err == nil {
				lockfile = filepath.Join(oldnameDir, "."+oldnameBase+lockSufix)
				if PathIsDir(oldname) {
					lockfile = filepath.Join(oldname, lockSufix)
				}
				if srcchange || !PathIsExist(lockfile) {
					msg = append(msg, fmt.Sprintf("Source data  %s is changed", oldname))
					FileWriteBytesIfChange(lockfile, []byte(time.Now().String()))
				}
			}
		} else {
			err = fmt.Errorf("path '%s' path does not exist", oldname)
		}
	}
	//else {
	// 	msg = append(msg, fmt.Sprintf("Nothing trigger creates symlink '%s' -> '%s'", newname, oldname))
	// }

	return
}

type File struct {
	f *os.File
	*sync.Pool
}

func OpenFile(filePath string, bufsize ...int) (f *File, err error) {
	f.f, err = os.Open(filePath)
	if err != nil {
		return
	}
	size := 1024
	if len(bufsize) != 0 {
		size = bufsize[0]
	}
	f.Pool = &sync.Pool{New: func() any {
		bs := make([]byte, size)
		return &bs
	}}
	return
}

func (rd *File) Read() (n int, err error) {
	buffer := rd.Get().(*([]byte))
	n, err = rd.f.Read(*buffer)
	if err != nil {
		rd.f.Close()
		if err == io.EOF {
			err = nil
		}
	}
	return
}

func (rd *File) Close() error {
	if rd.f != nil {
		return rd.f.Close()
	}
	return nil
}

func PathsAreEquivalent(path1 string, path2 string) (bool, error) {
	absPath1, err := filepath.Abs(path1)
	if err != nil {
		return false, err
	}

	absPath2, err := filepath.Abs(path2)
	if err != nil {
		return false, err
	}

	absPath1, err = filepath.EvalSymlinks(absPath1)
	if err != nil {
		return false, err
	}

	absPath2, err = filepath.EvalSymlinks(absPath2)
	if err != nil {
		return false, err
	}

	return absPath1 == absPath2, nil
}

func RemoveAllContents(paths ...string) error {
	for _, path := range paths {
		files, err := os.ReadDir(path)
		if err != nil {
			return err
		}

		for _, file := range files {
			filePath := filepath.Join(path, file.Name())

			err := os.RemoveAll(filePath)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func FileCopy(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file ", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer source.Close()
	if os.Rename(dst, dst+".fcb") == nil {
		defer func() {
			if err != nil {
				os.Rename(dst+".fcb", dst)
			} else {
				os.Remove(dst + ".fcb")
			}
		}()
	}
	destination, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer destination.Close()
	nBytes, err := io.Copy(destination, source)
	if err == nil {
		os.Chmod(dst, sourceFileStat.Mode())
		os.Chtimes(dst, sourceFileStat.ModTime(), sourceFileStat.ModTime())
	}
	return nBytes, err
}

func FileMove(src, dst string) (bytesmoved int64, err error) {
	if bytesmoved, err = FileCopy(src, dst); err == nil {
		err = os.Remove(src)
	}
	return
}

func FileCopyIfDiff(src, dst string) (int64, error) {
	if b, _ := FilesIsEqual(src, dst); b {
		return 0, nil
	} else {
		return FileCopy(src, dst)
	}
}

func FilesIsEqual(file1, file2 string) (bool, error) {
	f1, err := os.Open(file1)
	if err != nil {
		return false, err
	}
	defer f1.Close()

	f2, err := os.Open(file2)
	if err != nil {
		return false, err
	}
	defer f2.Close()

	const bufferSize = 4096 * 10
	buffer1 := make([]byte, bufferSize)
	buffer2 := make([]byte, bufferSize)

	for {
		n1, err1 := f1.Read(buffer1)
		n2, err2 := f2.Read(buffer2)

		if err1 != nil && err1 != io.EOF {
			return false, err1
		}
		if err2 != nil && err2 != io.EOF {
			return false, err2
		}

		if n1 != n2 || !bytes.Equal(buffer1[:n1], buffer2[:n2]) {
			return false, nil
		}

		if err1 == io.EOF && err2 == io.EOF {
			break
		}
	}

	return true, nil
}

func InstallDmg(path string, stringMatchs ...string) (err error) {
	stringMatch := ""
	if len(stringMatchs) != 0 {
		stringMatch = stringMatchs[0]
	}
	script := fmt.Sprintf(`
set -x
dmg_file="%s"
stringMatch="%s"
mount_point="$(hdiutil attach "$dmg_file" | grep -oEe '/Volumes/.+$')"
if [ -z "$mount_point" ]; then
  echo "Failed to mount DMG" >&2
  exit 1
fi

function exit_handler {
  hdiutil detach "$mount_point"
  exit
}

trap exit_handler EXIT

architecture=$(uname -m)
pkg_file=""

if [[ $stringMatch ]]; then
  pkg_file=$(find "$mount_point" -iname "*${stringMatch}*.pkg" -type f -maxdepth 1 -print -quit)
elif [ "$architecture" = "amd64" ]; then
  pkg_file=$(find "$mount_point" -iname "*amd64*.pkg" -type f -maxdepth 1 -print -quit)
  if [ -z "$pkg_file" ]; then
    pkg_file=$(find "$mount_point" -iname "*x86_64*.pkg" -type f -maxdepth 1 -print -quit)
  fi
else
  pkg_file=$(find "$mount_point" -iname "*${architecture}*.pkg" -type f -maxdepth 1 -print -quit)
fi

if [ -z "$pkg_file" ]; then
  echo "No suitable .pkg file found for architecture: $architecture" >&2
  exit 1
fi
osascript -e "do shell script \"installer -pkg '$pkg_file' -target /\" with administrator privileges"

if [ $? -ne 0 ]; then
  echo "An error occurred during installation" >&2
  exit 1
fi

trap - EXIT
exit_handler`, path, stringMatch)
	var stdout []byte
	stdout, _, err = sexec.ExecCommandShell(script)
	fmt.Print(string(stdout))
	return
}

func CopyOwnership(srcPath, destPath string) error {
	return copyOwnership(srcPath, destPath)
}

func GetFileOwnership(path string) (uint32, uint32, error) {
	return getFileOwnership(path)
}

type Watcher struct {
	*fsnotify.Watcher
	listPause *hashmap.MapEmpty[string]
	mapDirs   *gogmap.GlobalMap[[]string]
	// pause     bool
}

func matchRegex(files []string, basename string) bool {
	for _, v := range files {
		if strings.HasPrefix(v, "~") {
			if sregexp.New(strings.TrimPrefix(v, "~")).MatchString(basename) {
				return true
			}
		}
	}
	return false
}

// WatchConfig starts watching a config file for changes.
func FsnotifyChange(onConfigChange func(e fsnotify.Event), pauseWatchWhenCallBack bool, filesname ...string) (watcher *Watcher) {
	initWG := sync.WaitGroup{}
	initWG.Add(1)
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil
	}
	watcher = &Watcher{
		Watcher:   fsw,
		listPause: hashmap.NewMapEmpty[string](len(filesname)),
	}
	// watcher.listPause = hashmap.NewMapEmpty[string](len(filesname))

	// filename := filesname[0]
	// dirsPause := hashmap.NewMapEmpty[string](len(filesname))
	watcher.mapDirs = gogmap.NewGlobalMap[[]string]()
	for _, v := range filesname {
		isDir := strings.HasSuffix(v, string(os.PathSeparator)) || gofilepath.PathIsDir(v) || gofilepath.PathIsSymlinkDir(v)
		v = filepath.Clean(v)
		if isDir { // dir
			v = strings.TrimRight(v, string(os.PathSeparator))
			if val, ok := watcher.mapDirs.GetVal(v); !ok {
				watcher.mapDirs.Set(v, []string{""})
			} else {
				val = append(val, "")
				sutils.UniqueSlide(&val)
				watcher.mapDirs.Set(v, val)
			}
		} else { //v
			configParrDir, fname := filepath.Split(v)
			configParrDir = strings.TrimRight(configParrDir, string(os.PathSeparator))
			fileVal := v
			// mapDirs.Set(configDir, realConfigFile)
			if strings.HasPrefix(fname, "~") {
				fileVal = fname
			}
			if val, ok := watcher.mapDirs.GetVal(configParrDir); !ok {
				watcher.mapDirs.Set(configParrDir, []string{fileVal})
			} else {
				val = append(val, fileVal)
				sutils.UniqueSlide(&val)
				watcher.mapDirs.Set(configParrDir, val)
			}
		}
	}
	go func() {

		go func() {
			defer watcher.Close()
			for {
				select {
				case event, ok := <-watcher.Events:
					if !ok { // 'Events' channel is closed
						return
					}
					eventNameRealConfigFile := filepath.Clean(event.Name)
					if watcher.listPause.Contains(eventNameRealConfigFile) {
						continue
					}
					configDir, bname := filepath.Split(eventNameRealConfigFile)
					configDir = strings.TrimRight(configDir, string(os.PathSeparator))

					configFiles, okEle := watcher.mapDirs.GetVal(configDir)

					if !okEle {
						continue
					}

					// currentConfigFile, _ := filepath.EvalSymlinks(eventNameCleaned)
					// we only care about the config file with the following cases:
					// 1 - if the config file was modified or created
					// 2 - if the real path to the config file changed (eg: k8s ConfigMap replacement)
					if (sutils.SlideHasElement(configFiles, "") || matchRegex(configFiles, bname) || sutils.SlideHasElement(configFiles, eventNameRealConfigFile)) &&
						(event.Has(fsnotify.Write) || event.Has(fsnotify.Create)) {
						if onConfigChange != nil {
							if pauseWatchWhenCallBack {
								watcher.Pause(configDir)
							}
							onConfigChange(event)
							if pauseWatchWhenCallBack {
								watcher.Continue(configDir)
							}
						}
					} else if event.Has(fsnotify.Remove) && sutils.SlideHasElement(configFiles, eventNameRealConfigFile) {
						// removeList.Set(configDir, struct{}{})
						// eventsWG.Done()
						continue // return
					}

				case err, ok := <-watcher.Errors:
					if ok { // 'Errors' channel is not closed
						err = fmt.Errorf(fmt.Sprintf("watcher error: %s", err))
					}

					// eventsWG.Done()
					// eventsWG.ResetCount()
					continue //return
				}
			}
		}()
		go func() {
			for {
				for dir, _ := range watcher.mapDirs.Map() {
					if gofilepath.PathIsExist(dir) && !watcher.listPause.Contains(dir) {
						if !sutils.SlideHasElementInStrings(watcher.WatchList(), dir) {
							watcher.Add(dir)
						}
					}
				}
				time.Sleep(time.Second * 5)
			}
		}()
		initWG.Done() // done initializing the watch in this go routine, so the parent routine can move on...
	}()
	initWG.Wait() // make sure that the go routine above fully ended before returning
	return
}

func (watcher *Watcher) Pause(filePath ...string) {
	for dir, _ := range watcher.mapDirs.Map() {
		if len(filePath) == 0 {
			watcher.listPause.Add(dir)
			watcher.Remove(dir)
		} else {
			for _, path := range filePath {
				path = filepath.Clean(path)
				path = strings.TrimRight(path, string(os.PathSeparator))
				if path == dir { //dir
					watcher.Remove(dir)
				}
				watcher.listPause.Add(path)
			}
		}
	}
}

func (watcher *Watcher) Continue(filePath ...string) {
	for dir, _ := range watcher.mapDirs.Map() {
		if len(filePath) == 0 {
			watcher.listPause.Remove(dir)
		} else {
			for _, v1 := range filePath {
				v1 = filepath.Clean(v1)
				v1 = strings.TrimRight(v1, string(os.PathSeparator))
				if v1 == dir {
					watcher.Add(dir)
				}
				watcher.listPause.Remove(v1)
			}
		}
	}
}

func GetBuildTags() (tags []string) {
	tags = make([]string, 0)
	binfo, _ := debug.ReadBuildInfo()
	for _, v := range binfo.Settings {
		if v.Key == "-tags" && v.Value != "" {
			tags = append(tags, strings.Split(v.Value, ",")...)
		}
	}
	return
}

func BuildHasTags(tags ...string) bool {
	for _, v := range GetBuildTags() {
		if sutils.SlideHasElement(GetBuildTags(), v) {
			return true
		}
	}
	return false
}

func GetRuntimeCallerInformation(skip ...int) string {
	skipNum := 1
	if len(skip) != 0 {
		skipNum = skip[0]
	}
	pc, file, line, ok := runtime.Caller(skipNum)
	if !ok {
		return ""
	}
	functionName := runtime.FuncForPC(pc).Name()
	return fmt.Sprintf("%s:%s:%d", file, functionName, line)
}

func GetRuntimeCallerFuncName(skip ...int) string {
	skipNum := 1
	if len(skip) != 0 {
		skipNum = skip[0]
	}
	pc, _, _, ok := runtime.Caller(skipNum)
	if !ok {
		return ""
	}
	return runtime.FuncForPC(pc).Name()
}
