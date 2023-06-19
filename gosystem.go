package gosystem

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/sonnt85/gosutils/goreaper"

	"github.com/mattn/go-isatty"
	"github.com/shirou/gopsutil/process"
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
	return term.IsTerminal(int(fd))
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

func AllowNetworkProgram(path string, tempTime ...time.Duration) (err error) {
	return allownetworkprogram(path, tempTime...)
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
	case string:
		if pid, err = strconv.Atoi(v); err != nil {
			return
		}
	case int32:
	default:
		return nil
	}
	if p, err = process.NewProcess(int32(pid)); err == nil {
		return
	}
	return
}

func SendSignalToAllProcess(sig os.Signal) (errret []error) {
	processList, err := process.Processes()
	if err != nil {
		return []error{err}
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
	p, _ = process.NewProcess(pid) // Specify process id of parent ;
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

func InitSignal(cleanup func(s os.Signal) int, handleSIGCHILDs ...bool) {
	c := make(chan os.Signal, 1)
	var handleSIGCHILD bool
	if len(handleSIGCHILDs) != 0 {
		handleSIGCHILD = handleSIGCHILDs[0]
	} else {
		handleSIGCHILD = !sutils.IsContainer()
	}
	goreaper.Reap(handleSIGCHILD)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	go func() {
		s := <-c
		if cleanup != nil {
			retcode := cleanup(s)
			if retcode == 0 {
				os.Exit(retcode)
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

func WriteTrucFile(name string, contents string) bool {
	return nil == os.WriteFile(name, []byte(contents), 0755)
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
	// Mở file trong chế độ append, tạo mới nếu file không tồn tại
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	// Chuyển đổi dữ liệu thành byte slice nếu cần
	var bytes []byte
	switch v := data.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return fmt.Errorf("Unsupported data type")
	}

	// Ghi dữ liệu vào cuối file
	_, err = file.Write(bytes)
	if err != nil {
		return err
	}

	return nil
}

func GetHomeDir() (home string) {
	home, err := HomeDir() // os.UserHomeDir()
	if err == nil {
		return home
	} else {
		return ""
	}
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
	if finfo, err := os.Stat(path); err == nil {
		if finfo.IsDir() {
			return true
		}
	}
	return false
}

func PathIsFile(path string) bool {
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

func Symlink(src, dst string) error {
	return symlink(src, dst)
}

func SymlinkRel(src, dst string) error {
	relativePath, err := filepath.Rel(filepath.Dir(dst), src)
	if err != nil {
		return err
	}
	err = Symlink(relativePath, dst)
	return err
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
