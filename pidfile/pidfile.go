// Package pid provides structure and helper functions to create and remove
// PID file. A PID file is usually a file used to store the process ID of a
// running process.
package pidfile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/sonnt85/gosystem"
	"github.com/sonnt85/gsjson"
	"github.com/tidwall/gjson"
	// "github.com/tidwall/gjson"
)

// Pidfile is a file used to store the process ID of a running process.
type Pidfile struct {
	*gsjson.Fjson
	OtherRunning bool
}

func running(pid int, namePid, appname, seconname string) (ok bool) {
	if p := gosystem.GetProcessFromPid(pid); p != nil {
		if len(namePid) != 0 {
			var err error
			if ok, err = p.IsRunning(); err == nil && ok {
				var name string
				name, err = p.Name()
				if err == nil && name == namePid {
					if len(seconname) != 0 {
						if seconname == appname {
							return true
						}
					} else {
						return true
					}
				}
			}
		}
	}
	return
}

// return nil is successful
func (f *Pidfile) isRunning(seconnames ...string) (err error) {
	if pid := f.Get("pid").Int(); pid != 0 {
		var ok bool
		if p := gosystem.GetProcessFromPid(pid); p != nil {
			appname := f.Get("appname").String()
			if namePid := f.Get("name").String(); len(namePid) != 0 {
				if ok, err = p.IsRunning(); err == nil && ok {
					var name string
					if name, err = p.Name(); err == nil && name == namePid {
						if len(seconnames) == 0 || (seconnames[0] == appname) {
							return nil
						}
					}
					err = errors.New("name error")
				} else {
					err = errors.New("pidname is not running")
				}
			} else {
				err = errors.New("pidname is empty")
			}
		} else {
			err = errors.New("PID does not exist")
		}
	} else {
		err = errors.New("missing pid")
	}
	return
}

func (f *Pidfile) SetAppName(appname string) (err error) {
	return f.Set("appname", appname)
}

func (f *Pidfile) SetBinName(binname string) (err error) {
	return f.Set("name", binname)
}

func (f *Pidfile) SetPid(pid interface{}) (err error) {
	return f.Set("pid", pid)
}

func (f *Pidfile) GetPidRunning() int64 {
	return f.Get("pid").Int()
}

// pidi are int or string
func ProcessExists(pidi interface{}) bool {
	return nil != gosystem.GetProcessFromPid(pidi)
	// var pid int
	// switch v := pidi.(type) {
	// case int:
	// 	pid = v
	// case string:
	// 	var err error
	// 	if pid, err = strconv.Atoi(v); err != nil {
	// 		return false
	// 	}
	// }
	// return processExists(pid)
}

func PidFileIsRunning(path string, passphrase []byte, progname string) (ok bool) {
	jsonstr := gsjson.DecodeJsonFileNoErr(path, passphrase)
	if !gjson.Valid(jsonstr) {
		return false
	}
	gresult := gjson.Parse(jsonstr)
	pid := gresult.Get("pid").Int()
	namePid := gresult.Get("name").String()
	appname := gresult.Get("appname").String()
	return running(int(pid), namePid, appname, progname)
}

// New creates a PID file using the specified path.
func NewPidfile(path string, passphrase []byte, progname string, removeIfFileInvalid bool, datas ...map[string]interface{}) (f *Pidfile, err error) {
	f = new(Pidfile)
	var processName string
	// exepath, err = sexec.GetExecPath()
	// if err != nil {
	// 	return
	// }
	currentPid := os.Getpid()
	currentProcess := gosystem.GetProcessFromPid(currentPid)
	if currentProcess == nil {
		err = errors.New("can not get current process")
		return
	}
	processName, err = currentProcess.Name()
	if err != nil {
		return
	}
	if len(path) == 0 {
		path = filepath.Join(os.TempDir(), strings.TrimSuffix(processName, filepath.Ext(processName))+".pid")
		// f.RmdirFlag = true
	}
	// isrinning := PidFileIsRunning(path, passphrase, progname)
	// gosystem.WriteToFileWithLockSFL("/tmp/sdaemon.txt", fmt.Sprintf("BeforeNewFjson \nK: %v\n%v\n", PidFileIsRunning(path, passphrase, progname), gsjson.DecodeJsonFileNoErr(path, passphrase)))
	f.Fjson, err = gsjson.NewFjson(path, passphrase, removeIfFileInvalid, datas...)
	// defer gosystem.WriteToFileWithLockSFL("/tmp/sdaemon.txt", fmt.Sprintf("AfterNewFjson \nK: %v\n%v\n", PidFileIsRunning(path, passphrase, progname), gsjson.DecodeJsonFileNoErr(path, passphrase)))
	if err == nil {
		setConfig := func() {
			f.Set("pid", currentPid)
			if len(progname) != 0 {
				f.Set("appname", progname)
			}
			f.Set("name", processName)
		}
		oldpid := f.Get("pid").Int()
		// if err = f.isRunning(progname); err != nil || oldpid == int64(currentPid) { //check old pid
		if err = f.isRunning(progname); err != nil || oldpid == int64(currentPid) { //oldpid == int64(currentPid) meaning restart, use for stini
			err = nil
			setConfig()
			return
		} else {
			if os.Getenv("__FORCEKILL__") == "true" {
				err = nil
				os.Unsetenv("__FORCEKILL__")
				gosystem.KilPid(oldpid)
				setConfig()
			} else {
				err = errors.New("the program is still running")
				f.OtherRunning = true
			}
		}
	}

	// gosystem.WriteToFileWithLockSFL("/tmp/sdaemon.txt", fmt.Sprintf("\nK: %v\n%v\n", err, os.Environ()))
	return
}
