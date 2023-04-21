// Package pid provides structure and helper functions to create and remove
// PID file. A PID file is usually a file used to store the process ID of a
// running process.
package pidfile

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/sonnt85/gosutils/sexec"
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
				if (err == nil && name == namePid) || (len(seconname) != 0 && seconname == appname) {
					return true
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
					name, err = p.Name()
					if (err == nil && name == namePid) || (len(seconnames) != 0 && len(appname) != 0 && seconnames[0] == appname) {
						return nil
					} else {
						err = errors.New("name error")
					}
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
	var exepath, exebase string
	exepath, err = sexec.GetExecPath()
	if err != nil {
		// exepath = os.Args[0]
		return
	}
	exebase = filepath.Base(exepath)
	if len(path) == 0 {
		path = filepath.Join(os.TempDir(), exebase+".pid")
		// f.RmdirFlag = true
	}
	// isrinning := PidFileIsRunning(path, passphrase, progname)
	// gosystem.WriteToFileWithLockSFL("/tmp/sdaemon.txt", fmt.Sprintf("BeforeNewFjson \nK: %v\n%v\n", PidFileIsRunning(path, passphrase, progname), gsjson.DecodeJsonFileNoErr(path, passphrase)))
	f.Fjson, err = gsjson.NewFjson(path, passphrase, removeIfFileInvalid, datas...)
	// defer gosystem.WriteToFileWithLockSFL("/tmp/sdaemon.txt", fmt.Sprintf("AfterNewFjson \nK: %v\n%v\n", PidFileIsRunning(path, passphrase, progname), gsjson.DecodeJsonFileNoErr(path, passphrase)))
	if err == nil {
		currentPid := os.Getpid()
		if err = f.isRunning(progname); err != nil || f.Get("pid").Int() == int64(currentPid) { //check old pid
			err = nil
			f.Set("pid", currentPid)
			if len(progname) != 0 {
				f.Set("appname", progname)
			}
			f.Set("name", exebase)
			return
		} else {
			err = errors.New("the program is still running")
			f.OtherRunning = true
		}
	}

	// gosystem.WriteToFileWithLockSFL("/tmp/sdaemon.txt", fmt.Sprintf("\nK: %v\n%v\n", err, os.Environ()))
	return
}
