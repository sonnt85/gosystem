// Package pid provides structure and helper functions to create and remove
// PID file. A PID file is usually a file used to store the process ID of a
// running process.
package pidfile

import (
	"errors"

	"github.com/sonnt85/gosutils/sexec"
	"github.com/sonnt85/gosystem"
	"github.com/sonnt85/gsjson"

	"os"
	"path/filepath"
	// "github.com/tidwall/gjson"
)

// Pidfile is a file used to store the process ID of a running process.
type Pidfile struct {
	*gsjson.Fjson
}

func (f *Pidfile) validPid(seconnames ...string) (err error) {
	if pid := f.Get("pid").Int(); pid != 0 {
		var ok bool
		if p := gosystem.GetProcessFromPid(pid); p != nil {
			if namePid := f.Get("name").String(); len(namePid) != 0 {
				if ok, err = p.IsRunning(); err == nil && ok {
					name, err := p.Name()
					if err == nil && (name == namePid || (len(seconnames) != 0 && seconnames[0] == namePid)) {
						return nil
					}
				}
			}
			err = errors.New("name error")
		} else {
			err = errors.New("PID does not exist")
		}
	} else {
		err = errors.New("missing pid")
	}
	return
}

//pidi are int or string
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

// New creates a PID file using the specified path.
func NewPidfile(path string, passphrase []byte, progname string, removeIfFileInvalid bool, datas ...map[string]interface{}) (f *Pidfile, err error) {
	f = new(Pidfile)
	var exepath string
	exepath, err = sexec.GetExecPath()
	if err != nil {
		return
	}
	if len(path) == 0 {
		path = filepath.Join(os.TempDir(), filepath.Base(exepath)+".pid")
		f.RmdirFlag = true
	}
	if f.Fjson, err = gsjson.NewFjson(path, passphrase, removeIfFileInvalid, datas...); err == nil {
		if err = f.validPid(progname); err != nil { //check old pid
			err = nil
			pid := os.Getpid()
			f.Set("pid", pid)
			f.Set("name", filepath.Base(exepath))
			return
		} else {
			err = errors.New("the program is still running")
		}
	}
	return
}
