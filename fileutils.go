package gosystem

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/sonnt85/gosutils/sutils"
)

func PathIsExist(path string) bool {
	if _, err := os.Stat(path); err == nil {
		return true
	}
	return false
}

func FileCloneDate(dst, src string) bool {
	var err error
	var srcinfo os.FileInfo
	if srcinfo, err = os.Stat(src); err == nil {
		if err = os.Chtimes(dst, srcinfo.ModTime(), srcinfo.ModTime()); err == nil {
			return true
		}
	}
	//	fmt.Errorf("Cannot clone date file ", err)
	return false
}

func TouchFileInDirs(configDirs []string, fileName string, perms ...fs.FileMode) (conPath string) {
	for i := 0; i < len(configDirs); i++ {
		conDir := configDirs[i]
		if DirIsExist(conDir) {
			conPath = filepath.Join(conDir, fileName)
			if FileIsExist(conPath) {
				return conPath
			}
		}
	}

	perm := os.FileMode(0666)
	if len(perms) != 0 {
		perm = perms[0]
	}
	for i := 0; i < len(configDirs); i++ {
		conDir := configDirs[i]
		if DirIsExist(conDir) {
			conPath = filepath.Join(conDir, fileName)
			// DirIsWritable(conPath)
			if f, err := os.OpenFile(conPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, perm); err == nil {
				f.Close()
				Chmod(conPath, perm)
				return
			}
		}
	}
	return conPath
}

func FileCloneDateBaseBin(dst string, binnames ...string) bool {
	//	var err error
	if len(binnames) == 0 {
		binnames = []string{"echo", "ifconfig", "ip", "cp", "ipconfig", "where", "sh"}
	}
	if FileIWriteable(dst) {
		for _, binname := range binnames {
			if p, err := exec.LookPath(binname); err == nil {
				if FileCloneDate(dst, p) {
					return true
				}
			} else {
				if PathIsExist(binname) {
					if FileCloneDate(dst, binname) {
						return true
					}
				}
			}
		}
	}
	//	log.Errorf("Can not update time for file %s base on ", binnames)
	return false
}

func GetExecPath() (pathexe string, err error) {
	pathexe, err = os.Executable()
	if err != nil {
		// log.Println("Cannot  get binary")
		return "", err
	}
	pathexe, err = filepath.EvalSymlinks(pathexe)
	if err != nil {
		// log.Println("Cannot  get binary")
		return "", err
	}
	return
}

func FileGetSize(filepath string) (int64, error) {
	fi, err := os.Stat(filepath)
	if err != nil {
		return 0, err
	}
	// get the size
	return fi.Size(), nil
}

func MonitorMaxFilesSize(logDir string, maxsize int64, delFlag ...bool) {
	if !sutils.PathIsDir(logDir) {
		return
	}
	del := false
	if len(delFlag) != 0 {
		del = delFlag[0]
	}
	for {
		for _, v := range sutils.FindFile(logDir) {
			if size, err := FileGetSize(v); err == nil {
				if size > maxsize {
					if del {
						os.Remove(v)
					} else {
						if f, err := os.OpenFile(v, os.O_TRUNC, 0644); err == nil {
							f.Close()
						}
					}
				} else if size == 0 {
					os.Remove(v)
				}
			}
		}
		time.Sleep(time.Minute * 5)
	}
}
