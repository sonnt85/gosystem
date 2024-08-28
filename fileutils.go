package gosystem

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"

	"github.com/sonnt85/gosutils/sutils"
)

func PathIsExist(path string) bool {
	if _, err := os.Stat(path); err == nil {
		return true
	}
	return false
}

func CreateDirectoryIfParentExists(path string, modes ...fs.FileMode) error {
	parentDir := filepath.Dir(path)
	_, err := os.Stat(parentDir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("parent directory does not exist: %s", parentDir)
		}
		return err
	}
	_, err = os.Stat(path)
	if err == nil {
		return nil
	}

	mode := fs.FileMode(0755)
	if len(modes) != 0 {
		mode = modes[0]
	}
	err = os.Mkdir(path, mode)
	if err != nil {
		return fmt.Errorf("failed to create directory: %s", err)
	}

	return nil
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

func FileCloneDateBaseBin(dst string, binnames ...string) (err error) {
	//	var err error
	if len(binnames) == 0 {
		binnames = []string{"echo", "ifconfig", "ip", "cp", "ipconfig", "where", "sh"}
	}
	isw := false
	if file, err := os.OpenFile(dst, os.O_WRONLY, 0666); err == nil {
		isw = true
		file.Close()
	} else {
		if !(os.ErrPermission == err || err == os.ErrNotExist) {
			isw = true
		}
	}
	if isw {
		var p string
		for _, binname := range binnames {
			if p, err = exec.LookPath(binname); err == nil {
				if FileCloneDate(dst, p) {
					return nil
				}
			} else {
				if PathIsExist(binname) {
					if FileCloneDate(dst, binname) {
						return nil
					}
				}
			}
		}
	} else {
		err = os.ErrPermission
	}
	//	log.Errorf("Can not update time for file %s base on ", binnames)
	return err
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

func FileDirGetSize(filePath string) (int64, error) {
	fi, err := os.Stat(filePath)
	if err != nil {
		return 0, err
	}

	if fi.IsDir() {
		var size int64
		err = filepath.Walk(filePath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				size += info.Size()
			}
			return nil
		})
		return size, err
	}

	if !fi.Mode().IsRegular() {
		return 0, nil
	}

	return fi.Size(), nil
}

func FileIsText(filepath string) bool {
	file, err := os.Open(filepath)
	if err != nil {
		return false
	}
	defer file.Close()

	bufferSize := 1024 // Kích thước của mỗi mảng byte
	for {
		buffer := make([]byte, bufferSize)
		n, err := file.Read(buffer)
		if n > 0 {
			for _, b := range buffer[:n] {
				if (b < 0x20 || b > 0x7e) && b != '\n' && b != '\r' && b != '\t' {
					// fmt.Print(b)
					return false
				}
			}
		}
		if err != nil {
			return err == io.EOF
		}
	}
	// return false
}

func FileIsTextAndHasRegexp(file io.ReadSeeker, pattern string) bool {
	// defer file.Close()
	// var r io.Reader
	// switch v := filepath.(type) {
	// case []byte:
	// 	r = bytes.NewBuffer(v)
	// case string:
	// 	r = bytes.NewBufferString(v)
	// case io.Reader:
	// 	r = v
	// default:
	// 	return false
	// }
	defer file.Seek(0, 0)
	bufferSize := 1024 // Kích thước của mỗi mảng byte
	for {
		buffer := make([]byte, bufferSize)
		n, err := file.Read(buffer)
		if n > 0 {
			for _, b := range buffer[:n] {
				if (b < 0x20 || b > 0x7e) && b != '\n' && b != '\r' && b != '\t' {
					// fmt.Print(b)
					return false
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				file.Seek(0, 0)
				scanner := bufio.NewScanner(file)
				if re, e := regexp.Compile(pattern); e == nil {
					for scanner.Scan() {
						line := scanner.Text()
						if re.MatchString(line) {
							return true
						}
					}
				}
				// sregexp.New(pattern)
			}
			return false
		}
	}
	// return false
}

func BytesIsText(buffer []byte) bool {
	for _, b := range buffer {
		if (b < 0x20 || b > 0x7e) && b != '\n' && b != '\r' && b != '\t' {
			return false
		}
	}
	return true
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
