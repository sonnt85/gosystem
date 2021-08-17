package gosystem

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/sonnt85/gosutils/sexec"
	"github.com/sonnt85/gosutils/shellwords"
)

//func CPULoad() {
//	sexec.ExecCommand()
//}

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
	swargs := shellwords.Join(args...)
	GOOS := runtime.GOOS
	if len(exepath) == 0 {
		exepath, _ = os.Executable()
	}
	if !fullpathflag {
		relpath, _ := filepath.Rel(pwd, exepath)
		if GOOS == "windows" {
			exepath = shellwords.Join(append([]string{relpath}, swargs)...)
			//			exepath = relpath
		} else {
			//			filepath.Join(elem)
			exepath = `sh -c "cd $(dirname %k) && ./` + relpath + " " + swargs + `"`
		}
		//		exepath = filepath.Join(filepath.Dir(exepath), filepath.Base(exepath))
	} else {
		exepath = shellwords.Join(append([]string{exepath}, swargs)...)
	}
	desktopContent := ""
	clickdir = filepath.Join(clickdir, appName)
	if GOOS == "windows" {
		//		if showterminal {
		//			showterminal = true
		//		}
		desktopContent = fmt.Sprintf(`%s`, exepath)
		//WshShell.Run """" & cmdrun & """" & sargs, 0, False
		vbs := fmt.Sprintf(`Set WshShell = CreateObject("WScript.Shell")
WshShell.Run chr(34) & "%s" & Chr(34), 0
Set WshShell = Nothing`, exepath)
		if err1 := ioutil.WriteFile(clickdir+".vbs", []byte(vbs), os.FileMode(0755)); err1 != nil {
			err = err1
		}
		if err1 := ioutil.WriteFile(clickdir+".bat", []byte(desktopContent), os.FileMode(0755)); err1 != nil {
			err = err1
		}
		return
	} else if GOOS == "darwin" {
		//Icon=
		desktopContent = fmt.Sprintf("%s", exepath)
		err = ioutil.WriteFile(clickdir+".command", []byte(desktopContent), os.FileMode(0755))
		return err
	} else {
		//Icon=
		desktopContent = fmt.Sprintf(`[Desktop Entry]
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

func KilPid(pid int) error {
	//	p, err := process.NewProcess(pid) // Specify process id of parent
	//	if err != nil {
	//		return err
	//	}
	p, err := os.FindProcess(pid)
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
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
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
		return string(stdout)
	}
}
