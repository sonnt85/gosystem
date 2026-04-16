# gosystem

Cross-platform system utilities for Go — process management, file operations, environment handling, privilege elevation, filesystem watching, terminal detection, and PID files.

## Installation

```bash
go get github.com/sonnt85/gosystem
```

## Features

- Process management: find, kill, list, and inspect processes by PID or name; build process trees; send signals to process groups
- File utilities: copy, move, append, write with lock, atomic write-if-changed, symlink creation with data migration
- Filesystem watching (`FsnotifyChange`) with pause/resume, regex file matching, and auto-re-add of watched directories
- Terminal detection (`IsTerminal`, `IsTerminalWriter`) cross-platform including Cygwin
- Environment management: convert to/from maps, merge, add/remove PATH entries
- Goroutine ID retrieval (`GetGoroutineId`)
- Signal handling (`InitSignal`) with exit hooks (`TrapExitAdd`) and zombie reaping
- Home directory and working directory helpers
- Privilege elevation (`DoAsSystem`, `DoAsService`) — Windows: impersonation; non-Windows: no-op
- PID file management (`pidfile` sub-package) — JSON-based, encrypted, with running-process validation
- System actions: `Reboot`, `RestartApp`, `AppIsActive`
- Firewall helpers (`FirewallAddProgram`, `FirewallHasRule`, `FirewallRemoveProgram`) — Windows: netsh; other platforms: no-op
- macOS DMG installer (`InstallDmg`)

## Usage

```go
// Signal handling with exit cleanup
gosystem.TrapExitAdd(func(args ...interface{}) { fmt.Println("bye") })
gosystem.InitSignal(func(s os.Signal) int {
    fmt.Println("got signal:", s)
    return 0
})

// Kill a process tree
gosystem.KillProcessTree(1234)

// Watch files for changes
watcher := gosystem.FsnotifyChange(func(e fsnotify.Event) {
    fmt.Println("changed:", e.Name)
}, false, "/etc/myapp.conf")

// Atomic file write (only writes if content differs)
gosystem.FileWriteBytesIfChange("/tmp/out.txt", []byte("hello"))

// Copy a file preserving timestamps and permissions
gosystem.FileCopy("/src/file", "/dst/file")

// Symlink with automatic data migration
gosystem.SymlinkRelWithInit("/data/real", "/link/path", true, false)

// PID file
pidfile, err := pidfile.NewPidfile("", nil, "myapp", false)
```

## API

### Process

- `GetProcessFromPid(pidi interface{}) *process.Process`
- `GetProcessNameFromPid(pidi interface{}) string`
- `Processes(names ...string) ([]*process.Process, error)` — list/filter by name
- `Pgrep(names ...string) []*process.Process` / `PgrepWithEnv(name, key, val string)`
- `KillPid(pidi interface{}) error` / `KillProcessName(name string, isFullname ...bool) error`
- `KillProcessTree(rootPID int32, signals ...os.Signal) error`
- `GetProcessTree(pid int32) (*ProcessNode, error)` / `PrintProcessTree(node, prefix)`
- `GetAllDescendantPIDs(rootPID int32, ...) ([]int32, error)`
- `GetAllAncestorPIDs(rootPID int32, ...) ([]int32, error)`
- `SendSignalToAllProcess(sig os.Signal, parentPID ...int) []error`
- `SendSignalToSelf(sig os.Signal) error` / `Terminate() error`

### Signals

- `InitSignal(cleanup func(os.Signal) int, handleSIGCHILD ...bool)` — setup signal handler
- `TrapExitAdd(f func(...interface{}))` — register exit hook
- `IsExitSignal(sig os.Signal) bool` / `SignalToInt(sig os.Signal) int`

### Files

- `FileCopy(src, dst string) (int64, error)` / `FileMove(src, dst string) (int64, error)`
- `FileCopyIfDiff(src, dst string) (int64, error)` / `FilesIsEqual(f1, f2 string) (bool, error)`
- `FileWriteBytesIfChange(path string, contents []byte) (bool, error)`
- `WriteToFile(filename string, flag int, data interface{}, perms ...fs.FileMode) error`
- `AppendToFile(filename string, data interface{}) error`
- `WriteTrucFile(name string, contents interface{}) bool`
- `WriteToFileWithLockSFL(filePath string, data interface{}, truncs ...bool) error`
- `TouchFile(name string) error`
- `Symlink(old, new string) error` / `SymlinkRel(old, new string) error`
- `SymlinkRelWithInit(old, new string, force, dstIsFile bool) (string, error)`
- `RemoveAllContents(paths ...string) error`
- `CopyOwnership(src, dst string) error` / `GetFileOwnership(path string) (uid, gid uint32, err error)`

### Filesystem Watcher

- `FsnotifyChange(onChange func(fsnotify.Event), pauseOnCallback bool, files ...string) *Watcher`
- `Watcher.Pause(filePath ...string)` / `Watcher.Continue(filePath ...string)`

### Path / Environment

- `IsTerminal(fd uintptr) bool` / `IsTerminalWriter(w io.Writer) bool`
- `GetHomeDir() string` / `GetWorkingDir() string` / `GetHostname() string` / `GetUsername() string`
- `PathAddDirs(dirs ...string)` / `PathRemoveDirs(dirs ...string)` / `PathList() []string`
- `EnvironmentMap(envstrings ...string) map[string]string`
- `EnvironmentMergeMap(m map[string]string) []string`
- `EnvironmentMapToStrings(m map[string]string) []string`
- `SetAllEnv(env []string)`

### Privilege / System

- `IsCurrentUserRoot() bool` / `IsCurrentUserInSudoGroup() bool`
- `DoAsSystem(f func() error) error` / `DoAsService(serviceName string, f func() error) error`
- `Reboot(delay time.Duration)` / `RestartApp(appName string, delay ...time.Duration) bool`
- `AppIsActive(appName string) bool`
- `Chmod(name string, mode os.FileMode) error`
- `GetGoroutineId() uint64`
- `GetBuildTags() []string` / `BuildHasTags(tags ...string) bool`
- `GetRuntimeCallerInformation(skip ...int) string`

### pidfile sub-package

- `NewPidfile(path string, passphrase []byte, progname string, removeIfInvalid bool, ...) (*Pidfile, error)`
- `PidFileIsRunning(path string, passphrase []byte, progname string) bool`
- `ProcessExists(pidi interface{}) bool`

## License

MIT License - see [LICENSE](LICENSE) for details.
