//go:build windows

package app

// Windows host glue: targets chrome.dll under the installed release channels.
// Uses Restart Manager to resolve exactly which channel holds the file (so only
// that channel is closed), an admin-token check for elevation, and VT enabling
// for colour. Zero external dependencies - everything goes through LazyDLL.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func newPlatform() platform { return winPlatform{} }

type winPlatform struct{}

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")
	rstrtmgr = syscall.NewLazyDLL("rstrtmgr.dll")

	procGetStdHandle         = kernel32.NewProc("GetStdHandle")
	procGetConsoleMode       = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode       = kernel32.NewProc("SetConsoleMode")
	procCreateFileW          = kernel32.NewProc("CreateFileW")
	procCloseHandle          = kernel32.NewProc("CloseHandle")
	procOpenProcess          = kernel32.NewProc("OpenProcess")
	procGetProcessTimes      = kernel32.NewProc("GetProcessTimes")
	procTerminateProcess     = kernel32.NewProc("TerminateProcess")
	procWaitForSingleObject  = kernel32.NewProc("WaitForSingleObject")
	procAllocateAndInitSid   = advapi32.NewProc("AllocateAndInitializeSid")
	procCheckTokenMembership = advapi32.NewProc("CheckTokenMembership")
	procFreeSid              = advapi32.NewProc("FreeSid")
	procRmStartSession       = rstrtmgr.NewProc("RmStartSession")
	procRmRegisterResources  = rstrtmgr.NewProc("RmRegisterResources")
	procRmGetList            = rstrtmgr.NewProc("RmGetList")
	procRmEndSession         = rstrtmgr.NewProc("RmEndSession")
)

const (
	stdOutputHandle = ^uintptr(10) // (DWORD)-11
	enableVTP       = 0x0004

	genericRead  = 0x80000000
	genericWrite = 0x40000000
	openExisting = 3
	fileAttrNorm = 0x80

	errSharingViolation = 32
	errLockViolation    = 33

	processTerminate    = 0x0001
	processQueryLimited = 0x1000
	waitTimeoutMs       = 5000

	rmProcessInfoSize = 12 + 2*256 + 2*64 + 4 + 4 + 4 + 4 // sizeof(RM_PROCESS_INFO) = 668
)

func (winPlatform) terminalCapable() bool {
	h, _, _ := procGetStdHandle.Call(stdOutputHandle)
	if h == 0 || h == uintptr(syscall.InvalidHandle) {
		return false
	}
	var mode uint32
	r, _, _ := procGetConsoleMode.Call(h, uintptr(unsafe.Pointer(&mode)))
	if r == 0 {
		return false // stdout is a pipe/file - no colour
	}
	r, _, _ = procSetConsoleMode.Call(h, uintptr(mode|enableVTP))
	return r != 0
}

func (winPlatform) isElevated() bool {
	// AllocateAndInitializeSid(BUILTIN\Administrators) + CheckTokenMembership.
	const securityBuiltinDomainRID = 0x20
	const domainAliasRIDAdmins = 0x220
	var ntAuthority = [6]byte{0, 0, 0, 0, 0, 5} // SECURITY_NT_AUTHORITY
	var adminGroup uintptr

	r, _, _ := procAllocateAndInitSid.Call(
		uintptr(unsafe.Pointer(&ntAuthority[0])), 2,
		securityBuiltinDomainRID, domainAliasRIDAdmins,
		0, 0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&adminGroup)))
	if r == 0 {
		return false
	}
	defer procFreeSid.Call(adminGroup)

	var isMember int32
	r, _, _ = procCheckTokenMembership.Call(0, adminGroup, uintptr(unsafe.Pointer(&isMember)))
	return r != 0 && isMember != 0
}

func (winPlatform) elevationHint() string {
	return "Administrator privileges are REQUIRED to modify chrome.dll in Program Files!\n" +
		"    Re-run from an elevated terminal, or right-click the exe and 'Run as administrator'."
}

// isDllLocked opens the file for write with no sharing; a sharing/lock violation
// means a running process has it mapped (this exact channel). Any other failure
// is a permissions problem, not a running browser.
func isDllLocked(path string) bool {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	h, _, _ := procCreateFileW.Call(
		uintptr(unsafe.Pointer(p)),
		genericRead|genericWrite,
		0, // no sharing
		0, openExisting, fileAttrNorm, 0)
	if h != uintptr(syscall.InvalidHandle) {
		procCloseHandle.Call(h)
		return false
	}
	err = syscall.GetLastError()
	if errno, ok := err.(syscall.Errno); ok {
		return errno == errSharingViolation || errno == errLockViolation
	}
	return false
}

// rmHolder is one process holding the target file, as reported by Restart Manager.
type rmHolder struct {
	pid       uint32
	startTime uint64 // FILETIME as a single 64-bit value
	appName   string
}

// dllHolders resolves the file path to the processes using it via Restart
// Manager (only this channel's processes appear).
func dllHolders(path string) ([]rmHolder, bool) {
	var session uint32
	sessionKey := make([]uint16, 64)
	if r, _, _ := procRmStartSession.Call(
		uintptr(unsafe.Pointer(&session)), 0,
		uintptr(unsafe.Pointer(&sessionKey[0]))); r != 0 {
		return nil, false
	}
	defer procRmEndSession.Call(uintptr(session))

	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, false
	}
	files := []uintptr{uintptr(unsafe.Pointer(p))}
	if r, _, _ := procRmRegisterResources.Call(
		uintptr(session), 1, uintptr(unsafe.Pointer(&files[0])),
		0, 0, 0, 0); r != 0 {
		return nil, false
	}

	var needed, got uint32
	var reason uint32
	procRmGetList.Call(uintptr(session),
		uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&got)),
		0, uintptr(unsafe.Pointer(&reason)))
	if needed == 0 {
		return nil, true
	}

	buf := make([]byte, int(needed)*rmProcessInfoSize)
	got = needed
	if r, _, _ := procRmGetList.Call(uintptr(session),
		uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&got)),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&reason))); r != 0 {
		return nil, false
	}

	var out []rmHolder
	for i := 0; i < int(got); i++ {
		base := i * rmProcessInfoSize
		pid := *(*uint32)(unsafe.Pointer(&buf[base]))
		start := *(*uint64)(unsafe.Pointer(&buf[base+4]))
		// strAppName is a UTF-16 array at offset 12, CCH_RM_MAX_APP_NAME+1 = 256.
		name := utf16zToString(buf[base+12 : base+12+2*256])
		out = append(out, rmHolder{pid: pid, startTime: start, appName: name})
	}
	return out, true
}

// closeHolders force-closes only the processes holding this file, confirming
// each PID still refers to the process RM saw (PIDs recycle) before killing.
func closeHolders(path string) bool {
	holders, _ := dllHolders(path)
	if len(holders) > 0 {
		warnf("Force-closing %d process(es) that hold this chrome.dll.", len(holders))
	}
	for _, h := range holders {
		hProc, _, _ := procOpenProcess.Call(processTerminate|processQueryLimited, 0, uintptr(h.pid))
		if hProc == 0 {
			continue
		}
		var creation, exitT, kernelT, userT uint64
		r, _, _ := procGetProcessTimes.Call(hProc,
			uintptr(unsafe.Pointer(&creation)), uintptr(unsafe.Pointer(&exitT)),
			uintptr(unsafe.Pointer(&kernelT)), uintptr(unsafe.Pointer(&userT)))
		if r != 0 && h.startTime != 0 && creation != h.startTime {
			procCloseHandle.Call(hProc) // recycled PID - not our process
			continue
		}
		if r, _, _ := procTerminateProcess.Call(hProc, 1); r != 0 {
			name := h.appName
			if name == "" {
				name = "process"
			}
			fmt.Printf("    %s Closed %s (PID %d).\n", tagOK, name, h.pid)
			procWaitForSingleObject.Call(hProc, waitTimeoutMs)
		}
		procCloseHandle.Call(hProc)
	}

	// Chrome tears down asynchronously; re-check the file itself.
	for i := 0; i < 20; i++ {
		if !isDllLocked(path) {
			return true
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false
}

func (winPlatform) ensureUnlocked(path string, forceClose bool) bool {
	if !isDllLocked(path) {
		return true
	}
	infof("chrome.dll is in use - this Chrome channel is running.")
	if !forceClose {
		return false
	}
	if closeHolders(path) {
		okf("This channel is closed; other Chrome channels were left running.")
		return true
	}
	return false
}

func (winPlatform) writeTarget(path string, buf []byte) error {
	// The file was unlocked first; a straight truncate-and-write matches the C++
	// (an in-place overwrite - Chrome reopens chrome.dll on next launch).
	return os.WriteFile(path, buf, 0o644)
}

// --- install discovery ------------------------------------------------------

type winChannel struct{ name, subdir string }

var winChannels = []winChannel{
	{"Stable", `Google\Chrome`},
	{"Beta", `Google\Chrome Beta`},
	{"Dev", `Google\Chrome Dev`},
	{"Canary", `Google\Chrome SxS`},
}

func installRoots() []string {
	var roots []string
	for _, v := range []string{"ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"} {
		if val := os.Getenv(v); val != "" {
			roots = append(roots, val)
		}
	}
	return roots
}

// findDllUnderApplication returns the chrome.dll under the highest-numbered
// version subdirectory of an Application dir, or one sitting directly in it.
func findDllUnderApplication(appDir string) string {
	entries, err := os.ReadDir(appDir)
	if err == nil {
		var best string
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			if best == "" || versionLess(best, e.Name()) {
				if fileExists(filepath.Join(appDir, e.Name(), "chrome.dll")) {
					best = e.Name()
				}
			}
		}
		if best != "" {
			return filepath.Join(appDir, best, "chrome.dll")
		}
	}
	direct := filepath.Join(appDir, "chrome.dll")
	if fileExists(direct) {
		return direct
	}
	return ""
}

func (w winPlatform) enumerate() []chromeInstall {
	var found []chromeInstall
	seen := map[string]bool{}
	for _, ch := range winChannels {
		for _, root := range installRoots() {
			dll := findDllUnderApplication(filepath.Join(root, ch.subdir, "Application"))
			if dll == "" {
				continue
			}
			key := strings.ToLower(dll)
			if seen[key] {
				continue
			}
			seen[key] = true
			inst := chromeInstall{channel: ch.name, path: dll}
			w.fillDetails(&inst)
			found = append(found, inst)
		}
	}
	// A chrome.dll dropped next to the patcher stays supported for offline use.
	if len(found) == 0 && fileExists("chrome.dll") {
		inst := chromeInstall{channel: "Local file", path: "chrome.dll"}
		w.fillDetails(&inst)
		found = append(found, inst)
	}
	return found
}

func (w winPlatform) describe(path string) chromeInstall {
	inst := chromeInstall{path: path}
	w.fillDetails(&inst)
	return inst
}

func (winPlatform) fillDetails(inst *chromeInstall) {
	inst.version = dirVersion(inst.path)
	inst.hasBackup = fileExists(backupPathFor(inst.path))

	if holders, ok := dllHolders(inst.path); ok {
		inst.holders = len(holders)
	}
	inst.running = inst.holders > 0 || isDllLocked(inst.path)

	if inst.channel == "" {
		lower := strings.ToLower(inst.path)
		for _, ch := range winChannels {
			if strings.Contains(lower, strings.ToLower(ch.subdir)) {
				inst.channel = ch.name
				break
			}
		}
		if inst.channel == "" {
			inst.channel = "Unknown"
		}
	}
}

// utf16zToString decodes a NUL-terminated little-endian UTF-16 buffer.
func utf16zToString(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		c := uint16(b[i]) | uint16(b[i+1])<<8
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return syscall.UTF16ToString(u)
}
