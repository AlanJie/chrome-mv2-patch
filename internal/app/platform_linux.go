//go:build linux

package app

// Linux host glue: targets /opt/google/chrome (+ -beta, -unstable). There is no
// Restart Manager and no in-place-write lock; writing a running binary fails
// with ETXTBSY, so writeTarget writes a sibling temp file and rename()s it over
// the target atomically. Running instances are found by walking /proc.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"time"
)

func newPlatform() platform { return linuxPlatform{} }

type linuxPlatform struct{}

func (linuxPlatform) terminalCapable() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func (linuxPlatform) isElevated() bool { return os.Geteuid() == 0 }

func (linuxPlatform) elevationHint() string {
	return "root privileges are REQUIRED to modify /opt/google/chrome/chrome.\n" +
		"    Re-run with sudo."
}

type linuxChannel struct{ name, dir string }

var linuxChannels = []linuxChannel{
	{"Stable", "/opt/google/chrome"},
	{"Beta", "/opt/google/chrome-beta"},
	{"Dev", "/opt/google/chrome-unstable"},
}

func (l linuxPlatform) enumerate() []chromeInstall {
	var found []chromeInstall
	for _, ch := range linuxChannels {
		bin := filepath.Join(ch.dir, "chrome")
		if !fileExists(bin) {
			continue
		}
		inst := chromeInstall{channel: ch.name, path: bin}
		l.fillDetails(&inst)
		found = append(found, inst)
	}
	if len(found) == 0 && fileExists("chrome") {
		inst := chromeInstall{channel: "Local file", path: "chrome"}
		l.fillDetails(&inst)
		found = append(found, inst)
	}
	return found
}

func (l linuxPlatform) describe(path string) chromeInstall {
	inst := chromeInstall{path: path}
	l.fillDetails(&inst)
	return inst
}

func (linuxPlatform) fillDetails(inst *chromeInstall) {
	inst.version = chromeVersion(inst.path)
	inst.hasBackup = fileExists(backupPathFor(inst.path))
	holders := procHolders(inst.path)
	inst.holders = len(holders)
	inst.running = inst.holders > 0

	if inst.channel == "" {
		for _, ch := range linuxChannels {
			if filepath.Dir(inst.path) == ch.dir {
				inst.channel = ch.name
				break
			}
		}
		if inst.channel == "" {
			inst.channel = "Unknown"
		}
	}
}

// chromeVersion runs `chrome --version` (display-only; exits before sandbox
// init). Returns "" if it cannot be determined.
func chromeVersion(bin string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "--version").Output()
	if err != nil {
		return ""
	}
	m := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)`).FindStringSubmatch(string(out))
	if m != nil {
		return m[1]
	}
	return ""
}

// procHolders returns the PIDs whose executable is the target binary, by
// walking /proc/<pid>/exe. A running Chrome's browser and renderer processes all
// exec the same binary, so they all appear.
func procHolders(bin string) []int {
	want, err := filepath.EvalSymlinks(bin)
	if err != nil {
		want = bin
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var pids []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		target, err := os.Readlink(filepath.Join("/proc", e.Name(), "exe"))
		if err != nil {
			continue
		}
		// A replaced binary shows up as "<path> (deleted)".
		if target == want || target == bin || target == want+" (deleted)" || target == bin+" (deleted)" {
			pids = append(pids, pid)
		}
	}
	return pids
}

func (linuxPlatform) ensureUnlocked(path string, forceClose bool) bool {
	holders := procHolders(path)
	if len(holders) == 0 {
		return true
	}
	if !forceClose {
		infof("Chrome is running (%d process(es)).", len(holders))
		return false
	}
	warnf("Closing %d running Chrome process(es).", len(holders))
	for _, pid := range holders {
		_ = syscall.Kill(pid, syscall.SIGTERM)
	}
	// Give them a moment; the atomic rename does not require them gone, but a
	// clean close means the new binary is what respawns.
	for i := 0; i < 20; i++ {
		if len(procHolders(path)) == 0 {
			return true
		}
		time.Sleep(250 * time.Millisecond)
	}
	// Still running: the rename will still succeed (old inode stays mapped),
	// so allow the write - the caller warns that a restart is needed.
	return true
}

// writeTarget writes a sibling temp file, fsyncs it, and rename()s it over the
// target. Atomic, sidesteps ETXTBSY, and preserves the path so any AppArmor
// profile keyed on it still applies. Re-applies the target's mode (0755).
func (linuxPlatform) writeTarget(path string, buf []byte) error {
	dir := filepath.Dir(path)
	mode := os.FileMode(0o755)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}

	tmp, err := os.CreateTemp(dir, ".chrome-mv2-*")
	if err != nil {
		return fmt.Errorf("creating temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	if _, err := tmp.Write(buf); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("renaming temp over target: %w", err)
	}
	return nil
}
