package app

// Host-OS glue behind one interface, so the patch/restore flow in main is
// OS-agnostic. The Windows implementation (platform_windows.go) targets
// chrome.dll with Restart Manager + elevation; the Linux one (platform_linux.go)
// targets /opt/google/chrome with /proc + atomic rename. Exactly one is built
// per GOOS via build tags, each providing newPlatform().

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// chromeInstall is one installed Chrome release channel. Several channels can be
// installed and running at once, each with its own target file, which is why
// patching one never disturbs the others.
type chromeInstall struct {
	channel   string // "Stable", "Beta", "Dev", "Canary", "Local file", ...
	path      string // chrome.dll (Windows) or chrome (Linux)
	version   string // "" if unreadable
	running   bool   // its target file is in use right now
	holders   int    // processes holding it
	hasBackup bool   // a .bak sits next to it
}

// platform is the set of host-specific operations the flow needs.
type platform interface {
	// isElevated reports admin/root; elevationHint tells the user how to fix it.
	isElevated() bool
	elevationHint() string

	// terminalCapable reports whether stdout can render ANSI colour.
	terminalCapable() bool

	// enumerate scans the host for installed channels, details filled in.
	enumerate() []chromeInstall
	// describe builds an install for an explicit target path, details filled in.
	describe(path string) chromeInstall

	// ensureUnlocked makes the target writable, closing only its own owner.
	// Returns false if it is still locked and the caller should abort.
	ensureUnlocked(path string, forceClose bool) bool

	// writeTarget writes buf to path durably (atomic rename where the platform
	// needs it), preserving ownership/mode as appropriate.
	writeTarget(path string, buf []byte) error
}

// versionSubdir reports the highest version-looking directory name for display,
// used by both platforms when the target lives under a versioned dir. Chrome's
// version equals that directory name, so no resource parsing is needed.
func looksLikeVersion(name string) bool {
	parts := strings.Split(name, ".")
	if len(parts) < 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		if _, err := strconv.Atoi(p); err != nil {
			return false
		}
	}
	return true
}

// versionLess compares two dotted version strings numerically (missing fields
// treated as 0), ported from VersionLess.
func versionLess(a, b string) bool {
	pa := splitVersion(a)
	pb := splitVersion(b)
	for i := 0; i < 4; i++ {
		x, y := 0, 0
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			return x < y
		}
	}
	return false
}

func splitVersion(s string) []int {
	var out []int
	for _, p := range strings.Split(s, ".") {
		n, _ := strconv.Atoi(p)
		out = append(out, n)
	}
	return out
}

// backupPathFor returns the .bak sibling of a target.
func backupPathFor(target string) string {
	return target + ".bak"
}

// copyFile copies src to dst byte-for-byte. Used for backup create/restore;
// plain content copy is enough on both platforms.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}

// fileExists is a small helper used across the flow.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// dirVersion returns the version string implied by a target path's parent
// directory name, or "" - shared fallback for display.
func dirVersion(path string) string {
	parent := filepath.Base(filepath.Dir(path))
	if looksLikeVersion(parent) {
		return parent
	}
	return ""
}
