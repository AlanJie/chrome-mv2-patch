package app

// Console colour + pre-composed line tags, ported from InitConsoleColors in the
// original C++ patcher. ANSI SGR codes stay empty strings unless the terminal
// actually accepts them, so redirected output and NO_COLOR degrade to the plain
// text this tool has always printed instead of leaking escape bytes.

import (
	"fmt"
	"os"
	"strings"
)

var (
	cReset, cRed, cGrn, cYel, cCyn, cDim, cBold string

	tagOK, tagErr, tagInfo, tagWarn, tagSuccess, tagWarning string
)

// initColors decides whether to emit ANSI codes. On Windows the caller enables
// virtual-terminal processing first (see platform_windows.go); everywhere else
// a TTY on stdout is assumed capable. FORCE_COLOR forces on, NO_COLOR forces
// off (checked last so it always wins).
func initColors(terminalCapable bool) {
	vt := terminalCapable
	if os.Getenv("FORCE_COLOR") != "" {
		vt = true
	}
	if os.Getenv("NO_COLOR") != "" {
		vt = false
	}

	if vt {
		cReset, cRed, cGrn = "\x1b[0m", "\x1b[91m", "\x1b[92m"
		cYel, cCyn, cDim = "\x1b[93m", "\x1b[96m", "\x1b[90m"
		cBold = "\x1b[1m"
	}

	tagOK = cGrn + "[+]" + cReset
	tagErr = cRed + "[-]" + cReset
	tagInfo = cCyn + "[*]" + cReset
	tagWarn = cYel + "[!]" + cReset
	tagSuccess = cBold + cGrn + "[SUCCESS]" + cReset
	tagWarning = cBold + cYel + "[WARNING]" + cReset
}

// infof/okf/warnf/errf/successf mirror the "TAG_* message" prints in the C++.
func printTag(tag, format string, a ...any) {
	fmt.Println(tag + " " + fmt.Sprintf(format, a...))
}

func infof(f string, a ...any)    { printTag(tagInfo, f, a...) }
func okf(f string, a ...any)      { printTag(tagOK, f, a...) }
func warnf(f string, a ...any)    { printTag(tagWarn, f, a...) }
func errf(f string, a ...any)     { printTag(tagErr, f, a...) }
func successf(f string, a ...any) { printTag(tagSuccess, f, a...) }

func rule() {
	fmt.Println(cCyn + "==========================================================" + cReset)
}

func banner() {
	rule()
	fmt.Println(cBold + "        Google Chrome Manifest V2 Patcher (Go)             " + cReset)
	fmt.Println(cDim + "                    v" + appVersion + "                       " + cReset)
	rule()
}

// hexUpper formats bytes the way the C++ candidate dump did: space-separated
// two-digit uppercase, e.g. "83 7A 50 02".
func hexUpper(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02X", x)
	}
	return strings.Join(parts, " ")
}
