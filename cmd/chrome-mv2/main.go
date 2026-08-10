// Command chrome-mv2 re-enables Manifest V2 extension support in Google Chrome
// by flipping the inlined IsExtensionAffected manifest-version checks in the
// browser binary (chrome.dll on Windows, the ELF on Linux).
//
// This is a thin entry point; all behaviour lives in internal/app.
package main

import (
	"os"

	"chrome-mv2-patch/internal/app"
)

func main() {
	os.Exit(app.Run(os.Args[1:]))
}
