package app

// Package app is the OS-agnostic core of the Chrome MV2 patcher: the patch /
// restore orchestration (ported from wmain() in the original C++ patcher), the
// signature engine, and the PE/ELF image layer. The cmd/chrome-mv2 entry point
// is a thin wrapper around Run.
//
// One binary, two subcommands:
//
//	chrome-mv2 patch   [path]   flip the MV2 gates (default command)
//	chrome-mv2 restore [path]   restore the target from its .bak
//
// With no path, installed channels are listed so you can pick one. Fetching
// debug symbols for porting is a separate tool: scripts/fetch_symbols.py.

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

const appVersion = "1.1.0"

var (
	quiet   bool
	plat    platform
	pauseFn = defaultPause
)

// Run parses argv (without the program name) and returns a process exit code.
func Run(argv []string) int {
	plat = newPlatform()
	initColors(plat.terminalCapable())

	// Split off the subcommand (default "patch" for back-compat with the
	// single-purpose exe) and parse the rest.
	cmd := "patch"
	if len(argv) > 0 {
		switch argv[0] {
		case "patch", "restore":
			cmd = argv[0]
			argv = argv[1:]
		}
	}

	var (
		targetPath string
		assumeYes  bool
	)
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		switch {
		case arg == "--yes" || arg == "-y":
			assumeYes = true
		case arg == "--quiet" || arg == "-q":
			quiet = true
		case arg == "--version" || arg == "-v":
			fmt.Println("chrome-mv2-patch " + appVersion)
			return 0
		case arg == "--help" || arg == "-h" || arg == "/?":
			printUsage()
			return 0
		case strings.HasPrefix(arg, "-"):
			errf("Unknown option: %s", arg)
			printUsage()
			return 2
		default:
			targetPath = arg
		}
	}

	banner()

	if !plat.isElevated() && os.Getenv("MV2_TEST_NO_ELEVATION") == "" {
		return fail(tagWarn + " " + plat.elevationHint())
	}

	interactive := !quiet
	target, ok := resolveTarget(targetPath, interactive)
	if !ok {
		return fail("")
	}

	fmt.Printf("%s Target channel: %s%s%s\n", tagOK, cCyn, target.channel, cReset)
	fmt.Printf("%s Target file: %s\n", tagOK, target.path)
	if target.version != "" {
		fmt.Printf("%s Chrome version detected: %s\n", tagOK, target.version)
	}

	switch cmd {
	case "restore":
		return doRestore(target, assumeYes)
	default:
		return doPatch(target, assumeYes)
	}
}

// resolveTarget produces the install to act on, from an explicit path or by
// scanning + prompting. Returns ok=false if nothing was selected.
func resolveTarget(targetPath string, interactive bool) (chromeInstall, bool) {
	if targetPath != "" {
		if !fileExists(targetPath) {
			errf("Error: the given path does not exist.")
			return chromeInstall{}, false
		}
		return plat.describe(targetPath), true
	}

	infof("Scanning for installed Chrome release channels...")
	installs := plat.enumerate()
	if len(installs) == 0 {
		if !interactive {
			errf("Error: no installed Chrome channel was found.")
			fmt.Println("    Pass the path explicitly, e.g. chrome-mv2 patch /path/to/chrome[.dll]")
			return chromeInstall{}, false
		}
		// Nothing auto-found (e.g. a loose 32-bit chrome.dll outside the standard
		// install roots): let the user point at it directly instead of erroring.
		warnf("No installed Chrome channel was found.")
		if pick := promptCustomPath(); pick != nil {
			return *pick, true
		}
		infof("No path entered - nothing was changed.")
		return chromeInstall{}, false
	}
	if !interactive && len(installs) > 1 {
		errf("%d channels are installed and --quiet cannot prompt.", len(installs))
		for i := range installs {
			printInstallRow(i+1, installs[i])
		}
		fmt.Println("    Re-run with the path of the channel you want.")
		return chromeInstall{}, false
	}
	if !interactive {
		return installs[0], true
	}
	picked := chooseInstall(installs)
	if picked == nil {
		infof("No channel selected - nothing was changed.")
		return chromeInstall{}, false
	}
	return *picked, true
}

// consentToClose reproduces the running-channel gate: --yes force-closes,
// --quiet cannot prompt (so it errors), otherwise the user confirms.
func consentToClose(target chromeInstall, assumeYes bool) bool {
	if !target.running {
		return true
	}
	if assumeYes {
		warnf("Chrome %s is running and will be force closed (--yes).", target.channel)
		return true
	}
	if quiet {
		errf("Chrome %s is running (%d process(es)).", target.channel, target.holders)
		fmt.Println("    Close it, or pass --yes to force close it.")
		return false
	}
	return confirmForceClose(target)
}

func doRestore(target chromeInstall, assumeYes bool) int {
	infof("Restore mode requested...")
	backupPath := backupPathFor(target.path)
	if !fileExists(backupPath) {
		return fail(tagErr + " Error: backup file " + backupPath + " does not exist.")
	}
	if !consentToClose(target, assumeYes) {
		return fail("")
	}
	if !plat.ensureUnlocked(target.path, true) {
		return fail(tagErr + " Target is still locked and no owning process could be closed.\n" +
			"    Close this Chrome channel manually and re-run.")
	}
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return fail(tagErr + " Error reading backup: " + err.Error())
	}
	if err := plat.writeTarget(target.path, data); err != nil {
		return fail(tagErr + " Error restoring file: " + err.Error())
	}
	successf("Original binary successfully restored from backup!")
	return fail("")
}

func doPatch(target chromeInstall, assumeYes bool) int {
	if !consentToClose(target, assumeYes) {
		return fail("")
	}
	if !plat.ensureUnlocked(target.path, true) {
		return fail(tagErr + " Target is still locked and no owning process could be closed.\n" +
			"    Close this Chrome channel manually and re-run. Other channels can stay open.")
	}

	buf, err := os.ReadFile(target.path)
	if err != nil {
		return fail(tagErr + " Error: failed to read the target file: " + err.Error())
	}
	if len(buf) == 0 {
		return fail(tagErr + " Error: the target file is empty.")
	}
	okf("Loaded %d bytes from %s.", len(buf), target.path)

	img, err := openImage(buf)
	if err != nil {
		return fail(tagErr + " Error: " + err.Error())
	}

	// Smart backup management, ported from wmain.
	backupPath := backupPathFor(target.path)
	if !fileExists(backupPath) {
		infof("Creating initial backup copy: %s ...", backupPath)
		if err := copyFile(target.path, backupPath); err != nil {
			return fail(tagErr + " Error creating backup file: " + err.Error())
		}
		okf("Initial backup created successfully.")
	} else if img.isLikelyStock(buf) {
		infof("Unpatched stock detected - refreshing %s ...", backupPath)
		_ = copyFile(target.path, backupPath)
		okf("Backup updated to latest stock version.")
	} else {
		infof("Previously patched binary detected. Restoring clean stock from backup before re-patching...")
		if data, err := os.ReadFile(backupPath); err == nil {
			buf = data
			if img, err = openImage(buf); err != nil {
				return fail(tagErr + " Error: restored backup is not a valid image: " + err.Error())
			}
			okf("Restored clean stock into memory buffer.")
		} else {
			warnf("Backup restore failed (%v). Attempting idempotent re-patch of the existing file...", err)
		}
	}

	patch, ok := patchImage(buf, img)
	if !ok {
		return fail(tagWarning + " No patches were applied.")
	}

	if err := plat.writeTarget(target.path, buf); err != nil {
		return fail(tagErr + " Error: failed to write patched bytes: " + err.Error() + "\n" +
			"    Make sure you ran this elevated (admin / sudo).")
	}

	infof("Verifying patched binary on disk...")
	if err := verifyOnDisk(target.path, patch); err != nil {
		return fail(tagErr + " On-disk verification FAILED (" + err.Error() + "). Revert with: chrome-mv2 restore")
	}

	reportOutcome(patch)
	return fail("")
}

// patchImage runs the milestone engine for the image's format, prints the
// decline path when nothing matches, and returns (result, applied?).
func patchImage(buf []byte, img Image) (patchResult, bool) {
	all, err := loadMilestones()
	if err != nil {
		errf("Error: %v", err)
		return patchResult{}, false
	}
	ms := milestonesForContainer(all, img.format())
	t := img.text()

	infof("Starting MV2 patching (ManifestV2Handler architecture, %s target)...", strings.ToUpper(img.format()))
	if len(ms) == 0 {
		warnf("No %s milestone signatures are known yet - declining (nothing modified).", strings.ToUpper(img.format()))
		if img.format() == "elf" {
			fmt.Println("    The Linux gate table has not been derived yet; see mv2-reversing.md.")
		}
		reportLayoutCandidates(buf, t.rva, t.raw, t.size)
		return patchResult{}, false
	}

	infof("Probing for a known Chrome layout (%d milestone table(s))...", len(ms))
	res := patchMilestones(buf, t.rva, t.raw, t.size, ms)
	if res.status == 0 {
		reportLayoutCandidates(buf, t.rva, t.raw, t.size)
		warnf("No known MV2 layout matched this binary.")
		fmt.Println("    Chrome likely shifted its layout (new milestone or different codegen).")
		fmt.Println("    Nothing was modified. See 'Porting to a new Chrome version' in the")
		fmt.Println("    mv2-reversing.md notes and add a milestone to signatures.json (next to the exe).")
		return patchResult{}, false
	}

	infof("Chrome %s %s", res.milestone, map[bool]string{true: "applied.", false: "all sites already patched (no change needed)."}[res.status == 1])

	if err := img.finalize(buf); err != nil {
		errf("Error finalizing image: %v", err)
		return patchResult{}, false
	}
	return res, true
}

// verifyOnDisk re-reads the written file and confirms the format fixups and
// every flipped site, ported from VerifyPatchedFile.
func verifyOnDisk(path string, patch patchResult) error {
	buf, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("could not re-open patched file")
	}
	img, err := openImage(buf)
	if err != nil {
		return fmt.Errorf("patched file is not a valid image on disk")
	}
	if err := img.verifyFinalize(buf); err != nil {
		return err
	}
	t := img.text()
	for _, wp := range patch.written {
		raw := uint64(t.raw) + uint64(wp.rva-t.rva)
		if raw+uint64(len(wp.bytes)) > uint64(len(buf)) ||
			!equalBytes(buf[raw:raw+uint64(len(wp.bytes))], wp.bytes) {
			return fmt.Errorf("site RVA 0x%X does not match the expected patch on disk", wp.rva)
		}
		okf("Verification: patch site RVA 0x%X confirmed on disk.", wp.rva)
	}
	return nil
}

func reportOutcome(patch patchResult) {
	rule()
	if patch.full {
		successf("Binary successfully patched and verified on disk!")
		fmt.Printf("          Manifest V2 extension support re-enabled (Chrome %s layout).\n", patch.milestone)
	} else {
		fmt.Printf("%s Binary was PARTIALLY patched (Chrome %s layout, %d/%d gates).\n",
			tagWarning, patch.milestone, patch.located, patch.total)
		fmt.Println("          The flips found were written and verified on disk, but")
		fmt.Printf("          %d gate(s) were not located, so MV2 may STILL be blocked.\n", patch.total-patch.located)
		fmt.Println("          Please report the exact version. Revert with: chrome-mv2 restore")
	}
	rule()
}

// --- interactive prompts ----------------------------------------------------

func printInstallRow(index int, inst chromeInstall) {
	fmt.Printf("  %s%d)%s %s%s%s", cBold, index, cReset, cCyn, inst.channel, cReset)
	if inst.version != "" {
		fmt.Printf("  %s", inst.version)
	}
	if inst.running {
		fmt.Printf("  %s[RUNNING", cYel)
		if inst.holders > 0 {
			fmt.Printf(", %d process(es)", inst.holders)
		}
		fmt.Printf("]%s", cReset)
	} else {
		fmt.Printf("  %s[not running]%s", cGrn, cReset)
	}
	if inst.hasBackup {
		fmt.Printf(" %s(backup present)%s", cDim, cReset)
	}
	fmt.Printf("\n      %s%s%s\n", cDim, inst.path, cReset)
}

func chooseInstall(installs []chromeInstall) *chromeInstall {
	if len(installs) == 1 {
		okf("One Chrome channel found:")
		printInstallRow(1, installs[0])
	} else {
		fmt.Printf("\n%s %d Chrome release channels found:\n", tagInfo, len(installs))
		for i := range installs {
			printInstallRow(i+1, installs[i])
		}
		fmt.Printf("\n%s Only the channel you pick is modified; the others keep running.\n", tagInfo)
	}

	reader := bufio.NewReader(os.Stdin)
	for {
		if len(installs) == 1 {
			fmt.Printf("%s\nPatch this channel? [Enter=yes, c=custom path, q=quit]: %s", cBold, cReset)
		} else {
			fmt.Printf("%s\nWhich channel do you want to patch? [1-%d, c=custom path, q=quit]: %s", cBold, len(installs), cReset)
		}
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			return nil
		}
		line = strings.TrimSpace(line)
		switch {
		case line == "q" || line == "Q":
			return nil
		case line == "c" || line == "C":
			if pick := promptCustomPath(); pick != nil {
				return pick
			}
			continue // custom entry cancelled - fall back to the list
		case len(installs) == 1 && line == "":
			return &installs[0]
		}
		if n := atoiSafe(line); n >= 1 && n <= len(installs) {
			return &installs[n-1]
		}
		if len(installs) == 1 {
			errf("Press Enter to accept, c for a custom path, or q to quit.")
		} else {
			errf("Enter a number between 1 and %d, c for a custom path, or q to quit.", len(installs))
		}
	}
}

// promptCustomPath asks for an explicit chrome.dll (or chrome) path and returns
// the described install, or nil if the user entered nothing. Surrounding quotes
// are stripped so a path pasted from Explorer ("C:\...\chrome.dll") works as-is.
func promptCustomPath() *chromeInstall {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("%s\nEnter the full path to chrome.dll (or chrome), blank to cancel: %s", cBold, cReset)
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			return nil
		}
		path := strings.TrimSpace(line)
		path = strings.TrimSpace(strings.Trim(path, "\"'"))
		if path == "" {
			return nil
		}
		if !fileExists(path) {
			errf("No file at that path. Try again, or leave blank to cancel.")
			continue
		}
		inst := plat.describe(path)
		return &inst
	}
}

func confirmForceClose(inst chromeInstall) bool {
	fmt.Printf("\n%s%s  !! WARNING: Chrome %s is running !!%s\n", cBold, cYel, inst.channel, cReset)
	fmt.Printf("     Close it now to patch cleanly. If you continue, its %d process(es)\n", inst.holders)
	fmt.Println("     will be FORCE CLOSED and any unsaved tabs or downloads are lost.")
	fmt.Printf("     %sOther Chrome channels are unaffected either way.%s\n", cDim, cReset)

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("%s\nForce close Chrome %s and patch? [y/N]: %s", cBold, inst.channel, cReset)
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			return false
		}
		line = strings.TrimSpace(line)
		if line == "y" || line == "Y" {
			return true
		}
		if line == "" || line == "n" || line == "N" {
			infof("Cancelled - nothing was changed.")
			return false
		}
	}
}

// fail prints an optional message, pauses (unless --quiet), and returns 1.
// A bare fail("") is the success/quiet exit: just pause.
func fail(msg string) int {
	if msg != "" {
		fmt.Println(msg)
	}
	pauseFn()
	if msg == "" {
		return 0
	}
	return 1
}

func defaultPause() {
	if quiet {
		return
	}
	fmt.Println("\nPress Enter to exit...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

func printUsage() {
	fmt.Print(`Usage: chrome-mv2 <command> [path] [options]

Re-enables Manifest V2 extension support in Google Chrome by flipping the
inlined IsExtensionAffected manifest-version checks (Chrome 151 / 152 on
Windows, 32-bit and 64-bit; point releases relocate cleanly). With no path,
installed channels are listed so you can pick one - or choose 'c' at the prompt
to enter any chrome.dll path yourself (e.g. a copy outside the standard install
folders).

Commands:
  patch [path]           Flip the MV2 gates (default if omitted).
  restore [path]         Restore the target binary from its .bak.

Options:
  -y, --yes              Force close a running Chrome without asking.
  -q, --quiet            Do not pause for 'Press Enter' on exit (for scripting).
  -v, --version          Print the tool version and exit.
  -h, --help             Show this help and exit.

Porting to a new Chrome version (fetch symbols + derive signatures) is done with
the scripts in scripts/ - start with: python scripts/fetch_symbols.py <binary>
`)
}

// --- small helpers ----------------------------------------------------------

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return -1
		}
		n = n*10 + int(c-'0')
	}
	if s == "" {
		return -1
	}
	return n
}
