#define NOMINMAX
#include <windows.h>
#include <restartmanager.h>
#include <shlobj.h>
#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <cwctype>

// ---------------------------------------------------------------------------
// Patcher version — the single source of truth. build.bat parses these exact
// "#define APP_VER_* <n>" lines to stamp the Windows VERSIONINFO resource and to
// name the release .zip, so keep this literal form (one number per line).
// ---------------------------------------------------------------------------
#define APP_VER_MAJOR 1
#define APP_VER_MINOR 0
#define APP_VER_PATCH 1
#define APP_VER_BUILD 0
#define APP_STRINGIZE2(s) #s
#define APP_STRINGIZE(s)  APP_STRINGIZE2(s)
#define APP_VERSION_STR \
    APP_STRINGIZE(APP_VER_MAJOR) "." APP_STRINGIZE(APP_VER_MINOR) "." APP_STRINGIZE(APP_VER_PATCH)

// Elevation is requested via /MANIFESTUAC on the LINK command line in
// build.bat (the #pragma comment(linker,...) form is silently rejected by
// LINK with LNK4229 and the exe falls back to asInvoker).

// ============================================================================
// Console colour
//
// ANSI SGR sequences, switched on through the Windows 10+ virtual-terminal
// console mode. Every code below stays an empty string unless the console
// actually accepted VT processing, so redirected output (`> log.txt`, a CI
// pipe) and the NO_COLOR convention both degrade to the plain text this tool
// has always printed instead of leaking escape bytes.
// ============================================================================
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

static std::string  C_RESET, C_RED, C_GRN, C_YEL, C_CYN, C_DIM, C_BOLD;
static std::wstring W_RESET, W_RED, W_GRN, W_YEL, W_CYN, W_DIM, W_BOLD;

// Pre-composed line tags. Nearly every line of output starts with one of
// these, so the colour lives in the tag and the message text in the source
// stays plain and greppable.
static std::string  TAG_OK, TAG_ERR, TAG_INFO, TAG_WARN, TAG_SUCCESS, TAG_WARNING;
static std::wstring WTAG_OK, WTAG_ERR, WTAG_INFO, WTAG_WARN;

static void InitConsoleColors() {
    // GetConsoleMode fails when stdout is a pipe or a file, which is exactly
    // the case where escape codes would render as garbage.
    bool vt = false;
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (hOut != INVALID_HANDLE_VALUE && GetConsoleMode(hOut, &mode)) {
        vt = SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;
    }
    // FORCE_COLOR keeps colour on when stdout is a pipe - for piping into a
    // pager that understands ANSI.
    if (GetEnvironmentVariableW(L"FORCE_COLOR", NULL, 0) != 0) vt = true;
    // https://no-color.org - any value at all means "no colour". Checked last
    // so it always wins.
    if (GetEnvironmentVariableW(L"NO_COLOR", NULL, 0) != 0) vt = false;

    if (vt) {
        C_RESET = "\x1b[0m";  C_RED  = "\x1b[91m"; C_GRN = "\x1b[92m";
        C_YEL   = "\x1b[93m"; C_CYN  = "\x1b[96m"; C_DIM = "\x1b[90m";
        C_BOLD  = "\x1b[1m";
        W_RESET = L"\x1b[0m";  W_RED  = L"\x1b[91m"; W_GRN = L"\x1b[92m";
        W_YEL   = L"\x1b[93m"; W_CYN  = L"\x1b[96m"; W_DIM = L"\x1b[90m";
        W_BOLD  = L"\x1b[1m";
    }

    TAG_OK      = C_GRN  + "[+]" + C_RESET;
    TAG_ERR     = C_RED  + "[-]" + C_RESET;
    TAG_INFO    = C_CYN  + "[*]" + C_RESET;
    TAG_WARN    = C_YEL  + "[!]" + C_RESET;
    TAG_SUCCESS = C_BOLD + C_GRN + "[SUCCESS]" + C_RESET;
    TAG_WARNING = C_BOLD + C_YEL + "[WARNING]" + C_RESET;
    WTAG_OK     = W_GRN + L"[+]" + W_RESET;
    WTAG_ERR    = W_RED + L"[-]" + W_RESET;
    WTAG_INFO   = W_CYN + L"[*]" + W_RESET;
    WTAG_WARN   = W_YEL + L"[!]" + W_RESET;
}

// ============================================================================
// Helper: Check if current process has Administrator privileges
// ============================================================================
static bool IsElevatedAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin == TRUE;
}

// ============================================================================
// Helper: Is this exact chrome.dll locked by a running process?
//
// Chrome installs each channel (Stable / Beta / Dev / Canary) under its own
// root with its own chrome.dll, but every channel's process is named
// "chrome.exe". Matching on the process name therefore cannot tell the
// channels apart, so this asks the filesystem about the one file we are
// about to modify instead: open it for write with no sharing. If some
// process has it mapped, the open fails and only that channel is affected;
// every other channel keeps running untouched.
//
// Only a sharing/lock violation counts as "locked". Any other failure -
// ERROR_ACCESS_DENIED from a non-elevated run or a read-only attribute - is a
// permissions problem, not a running browser, and must not be reported as one.
// ============================================================================
static bool IsDllLocked(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
                           0 /* no sharing */, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
        return false;
    }
    DWORD err = GetLastError();
    return err == ERROR_SHARING_VIOLATION || err == ERROR_LOCK_VIOLATION;
}

// ============================================================================
// Helper: which processes are holding THIS chrome.dll?
//
// Restart Manager resolves a *file path* to the processes using it, so the PIDs
// it returns are exactly the channel that owns this file - its browser,
// renderer and crashpad processes. Other channels never appear in the list.
// This call only asks, so the channel picker can label what is running before
// the user commits to closing anything.
// ============================================================================
static bool GetDllHolders(const std::wstring& path,
                          std::vector<RM_PROCESS_INFO>& out) {
    out.clear();
    DWORD session = 0;
    WCHAR sessionKey[CCH_RM_SESSION_KEY + 1] = { 0 };
    if (RmStartSession(&session, 0, sessionKey) != ERROR_SUCCESS) return false;

    bool ok = false;
    LPCWSTR files[1] = { path.c_str() };
    if (RmRegisterResources(session, 1, files, 0, NULL, 0, NULL) == ERROR_SUCCESS) {
        // Two passes: RmGetList reports how many holders exist, then we size
        // the buffer to match and ask again.
        UINT needed = 0, got = 0;
        DWORD reason = 0;
        RmGetList(session, &needed, &got, NULL, &reason);
        if (needed == 0) {
            ok = true;
        } else {
            std::vector<RM_PROCESS_INFO> info(needed);
            got = needed;
            if (RmGetList(session, &needed, &got, info.data(), &reason) == ERROR_SUCCESS) {
                info.resize(got);
                out.swap(info);
                ok = true;
            }
        }
    }

    RmEndSession(session);
    return ok;
}

// ============================================================================
// Helper: Close only the Chrome instance holding THIS chrome.dll. Every other
// installed channel keeps running. Returns true if the file is free afterwards.
// ============================================================================
static bool CloseHoldersOfDll(const std::wstring& path) {
    std::vector<RM_PROCESS_INFO> holders;
    GetDllHolders(path, holders);

    if (!holders.empty()) {
        std::wcout << WTAG_WARN << L" Force-closing " << holders.size()
                   << L" process(es) that hold this chrome.dll." << std::endl;
    }
    for (const RM_PROCESS_INFO& h : holders) {
        DWORD pid = h.Process.dwProcessId;
        HANDLE hProc = OpenProcess(
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProc == NULL) continue;

        // A PID is recycled aggressively on Windows; confirm this handle still
        // refers to the process RM saw before terminating anything.
        FILETIME created, exitT, kernelT, userT;
        if (GetProcessTimes(hProc, &created, &exitT, &kernelT, &userT) &&
            CompareFileTime(&created, &h.Process.ProcessStartTime) != 0) {
            CloseHandle(hProc);
            continue;
        }
        if (TerminateProcess(hProc, 1)) {
            std::wcout << L"    " << WTAG_OK << L" Closed " << h.strAppName
                       << L" (PID " << pid << L")." << std::endl;
            WaitForSingleObject(hProc, 5000);
        }
        CloseHandle(hProc);
    }

    // Chrome tears down asynchronously; give the handles a moment to drop and
    // re-check the file itself rather than trusting the kill loop.
    for (int i = 0; i < 20; ++i) {
        if (!IsDllLocked(path)) return true;
        Sleep(250);
    }
    return false;
}

// ============================================================================
// Ensure the target chrome.dll is writable, closing only its own channel.
// Returns false if it is still locked and the caller should abort.
// ============================================================================
static bool EnsureDllUnlocked(const std::wstring& path) {
    if (!IsDllLocked(path)) return true;

    std::cout << TAG_INFO << " chrome.dll is in use - this Chrome channel is running." << std::endl;
    if (CloseHoldersOfDll(path)) {
        std::cout << TAG_OK << " This channel is closed; other Chrome channels were left running."
                  << std::endl;
        return true;
    }
    return false;
}

// ============================================================================
// Helper: Locate Chrome installation directory containing chrome.dll
// ============================================================================
static bool VersionLess(const std::wstring& a, const std::wstring& b) {
    auto split = [](const std::wstring& s) {
        std::vector<int> v;
        size_t start = 0;
        for (size_t i = 0; i <= s.size(); ++i) {
            if (i == s.size() || s[i] == L'.') {
                v.push_back(_wtoi(s.substr(start, i - start).c_str()));
                start = i + 1;
            }
        }
        return v;
    };
    std::vector<int> va = split(a), vb = split(b);
    for (size_t i = 0; i < 4; ++i) {
        int x = i < va.size() ? va[i] : 0;
        int y = i < vb.size() ? vb[i] : 0;
        if (x != y) return x < y;
    }
    return false;
}

// Defined further down; the channel scan needs it to label each install.
static std::wstring GetFileVersion(const std::wstring& path);

// One installed Chrome release channel. All four can be installed and running
// at the same time, each with its own chrome.dll, which is why patching one
// never disturbs the others.
struct ChromeInstall {
    std::wstring channel;            // "Stable", "Beta", "Dev", "Canary", ...
    std::wstring dllPath;
    std::wstring version;            // chrome.dll file version, "" if unreadable
    bool         running = false;    // its chrome.dll is locked right now
    size_t       holders = 0;        // processes holding it, per Restart Manager
    bool         hasBackup = false;  // a chrome.dll.bak sits next to it
};

// Channel display name -> install directory, relative to an install root.
static const struct { const wchar_t* name; const wchar_t* subdir; } kChannels[] = {
    { L"Stable", L"Google\\Chrome"      },
    { L"Beta",   L"Google\\Chrome Beta" },
    { L"Dev",    L"Google\\Chrome Dev"  },
    { L"Canary", L"Google\\Chrome SxS"  },
};

// Given "...\Google\Chrome\Application", return the chrome.dll under the
// highest-numbered version subdirectory (or a chrome.dll sitting directly in
// Application), or "" if none is found. Shared by every install root.
static std::wstring FindDllUnderApplication(const std::wstring& appDir) {
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW((appDir + L"\\*").c_str(), &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        std::wstring best;
        do {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (best.empty() || VersionLess(best, findData.cFileName)) {
                    best = findData.cFileName;
                }
            }
        } while (FindNextFileW(hFind, &findData));
        FindClose(hFind);
        if (!best.empty()) {
            std::wstring dllPath = appDir + L"\\" + best + L"\\chrome.dll";
            if (GetFileAttributesW(dllPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
                return dllPath;
            }
        }
    }
    std::wstring direct = appDir + L"\\chrome.dll";
    if (GetFileAttributesW(direct.c_str()) != INVALID_FILE_ATTRIBUTES) {
        return direct;
    }
    return L"";
}

static std::wstring ToLower(std::wstring s) {
    for (wchar_t& c : s) c = towlower(c);
    return s;
}

// Fill in everything that needs a file or a Restart Manager query. Used for
// both scanned channels and an explicitly supplied path, so the status shown
// and the confirmation asked for are identical either way.
static void FillInstallDetails(ChromeInstall& inst) {
    inst.version = GetFileVersion(inst.dllPath);
    inst.hasBackup =
        GetFileAttributesW((inst.dllPath + L".bak").c_str()) != INVALID_FILE_ATTRIBUTES;

    // Restart Manager is the source of truth for "is this channel running": it
    // resolves the file to its holding PIDs without needing write access, so
    // the status is right whether or not this run is elevated.
    std::vector<RM_PROCESS_INFO> holders;
    if (GetDllHolders(inst.dllPath, holders)) inst.holders = holders.size();
    inst.running = inst.holders > 0 || IsDllLocked(inst.dllPath);

    if (inst.channel.empty()) {
        // An explicit path still names its channel, so recover it for display.
        std::wstring lower = ToLower(inst.dllPath);
        for (const auto& ch : kChannels) {
            if (lower.find(ToLower(ch.subdir)) != std::wstring::npos) {
                inst.channel = ch.name;
                break;
            }
        }
        if (inst.channel.empty()) inst.channel = L"Unknown";
    }
}

// ============================================================================
// Scan every install root for every release channel.
// ============================================================================
static std::vector<ChromeInstall> EnumerateChromeInstalls() {
    // 64-bit Chrome lands in Program Files, 32-bit in Program Files (x86), and
    // a user-scope install (always the case for Canary) in Local AppData.
    static const int kRoots[] = {
        CSIDL_PROGRAM_FILES, CSIDL_PROGRAM_FILESX86, CSIDL_LOCAL_APPDATA
    };

    std::vector<ChromeInstall> found;
    std::vector<std::wstring> seen;  // lower-cased paths, to dedupe the roots

    for (const auto& ch : kChannels) {
        for (int folder : kRoots) {
            wchar_t root[MAX_PATH];
            if (!SUCCEEDED(SHGetFolderPathW(NULL, folder, NULL, 0, root))) continue;

            std::wstring dll = FindDllUnderApplication(
                std::wstring(root) + L"\\" + ch.subdir + L"\\Application");
            if (dll.empty()) continue;

            std::wstring key = ToLower(dll);
            if (std::find(seen.begin(), seen.end(), key) != seen.end()) continue;
            seen.push_back(key);

            ChromeInstall inst;
            inst.channel = ch.name;
            inst.dllPath = dll;
            found.push_back(inst);
        }
    }

    // A chrome.dll dropped next to the patcher stays supported for offline use.
    if (found.empty() && GetFileAttributesW(L"chrome.dll") != INVALID_FILE_ATTRIBUTES) {
        ChromeInstall inst;
        inst.channel = L"Local file";
        inst.dllPath = L"chrome.dll";
        found.push_back(inst);
    }

    for (ChromeInstall& inst : found) FillInstallDetails(inst);
    return found;
}

// ============================================================================
// PE File Section & Address Utilities
// ============================================================================
struct PESection {
    std::string name;
    DWORD rawAddr;
    DWORD rawSize;
    DWORD virtAddr;
    DWORD virtSize;
};

// Validate a buffer as a well-formed 64-bit PE image and return its NT headers,
// or nullptr on any malformation. Every field this returns is guaranteed to be
// in-bounds: e_lfanew, the file header, the full optional header, and the whole
// section table. Callers can then dereference the result without re-checking.
// This guards against out-of-bounds reads when a truncated/garbage file is
// handed in (e.g. a bad custom path).
static PIMAGE_NT_HEADERS64 ValidatePe64(const uint8_t* data, size_t size) {
    if (data == nullptr || size < sizeof(IMAGE_DOS_HEADER)) return nullptr;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    if (dos->e_lfanew < 0) return nullptr;

    // Must be able to read Signature (4) + IMAGE_FILE_HEADER before touching them.
    size_t optOff = (size_t)dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (optOff > size) return nullptr;

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(data + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    // The optional header must be fully present and be PE32+.
    size_t optSize = nt->FileHeader.SizeOfOptionalHeader;
    if (optSize < sizeof(IMAGE_OPTIONAL_HEADER64)) return nullptr;
    if (optOff + optSize > size) return nullptr;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return nullptr;

    // The section table must lie fully within the buffer.
    size_t secOff = optOff + optSize;
    size_t secBytes = (size_t)nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    if (secOff + secBytes > size) return nullptr;

    return nt;
}

// Recalculate PE CheckSum
static DWORD CalculatePEChecksum(uint8_t* data, size_t size, DWORD checksumOffset) {
    uint64_t checksum = 0;
    size_t dwords = size / 4;
    uint32_t* ptr = (uint32_t*)data;
    size_t checksumDwordIndex = checksumOffset / 4;

    for (size_t i = 0; i < dwords; ++i) {
        if (i == checksumDwordIndex) continue;
        uint64_t val = ptr[i];
        checksum += val;
        if (checksum > 0xFFFFFFFFULL) {
            checksum = (checksum & 0xFFFFFFFFULL) + (checksum >> 32);
        }
    }
    if (size % 4) {
        uint32_t lastWord = 0;
        memcpy(&lastWord, data + dwords * 4, size % 4);
        checksum += lastWord;
        if (checksum > 0xFFFFFFFFULL) {
            checksum = (checksum & 0xFFFFFFFFULL) + (checksum >> 32);
        }
    }
    while (checksum >> 16) {
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }
    return (DWORD)(checksum + size);
}

// Check if chrome.dll is unpatched stock
static bool IsStockUnpatchedBuffer(uint8_t* fileData, size_t fileSize) {
    PIMAGE_NT_HEADERS64 ntHeaders = ValidatePe64(fileData, fileSize);
    if (ntHeaders == nullptr) return false;

    PIMAGE_DATA_DIRECTORY secDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];

    // If Security Directory (digital signature) is non-zero, it's untouched stock chrome.dll
    if (secDir->VirtualAddress != 0 && secDir->Size != 0) {
        return true;
    }
    return false;
}

// ============================================================================
// Chrome Version Helper
// ============================================================================
static std::wstring GetFileVersion(const std::wstring& path) {
    DWORD dummy = 0;
    DWORD size = GetFileVersionInfoSizeW(path.c_str(), &dummy);
    if (size == 0) return L"";
    std::vector<uint8_t> buf(size);
    if (!GetFileVersionInfoW(path.c_str(), 0, size, buf.data())) return L"";
    VS_FIXEDFILEINFO* ffi = nullptr;
    UINT ffiLen = 0;
    if (!VerQueryValueW(buf.data(), L"\\", (void**)&ffi, &ffiLen) || ffi == nullptr) return L"";
    wchar_t out[64];
    swprintf_s(out, L"%u.%u.%u.%u",
        HIWORD(ffi->dwFileVersionMS), LOWORD(ffi->dwFileVersionMS),
        HIWORD(ffi->dwFileVersionLS), LOWORD(ffi->dwFileVersionLS));
    return out;
}

// ============================================================================
// Core Surgical Patching Engine for chrome.dll File Buffer
//
// Architecture (Chrome 138+, current layout is 151/branch-heads/7922):
//   Google replaced ManifestV2ExperimentManager with a new ManifestV2Handler
//   KeyedService (extensions/browser/manifest_v2_handler.cc). Every MV2 block
//   funnels through ShouldDisableLegacyExtensions() (always true in release) and
//   MV2DeprecationImpactChecker::IsExtensionAffected() (an extension is affected
//   iff manifest_version < 3, an extension/user-script/login-screen type, and not
//   a component location). The enforcement paths are ShouldBlockExtensionInstall-
//   ation() (Load Unpacked), ShouldBlockExtensionEnable() (enable + chrome.manage-
//   ment), the startup DisableAffectedExtensions() loop, MaybeReEnableExtension(),
//   and inlined copies inside UserMayInstall()/MustRemainDisabled().
//
// The patch (Stage 151): the release build INLINES IsExtensionAffected() into
// seven sites, each starting with `cmp manifest_version, 2 ; jg not_affected`.
// Flip that jg (0x7F) to an unconditional jmp (0xEB) at all seven sites so every
// extension takes the "not an affected MV2 extension" path - the release-build
// equivalent of g_allow_mv2_for_testing == true. See the Stage 151 banner below
// and mv2-reversing.md. Each site is located by a .text-unique signature (known-RVA
// fast path first), and only a branch direction is ever changed - no call is
// removed and no return value is synthesized (see the CARDINAL RULE below).
//
// CARDINAL RULE (learned the hard way, mv2-reversing.md "lessons"): never delete or
// blank a call and never invent control flow - only flip the direction of an
// existing branch. Blanking a side-effecting call is what crashed the browser in
// an earlier, reverted approach.
//
// If the seven signatures do not match (a future Chrome milestone shifted the
// struct layout or codegen), the engine declines, reports structural candidates,
// and refuses to write - see mv2-reversing.md "Porting to a new Chrome version".
// ============================================================================

// Records every Stage 151 site written (RVA -> replacement bytes) so the patched
// buffer can be re-verified byte-for-byte after writing to disk.
static std::vector<std::pair<DWORD, std::vector<uint8_t>>> g_writtenPatches;

// ============================================================================
// Stage 151: Chrome 151 (branch-heads/7922) LTO-layout MV2 re-enable
//
// Verified against Chromium M151 source (extensions/browser/manifest_v2_handler.cc
// + mv2_deprecation_impact_checker.cc) and the installed build's PDB
// (C:\ghidra\chrome\chrome.dll.pdb, resolved via dbghelp). See mv2-reversing.md §8.
//
// In M151, every MV2 block funnels through:
//
//   bool ShouldDisableLegacyExtensions() {
//     if (g_allow_mv2_for_testing) return false;   // stripped in release
//     return true;
//   }
//   bool IsExtensionAffected(ext) {
//     if (ext.manifest_version() >= 3) return false;    // <-- the branch we flip
//     if (type not in {extension, user_script, login_screen}) return false;
//     if (IsComponentLocation(loc)) return false;
//     return true;
//   }
//
// g_allow_mv2_for_testing is an anonymous-namespace bool whose ONLY writer
// (AllowMV2ExtensionsForTesting, PassKey/IN-TEST) is stripped from the release
// build. With no writer, LTO constant-folds ShouldDisableLegacyExtensions() to
// `return true` and deletes the global entirely - it is NOT present in the PDB
// and there is no global read to flip in the disassembly. (This is why the
// WinDbg "flip the flag" guides only work on Canary/debug, not stable.)
//
// So the real gate is IsExtensionAffected(), which the LTO build INLINES into
// SEVEN sites (not five - UserMayInstall and MustRemainDisabled carry their own
// inlined copies rather than calling the standalone gate functions). Each site
// begins with the manifest-version check compiled as:
//
//     cmp <manifest_version>, 2
//     jg  <not_affected>         ; manifest_version >= 3  -> not an MV2 extension
//
// Flipping that single `jg` (0x7F) to an unconditional `jmp` (0xEB) forces the
// "not an affected MV2 extension" outcome for EVERY extension - byte-for-byte
// identical in effect to g_allow_mv2_for_testing == true, but achievable in the
// release binary. No call is removed and no return value is synthesized (see the
// CARDINAL RULE above - blanking a side-effecting call is what crashed a reverted
// earlier approach), so control flow stays structurally valid.
//
// The seven inlined sites (M151 = 151.0.7922.76), each located by a `.text`-
// UNIQUE ~24-byte signature and, as a fast path, its known absolute RVA:
//
//   IsExtensionAffected               jg @ RVA 0x083012E4  -> return false (not affected)
//   ShouldBlockExtensionInstallation  jg @ RVA 0x08301323  -> return false (don't block install)
//   ShouldBlockExtensionEnable        jg @ RVA 0x03291F6B  -> return false (don't block enable; also covers chrome.management CheckManifestV2Deprecation, which CALLs this)
//   OnExtensionSystemReady (inlined)  jg @ RVA 0x01618C4C  -> skip disable in the startup loop
//   MaybeReEnableExtension            jg @ RVA 0x08301436  -> re-enable already-disabled MV2 extensions
//   UserMayInstall (inlined)          jg @ RVA 0x08E736BA  -> don't block install / LOAD UNPACKED (emits IDS_..CANT_INSTALL_MV2; the real load-unpacked reject)
//   MustRemainDisabled (inlined)      jg @ RVA 0x016448AA  -> don't force installed MV2 back to disabled on restart
//
// Each flip is byte-verified (must currently be 0x7F, or 0xEB if already applied
// for idempotent re-runs) before writing, and the signature must match at a
// UNIQUE offset in .text or the site is declined - never guessed.
//
// Returns: 0 = layout declined (no sites found - not this build's layout),
//          1 = one or more flips freshly applied,
//          2 = all sites already contain the flip (idempotent re-run).
// ============================================================================

// One inlined IsExtensionAffected() manifest-version check. `sig` is a byte run
// that is unique across .text and contains the `jg` at byte index `jgOff`; the
// `jg` sits at absolute RVA `knownJgRVA` in the reference 151.0.7922.76 build.
struct AffectedSite {
    const char* name;
    DWORD knownJgRVA;             // fast-path absolute RVA of the 0x7F byte
    std::vector<uint8_t> sig;     // .text-unique signature containing the jg
    size_t jgOff;                 // index of the 0x7F byte within sig
};

// Locate the jg byte for one site. Fast path: if knownJgRVA carries a 0x7F (or
// already-flipped 0xEB) and the full signature matches around it, use it.
// Otherwise scan all of .text for the signature and accept it only if UNIQUE.
// Returns the file offset of the jg byte, or 0 if not found / ambiguous.
// *relocated reports whether the scan (not the fast path) found it.
//
// Byte matching is exact for every signature byte EXCEPT two: the jg opcode at
// jgOff (0x7F stock / 0xEB if already flipped) and the jg displacement byte at
// jgOff+1. The displacement is wildcarded because a point release can move the
// jg's not-affected target - which usually sits OUTSIDE the ~24-byte signature
// window - while leaving every byte inside the window (opcodes, register bytes,
// [ext+off] struct immediates, the 2 constant) identical. Masking only that one
// displacement lets such a shift relocate cleanly; everything else must still
// match exactly, so a real layout change (reordered fields, different codegen)
// still MISSES rather than false-matching.
static size_t FindAffectedJg(const std::vector<uint8_t>& buf,
                             DWORD textRVA, DWORD textRaw, DWORD textSize,
                             const AffectedSite& s, bool* relocated) {
    *relocated = false;
    const uint8_t* sig = s.sig.data();
    size_t sigLen = s.sig.size();
    size_t jgOff = s.jgOff;

    auto sigMatchesAt = [&](size_t sigStartRaw) -> bool {
        if (sigStartRaw + sigLen > buf.size()) return false;
        const uint8_t* p = buf.data() + sigStartRaw;
        for (size_t k = 0; k < sigLen; ++k) {
            if (k == jgOff) {
                // The jg opcode is 0x7F stock, or 0xEB after our flip.
                if (p[k] != 0x7F && p[k] != 0xEB) return false;
            } else if (k == jgOff + 1) {
                // The jg displacement byte is wildcarded (see header comment).
                continue;
            } else if (p[k] != sig[k]) {
                return false;
            }
        }
        return true;
    };

    // Fast path: the documented RVA for this reference build.
    if (s.knownJgRVA >= textRVA && (s.knownJgRVA - textRVA) < textSize) {
        DWORD jgRaw = textRaw + (s.knownJgRVA - textRVA);
        if (jgRaw >= jgOff) {
            size_t sigStart = jgRaw - jgOff;
            if (sigMatchesAt(sigStart)) return jgRaw;
        }
    }

    // Slow path: a point release shifted the function. Scan for the unique
    // signature (matching the jg byte as 0x7F or 0xEB).
    if (textSize < sigLen) return 0;
    size_t found = 0;
    unsigned matches = 0;
    DWORD textEndRaw = textRaw + textSize;
    for (DWORD r = textRaw; r + sigLen <= textEndRaw && r + sigLen <= buf.size(); ++r) {
        // Fast filter on the first signature byte.
        if (buf[r] != sig[0]) continue;
        if (!sigMatchesAt(r)) continue;
        if (matches == 0) found = r + jgOff;
        if (++matches > 1) break;   // ambiguous -> decline
    }
    if (matches == 1) {
        *relocated = true;
        return found;
    }
    return 0;
}

static int PatchStage151(std::vector<uint8_t>& fileBuffer,
                         DWORD textRVA, DWORD textRaw, DWORD textSize, int& totalPatches) {
    // Signatures captured from the stock 151.0.7922.76 chrome.dll and verified
    // UNIQUE across the whole .text section. Each contains the `jg` (0x7F) at
    // jgOff; the surrounding bytes pin it to the correct inlined check.
    const std::vector<AffectedSite> kSites = {
        { "IsExtensionAffected", 0x083012E4,
          { 0x83,0x7A,0x50,0x02, 0x7F, 0x34, 0x48,0x8B,0x8A,0x28,0x02,0x00,0x00,
            0x8B,0x41,0x30, 0x80,0xBA,0x08,0x02,0x00,0x00,0x00, 0x75,0x08 }, 4 },
        { "ShouldBlockExtensionInstallation", 0x08301323,
          { 0x83,0xFA,0x02, 0x7F, 0x23, 0x41,0x83,0xF8,0x01, 0x75,0x11,
            0x41,0x83,0xF9,0x05, 0x0F,0x95,0xC1, 0x41,0x83,0xF9,0x0A }, 3 },
        { "ShouldBlockExtensionEnable", 0x03291F6B,
          { 0x8B,0x41,0x68, 0x41,0x83,0xF8,0x02, 0x7F, 0x28, 0x8B,0x49,0x30,
            0x83,0xF8,0x01, 0x75,0x16, 0x83,0xF9,0x05, 0x0F,0x95,0xC2 }, 7 },
        { "OnExtensionSystemReady startup loop", 0x01618C4C,
          { 0x83,0x79,0x50,0x02, 0x7F, 0x2D, 0x48,0x8B,0x91,0x28,0x02,0x00,0x00,
            0x8B,0x42,0x30, 0x80,0xB9,0x08,0x02,0x00,0x00,0x00, 0x75,0x0C }, 4 },
        { "MaybeReEnableExtension", 0x08301436,
          { 0x83,0x7E,0x50,0x02, 0x7F, 0x2D, 0x48,0x8B,0x8E,0x28,0x02,0x00,0x00,
            0x8B,0x41,0x30, 0x80,0xBE,0x08,0x02,0x00,0x00,0x00, 0x75,0x08 }, 4 },
        // UserMayInstall inlines its OWN copy of IsExtensionAffected (it does NOT
        // call ShouldBlockExtensionEnable in the LTO build). This is the site that
        // rejects "Load unpacked" with IDS_EXTENSIONS_CANT_INSTALL_MV2_EXTENSION
        // (edx=0x2150) - without this flip the other 5 never get reached on install.
        { "UserMayInstall (inlined)", 0x08E736BA,
          { 0x8B,0x41,0x68, 0x83,0xFA,0x02, 0x7F, 0x3B, 0x8B,0x49,0x30,
            0x83,0xF8,0x01, 0x0F,0x85,0x1A,0x01,0x00,0x00, 0x83,0xF9,0x05, 0x74,0x2A }, 6 },
        // MustRemainDisabled inlines it too - without this flip an installed MV2
        // extension is forced back to disabled (DISABLE_UNSUPPORTED_MANIFEST_VERSION)
        // on the next check / restart even after UserMayInstall lets it in.
        { "MustRemainDisabled (inlined)", 0x016448AA,
          { 0x8B,0x41,0x68, 0x83,0xFA,0x02, 0x7F, 0x78, 0x8B,0x49,0x30,
            0x83,0xF8,0x01, 0x75,0x66, 0x31,0xFF, 0x83,0xF9,0x05, 0x74,0x05, 0x83,0xF9 }, 6 },
    };

    // First pass: locate every site. If none is found, this layout is not
    // recognized and we decline (the caller then reports candidates and refuses
    // to write). If some but not all are found, we still apply the ones we
    // located (and say which are missing) - a point-release that shifted only
    // some sites is far better served by the flips we can place than by nothing.
    struct Located { const AffectedSite* site; size_t jgRaw; bool relocated; };
    std::vector<Located> located;
    for (const auto& s : kSites) {
        bool reloc = false;
        size_t jgRaw = FindAffectedJg(fileBuffer, textRVA, textRaw, textSize, s, &reloc);
        if (jgRaw != 0) located.push_back({ &s, jgRaw, reloc });
    }

    if (located.empty()) return 0;  // no sites found - caller reports & declines

    std::cout << TAG_INFO << " Stage 151: Chrome 151 MV2 layout detected (" << located.size()
              << "/" << kSites.size() << " inlined IsExtensionAffected sites located)." << std::endl;

    int applied = 0, already = 0;
    for (const auto& L : located) {
        uint8_t cur = fileBuffer[L.jgRaw];
        DWORD jgRVA = textRVA + (DWORD)(L.jgRaw - textRaw);
        if (cur == 0xEB) {
            std::cout << "    [i] Stage 151: " << L.site->name << " jg->jmp at RVA 0x"
                      << std::hex << jgRVA << std::dec << " already applied (no change)." << std::endl;
            already++;
            // Still record it so on-disk verification confirms the byte.
            g_writtenPatches.push_back({ jgRVA, { 0xEB } });
            continue;
        }
        if (cur != 0x7F) {
            std::cout << "    " << TAG_WARN << " Stage 151: " << L.site->name << " unexpected byte 0x"
                      << std::hex << (int)cur << " at RVA 0x" << jgRVA << std::dec
                      << " (expected 0x7F) - skipping this site." << std::endl;
            continue;
        }
        fileBuffer[L.jgRaw] = 0xEB;   // jg -> jmp: force "not an affected MV2 extension"
        totalPatches++;
        applied++;
        g_writtenPatches.push_back({ jgRVA, { 0xEB } });
        std::cout << "    " << TAG_OK << " Stage 151: " << L.site->name << " jg->jmp at RVA 0x"
                  << std::hex << jgRVA << std::dec
                  << (L.relocated ? "  (RELOCATED - point-release layout)" : "") << std::endl;
    }

    if (located.size() < kSites.size()) {
        std::cout << "    " << TAG_WARN << " Stage 151: " << (kSites.size() - located.size())
                  << " site(s) not found - Chrome point release may have changed them. "
                     "MV2 re-enable may be partial; please report the version." << std::endl;
    }

    // 1 = freshly applied at least one; 2 = everything was already applied.
    return (applied > 0) ? 1 : 2;
}

// ============================================================================
// Report-only structural scan (never writes).
//
// When the seven known signatures miss entirely, the binary has a different
// layout (new milestone, changed Extension struct offsets, or different
// compiler output). Instead of guessing, scan .text for the structural skeleton
// of the inlined IsExtensionAffected check with every layout-dependent byte
// wildcarded. The distinctive core is:
//
//     cmp <r/m32>, 2 ; jg short        -- the manifest_version >= 3 bail-out
//
// which appears in two encodings, both ending in the adjacent bytes `02 7F`
// (imm8 = 2, then the jg opcode):
//
//     83 F8..FF 02 7F            cmp <reg>, 2 ; jg          (mod=11, reg=/7)
//     83 78..7F <disp8> 02 7F    cmp [reg+disp8], 2 ; jg    (mod=01, reg=/7)
//
// To cut false positives, a candidate must ALSO carry, within the next ~40
// bytes, one of the checks that follow the manifest-version test in the real
// gate - either the Manifest::Type enum compare `cmp <reg>, {1,5}` (the
// register-form sites) or the location byte test `cmp byte [reg+disp32], 0`
// (`80 B8..BF <disp32> 00`, the memory-form sites). The constants 2 / 1 / 5 / 0
// are source-semantic and survive layout changes; struct offsets and jump
// displacements do not, so they are wildcarded.
//
// Matches are printed as CANDIDATES for manual review against mv2-reversing.md's
// porting checklist. Nothing is ever patched from this scan - the first time
// this project guessed at bytes it corrupted unrelated functions and crashed
// Chrome.
// ============================================================================
static void ReportLayoutCandidates(const std::vector<uint8_t>& buf,
                                   DWORD textRVA, DWORD textRaw, DWORD textSize) {
    const size_t maxDisplay = 20;
    if (textSize < 8 || (size_t)textRaw + textSize > buf.size()) return;

    std::cout << TAG_INFO << " Scanning .text for the IsExtensionAffected skeleton "
                 "(cmp r/m32,2 ; jg short ; ... ; type/location check)..." << std::endl;

    const uint8_t* t = buf.data() + textRaw;
    const size_t tsize = textSize;
    size_t total = 0, shown = 0;

    for (size_t i = 2; i + 2 < tsize; ++i) {
        // Core: imm8 = 0x02 immediately followed by jg short (0x7F).
        if (t[i] != 0x02 || t[i + 1] != 0x7F) continue;

        // Confirm the 0x02 is the immediate of a `cmp r/m32, imm8` (opcode 0x83,
        // /7) in one of the two encodings, and find where the cmp begins.
        size_t cmpStart;
        if (t[i - 2] == 0x83 && (t[i - 1] & 0xF8) == 0xF8) {
            cmpStart = i - 2;                 // reg form:   83 F8..FF 02
        } else if (i >= 3 && t[i - 3] == 0x83 && (t[i - 2] & 0xF8) == 0x78) {
            cmpStart = i - 3;                 // disp8 form: 83 78..7F disp8 02
        } else {
            continue;
        }

        // Follow-up within ~40 bytes after the jg: the type enum compare
        // `cmp <reg>, {1,5}` (83 /7 with imm 1 or 5) OR the location byte test
        // `cmp byte [reg+disp32], 0` (80 B8..BF <disp32> 00).
        bool follow = false;
        size_t end = i + 2 + 40;
        if (end > tsize) end = tsize;
        for (size_t j = i + 2; j + 2 < end; ++j) {
            if (t[j] == 0x83 && (t[j + 1] & 0xF8) == 0xF8 &&
                (t[j + 2] == 0x01 || t[j + 2] == 0x05)) {
                follow = true;   // cmp reg, 1/5  (Manifest::Type enum)
                break;
            }
            if (t[j] == 0x80 && (t[j + 1] & 0xF8) == 0xB8 && j + 6 < end &&
                t[j + 6] == 0x00) {
                follow = true;   // cmp byte [reg+disp32], 0  (location gate)
                break;
            }
        }
        if (!follow) continue;

        total++;
        if (shown < maxDisplay) {
            DWORD rva = textRVA + (DWORD)cmpStart;
            std::cout << "    [candidate] RVA 0x" << std::hex << rva << std::dec << ":";
            size_t hexEnd = cmpStart + 24;
            if (hexEnd > tsize) hexEnd = tsize;
            for (size_t k = cmpStart; k < hexEnd; ++k) {
                std::cout << " " << std::hex << std::setw(2) << std::setfill('0')
                          << (int)t[k];
            }
            std::cout << std::dec << std::endl;
            shown++;
        }
    }

    std::cout << TAG_INFO << " Skeleton scan found " << total << " candidate site(s)"
              << (total > shown ? " (" + std::to_string(total - shown) + " not shown)" : "")
              << ". None were modified - verify each against mv2-reversing.md "
                 "'Porting to a new Chrome version' before hand-patching."
              << std::endl;
}

static bool PatchChromeDllBuffer(std::vector<uint8_t>& fileBuffer) {
    PIMAGE_NT_HEADERS64 ntHeaders = ValidatePe64(fileBuffer.data(), fileBuffer.size());
    if (ntHeaders == nullptr) {
        std::cout << TAG_ERR << " Error: not a valid 64-bit PE image (bad DOS/NT headers or truncated file)." << std::endl;
        return false;
    }

    // Parse sections to locate .text (the only section the signature scan needs).
    PIMAGE_SECTION_HEADER secHeader = IMAGE_FIRST_SECTION(ntHeaders);
    PESection textSec{};
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
        char nameBuf[9] = {0};
        memcpy(nameBuf, secHeader[i].Name, 8);
        if (strcmp(nameBuf, ".text") == 0) {
            textSec.name = nameBuf;
            textSec.rawAddr = secHeader[i].PointerToRawData;
            textSec.rawSize = secHeader[i].SizeOfRawData;
            textSec.virtAddr = secHeader[i].VirtualAddress;
            textSec.virtSize = secHeader[i].Misc.VirtualSize;
            break;
        }
    }

    if (textSec.rawSize == 0) {
        std::cout << TAG_ERR << " Error: Could not locate .text section." << std::endl;
        return false;
    }

    int totalPatches = 0;
    g_writtenPatches.clear();

    std::cout << TAG_INFO << " Starting MV2 Patching (ManifestV2Handler architecture)..." << std::endl;

    // ========================================================================
    // Stage 151: Chrome 151 (branch-heads/7922) - flip the seven inlined
    // IsExtensionAffected() manifest-version checks (jg -> jmp). This is the
    // release-build equivalent of g_allow_mv2_for_testing == true.
    // stage151: 0 = declined (layout not recognized; nothing is written),
    //           1 = applied, 2 = already applied (idempotent re-run).
    // ========================================================================
    std::cout << TAG_INFO << " Stage 151: probing for the Chrome 151 ManifestV2Handler layout..." << std::endl;
    int stage151 = PatchStage151(fileBuffer, textSec.virtAddr, textSec.rawAddr, textSec.rawSize, totalPatches);

    if (stage151 == 0) {
        // The seven known signatures matched nothing - this is a future Chrome
        // layout, not a declined-but-known one. Report structural candidates
        // and stop. NEVER guess at bytes: the first time this project did, it
        // corrupted unrelated functions and crashed Chrome (mv2-reversing.md
        // "Superseded approaches & lessons").
        ReportLayoutCandidates(fileBuffer, textSec.virtAddr, textSec.rawAddr, textSec.rawSize);
        std::cout << TAG_WARN << " No known Stage 151 signature matched this chrome.dll." << std::endl;
        std::cout << "    Chrome likely changed its binary layout (new milestone, changed" << std::endl;
        std::cout << "    Extension struct layout, or different compiler output)." << std::endl;
        std::cout << "    Nothing was modified." << std::endl;
        std::cout << "    To port the patch to this version, follow 'Porting to a new Chrome" << std::endl;
        std::cout << "    version' in mv2-reversing.md: resolve the seven gate symbols from this" << std::endl;
        std::cout << "    version's PDB, re-capture their cmp/jg signatures, update the kSites" << std::endl;
        std::cout << "    table in chrome-mv2-patch.cpp, and rebuild." << std::endl;
        return false;
    }

    std::cout << TAG_INFO << " Stage 151 " << ((stage151 == 1) ? "applied."
                                                      : "all sites already patched (no change needed).")
              << std::endl;

    // ========================================================================
    // Step 4: Clean PE Header Fixups (Authenticode Signature & Checksum)
    // ========================================================================
    std::cout << TAG_INFO << " Updating PE Header checksum & clearing Security Directory..." << std::endl;

    PIMAGE_DATA_DIRECTORY secDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    if (secDir->VirtualAddress != 0 || secDir->Size != 0) {
        std::cout << TAG_OK << " Clearing Security Directory (RVA: 0x" << std::hex << secDir->VirtualAddress
                  << ", Size: 0x" << secDir->Size << std::dec << ")" << std::endl;
        secDir->VirtualAddress = 0;
        secDir->Size = 0;
    }

    DWORD checksumOffset = (DWORD)((uint8_t*)&ntHeaders->OptionalHeader.CheckSum - fileBuffer.data());
    DWORD newChecksum = CalculatePEChecksum(fileBuffer.data(), fileBuffer.size(), checksumOffset);
    ntHeaders->OptionalHeader.CheckSum = newChecksum;

    std::cout << TAG_OK << " Recalculated PE CheckSum: 0x" << std::hex << newChecksum << std::dec << std::endl;

    return true;
}

// ============================================================================
// Post-write verification: re-read the patched file from disk and confirm
// every Stage 151 site contains the exact replacement bytes, plus that the
// Security Directory is cleared and the checksum field matches the file.
// ============================================================================
static bool VerifyPatchedFile(const std::wstring& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cout << TAG_ERR << " Verification: could not re-open patched file." << std::endl;
        return false;
    }
    std::streamsize fileSize = file.tellg();
    if (fileSize <= 0) {
        std::cout << TAG_ERR << " Verification: patched file is empty or unreadable." << std::endl;
        return false;
    }
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf(fileSize);
    if (!file.read((char*)buf.data(), fileSize)) {
        std::cout << TAG_ERR << " Verification: could not re-read patched file." << std::endl;
        return false;
    }
    file.close();

    PIMAGE_NT_HEADERS64 ntHeaders = ValidatePe64(buf.data(), buf.size());
    if (ntHeaders == nullptr) {
        std::cout << TAG_ERR << " Verification: patched file is not a valid PE image on disk." << std::endl;
        return false;
    }
    PIMAGE_SECTION_HEADER secHeader = IMAGE_FIRST_SECTION(ntHeaders);

    DWORD textRaw = 0, textRVA = 0;
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
        char nameBuf[9] = {0};
        memcpy(nameBuf, secHeader[i].Name, 8);
        if (strcmp(nameBuf, ".text") == 0) {
            textRaw = secHeader[i].PointerToRawData;
            textRVA = secHeader[i].VirtualAddress;
            break;
        }
    }
    if (textRaw == 0) {
        std::cout << TAG_ERR << " Verification: .text section not found on disk." << std::endl;
        return false;
    }

    bool ok = true;

    PIMAGE_DATA_DIRECTORY secDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    if (secDir->VirtualAddress != 0 || secDir->Size != 0) {
        std::cout << TAG_ERR << " Verification: Security Directory still present on disk (0x"
                  << std::hex << secDir->VirtualAddress << " / 0x" << secDir->Size << std::dec << ")." << std::endl;
        ok = false;
    } else {
        std::cout << TAG_OK << " Verification: Security Directory cleared." << std::endl;
    }

    DWORD checksumOffset = (DWORD)((uint8_t*)&ntHeaders->OptionalHeader.CheckSum - buf.data());
    DWORD computed = CalculatePEChecksum(buf.data(), buf.size(), checksumOffset);
    if (ntHeaders->OptionalHeader.CheckSum != computed) {
        std::cout << TAG_ERR << " Verification: checksum mismatch (on disk 0x" << std::hex
                  << ntHeaders->OptionalHeader.CheckSum << " vs computed 0x" << computed << std::dec << ")." << std::endl;
        ok = false;
    } else {
        std::cout << TAG_OK << " Verification: PE checksum matches (0x" << std::hex << computed << std::dec << ")." << std::endl;
    }

    for (const auto& wp : g_writtenPatches) {
        DWORD raw = textRaw + (wp.first - textRVA);
        if ((size_t)raw + wp.second.size() > buf.size() ||
            memcmp(buf.data() + raw, wp.second.data(), wp.second.size()) != 0) {
            std::cout << TAG_ERR << " Verification: site RVA 0x" << std::hex << wp.first << std::dec
                      << " does NOT match the expected patch on disk!" << std::endl;
            ok = false;
        } else {
            std::cout << TAG_OK << " Verification: patch site RVA 0x" << std::hex << wp.first << std::dec
                      << " confirmed on disk." << std::endl;
        }
    }

    return ok;
}

// ============================================================================
// Main Application Entry Point
// ============================================================================
static bool g_quiet = false;

// Print a message, pause (unless --quiet), and return an exit code. Collapses
// the repeated "message / Press Enter / pause / return" boilerplate that every
// error path in wmain used to spell out by hand. An empty message just pauses
// (used by the success exits, which print their own banner first).
static int Fail(const std::string& msg, int code = 1) {
    if (!msg.empty()) std::cout << msg << std::endl;
    if (!g_quiet) {
        std::cout << "\nPress Enter to exit..." << std::endl;
        std::cin.get();
    }
    return code;
}

// Print one channel as a numbered menu row: what it is, which version, and
// whether it is running right now.
static void PrintInstallRow(size_t index, const ChromeInstall& inst) {
    std::wcout << L"  " << W_BOLD << index << L")" << W_RESET << L" "
               << W_CYN << inst.channel << W_RESET;
    if (!inst.version.empty()) std::wcout << L"  " << inst.version;
    if (inst.running) {
        std::wcout << L"  " << W_YEL << L"[RUNNING";
        if (inst.holders) std::wcout << L", " << inst.holders << L" process(es)";
        std::wcout << L"]" << W_RESET;
    } else {
        std::wcout << L"  " << W_GRN << L"[not running]" << W_RESET;
    }
    if (inst.hasBackup) std::wcout << L" " << W_DIM << L"(backup present)" << W_RESET;
    std::wcout << L"\n      " << W_DIM << inst.dllPath << W_RESET << std::endl;
}

// Ask which installed channel to act on. Returns nullptr if the user quits.
// With exactly one install there is nothing to choose, so it is reported and
// used directly.
static const ChromeInstall* ChooseInstall(const std::vector<ChromeInstall>& installs) {
    if (installs.size() == 1) {
        std::cout << TAG_OK << " One Chrome channel found:" << std::endl;
        PrintInstallRow(1, installs[0]);
        return &installs[0];
    }

    std::cout << "\n" << TAG_INFO << " " << installs.size()
              << " Chrome release channels found:" << std::endl;
    for (size_t i = 0; i < installs.size(); ++i) PrintInstallRow(i + 1, installs[i]);

    // Only the selected channel is ever touched, so say so where the choice is
    // actually being made.
    std::cout << "\n" << TAG_INFO << " Only the channel you pick is modified; the others keep running."
              << std::endl;

    for (;;) {
        std::cout << C_BOLD << "\nWhich channel do you want to patch? [1-"
                  << installs.size() << ", q to quit]: " << C_RESET << std::flush;

        std::string line;
        if (!std::getline(std::cin, line)) return nullptr;   // EOF / redirected stdin
        if (line == "q" || line == "Q") return nullptr;

        int pick = atoi(line.c_str());
        if (pick >= 1 && pick <= static_cast<int>(installs.size())) {
            return &installs[pick - 1];
        }
        std::cout << TAG_ERR << " Enter a number between 1 and " << installs.size()
                  << ", or q to quit." << std::endl;
    }
}

// Warn that a running channel will be force-closed, and get an explicit yes.
// Killing a browser loses unsaved tab state, so it is never implicit - but a
// channel that is not running needs no warning at all.
static bool ConfirmForceClose(const ChromeInstall& inst) {
    if (!inst.running) return true;

    std::wcout << L"\n" << W_BOLD << W_YEL
               << L"  !! WARNING: Chrome " << inst.channel << L" is running !!"
               << W_RESET << std::endl;
    std::wcout << L"     Close it now to patch cleanly. If you continue, its "
               << inst.holders << L" process(es)\n"
               << L"     will be FORCE CLOSED and any unsaved tabs or downloads are lost."
               << std::endl;
    std::wcout << L"     " << W_DIM
               << L"Other Chrome channels are unaffected either way." << W_RESET
               << std::endl;

    for (;;) {
        std::wcout << W_BOLD << L"\nForce close Chrome " << inst.channel
                   << L" and patch? [y/N]: " << W_RESET << std::flush;

        std::string line;
        if (!std::getline(std::cin, line)) return false;
        if (line == "y" || line == "Y") return true;
        if (line.empty() || line == "n" || line == "N") {
            std::cout << TAG_INFO << " Cancelled - nothing was changed." << std::endl;
            return false;
        }
    }
}

static void PrintUsage() {
    std::cout << "Usage: chrome-mv2-patch.exe [path\\to\\chrome.dll] [options]\n"
                 "\n"
                 "Re-enables Manifest V2 extension support in Google Chrome 151+\n"
                 "(the current MV2-blocking layout; point releases relocate cleanly).\n"
                 "With no path, every installed release channel (Stable/Beta/Dev/Canary)\n"
                 "is listed so you can pick the one to patch.\n"
                 "\n"
                 "Options:\n"
                 "  -r, --restore    Restore chrome.dll from chrome.dll.bak.\n"
                 "  -y, --yes        Force close a running Chrome without asking.\n"
                 "  -q, --quiet      Do not pause for 'Press Enter' on exit (for scripting).\n"
                 "  -v, --version    Print the patcher version and exit.\n"
                 "  -h, --help       Show this help text and exit.\n"
                 "\n"
                 "A running Chrome is force closed only after you confirm, or with\n"
                 "--yes. Other channels keep running either way. --quiet cannot\n"
                 "prompt, so it needs an explicit path when several channels exist.\n"
              << std::endl;
}

int wmain(int argc, wchar_t* argv[]) {
    InitConsoleColors();

    std::wstring targetPath = L"";
    bool restoreMode = false;
    bool assumeYes = false;

    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg == L"--restore" || arg == L"-r") {
            restoreMode = true;
        } else if (arg == L"--yes" || arg == L"-y") {
            assumeYes = true;
        } else if (arg == L"--quiet" || arg == L"-q") {
            g_quiet = true;
        } else if (arg == L"--version" || arg == L"-v") {
            std::cout << "chrome-mv2-patch " APP_VERSION_STR << std::endl;
            return 0;
        } else if (arg == L"--help" || arg == L"-h" || arg == L"/?") {
            PrintUsage();
            return 0;
        } else if (!arg.empty() && arg[0] == L'-') {
            std::wcout << WTAG_ERR << L" Unknown option: " << arg << std::endl;
            PrintUsage();
            return 2;
        } else {
            targetPath = arg;
        }
    }

    std::cout << C_CYN << "==========================================================" << C_RESET << std::endl;
    std::cout << C_BOLD << "        Google Chrome chrome.dll Manifest V2 Patcher       " << C_RESET << std::endl;
    std::cout << C_DIM  << "   (Chrome 151 ManifestV2Handler seven-flip edition)       " << C_RESET << std::endl;
    std::cout << C_DIM  << "                    v" APP_VERSION_STR "                       " << C_RESET << std::endl;
    std::cout << C_CYN << "==========================================================" << C_RESET << std::endl;

    if (!IsElevatedAdmin()) {
        return Fail(TAG_WARN + " Administrator privileges are REQUIRED to modify chrome.dll in Program Files!\n"
                    "    Please right-click chrome-mv2-patch.exe and select 'Run as administrator'.");
    }

    // Non-interactive runs must not sit on a prompt, so they need the channel
    // spelled out as a path.
    bool interactive = !g_quiet;

    ChromeInstall target;
    if (!targetPath.empty()) {
        if (GetFileAttributesW(targetPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            return Fail(TAG_ERR + " Error: the given path does not exist.");
        }
        target.dllPath = targetPath;
        FillInstallDetails(target);
    } else {
        std::cout << TAG_INFO << " Scanning for installed Chrome release channels..." << std::endl;
        std::vector<ChromeInstall> installs = EnumerateChromeInstalls();

        if (installs.empty()) {
            return Fail(TAG_ERR + " Error: no installed Chrome channel was found.\n"
                        "    Pass the path explicitly: chrome-mv2-patch.exe \"C:\\path\\to\\chrome.dll\"");
        }
        if (!interactive && installs.size() > 1) {
            std::cout << TAG_ERR << " " << installs.size()
                      << " channels are installed and --quiet cannot prompt." << std::endl;
            for (size_t i = 0; i < installs.size(); ++i) PrintInstallRow(i + 1, installs[i]);
            return Fail("    Re-run with the chrome.dll path of the channel you want.");
        }

        const ChromeInstall* picked =
            interactive ? ChooseInstall(installs) : &installs[0];
        if (picked == nullptr) {
            return Fail(TAG_INFO + " No channel selected - nothing was changed.", 0);
        }
        target = *picked;
        targetPath = target.dllPath;
    }

    std::wcout << WTAG_OK << L" Target channel: " << W_CYN << target.channel
               << W_RESET << std::endl;
    std::wcout << WTAG_OK << L" Target file: " << targetPath << std::endl;
    if (!target.version.empty()) {
        std::wcout << WTAG_OK << L" Chrome version detected: " << target.version << std::endl;
    }

    // Last stop before anything is closed or written.
    if (target.running) {
        if (assumeYes) {
            std::wcout << WTAG_WARN << L" Chrome " << target.channel << L" is running and will be "
                       << W_BOLD << L"force closed" << W_RESET << L" (--yes)." << std::endl;
        } else if (g_quiet) {
            // No prompt is possible, and force-closing a browser is never a
            // silent default: --yes has to say so explicitly.
            std::wcout << WTAG_ERR << L" Chrome " << target.channel
                       << L" is running (" << target.holders << L" process(es))." << std::endl;
            return Fail("    Close it, or pass --yes to force close it.");
        } else if (!ConfirmForceClose(target)) {
            return Fail("", 0);
        }
    }

    std::wstring backupPath = targetPath + L".bak";

    if (restoreMode) {
        std::cout << TAG_INFO << " Restore mode requested..." << std::endl;
        if (GetFileAttributesW(backupPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            return Fail(TAG_ERR + "Error: Backup file chrome.dll.bak does not exist.");
        }

        if (!EnsureDllUnlocked(targetPath)) {
            return Fail(TAG_ERR + "chrome.dll is still locked and no owning process could be found.\n"
                        "    Close this Chrome channel manually and re-run. Other channels\n"
                        "    can stay open - they use their own chrome.dll.");
        }

        if (CopyFileW(backupPath.c_str(), targetPath.c_str(), FALSE)) {
            std::cout << TAG_SUCCESS << " Original chrome.dll successfully restored from backup!" << std::endl;
            return Fail("", 0);  // success: print nothing extra, just pause + exit 0
        } else {
            return Fail(TAG_ERR + "Error restoring file. Code: " + std::to_string(GetLastError()));
        }
    }

    // Free the target file. Only the channel that owns this chrome.dll is
    // closed - other installed channels keep running.
    if (!EnsureDllUnlocked(targetPath)) {
        return Fail(TAG_ERR + "chrome.dll is still locked and no owning process could be found.\n"
                    "    Close this Chrome channel manually and re-run. Other channels\n"
                    "    can stay open - they use their own chrome.dll.");
    }

    // Read Target File into Memory Buffer to evaluate stock / backup state
    std::ifstream file(targetPath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return Fail(TAG_ERR + "Error: Failed to open file for reading.");
    }

    std::streamsize fileSize = file.tellg();
    if (fileSize <= 0) {
        return Fail(TAG_ERR + "Error: chrome.dll is empty or its size could not be determined.");
    }
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(fileSize);
    if (!file.read((char*)buffer.data(), fileSize)) {
        return Fail(TAG_ERR + "Error reading file contents into memory.");
    }
    file.close();

    std::cout << TAG_OK << " Loaded " << fileSize << " bytes from chrome.dll." << std::endl;

    bool isTargetStock = IsStockUnpatchedBuffer(buffer.data(), buffer.size());

    // Smart Backup Management
    if (GetFileAttributesW(backupPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::cout << TAG_INFO << " Creating initial backup copy: chrome.dll.bak ..." << std::endl;
        if (!CopyFileW(targetPath.c_str(), backupPath.c_str(), TRUE)) {
            return Fail(TAG_ERR + "Error creating backup file. Code: " + std::to_string(GetLastError()));
        }
        std::cout << TAG_OK << " Initial backup created successfully." << std::endl;
    } else {
        if (isTargetStock) {
            std::cout << TAG_INFO << " New Chrome version / unpatched stock detected! Updating chrome.dll.bak ..." << std::endl;
            CopyFileW(targetPath.c_str(), backupPath.c_str(), FALSE);
            std::cout << TAG_OK << " Backup updated to latest stock version." << std::endl;
        } else {
            std::cout << TAG_INFO << " Previously patched chrome.dll detected. Restoring clean stock from backup before re-patching..." << std::endl;
            if (CopyFileW(backupPath.c_str(), targetPath.c_str(), FALSE)) {
                // Re-read restored stock file into memory buffer
                std::ifstream rFile(targetPath, std::ios::binary | std::ios::ate);
                if (rFile.is_open()) {
                    fileSize = rFile.tellg();
                    rFile.seekg(0, std::ios::beg);
                    buffer.resize(fileSize);
                    rFile.read((char*)buffer.data(), fileSize);
                    rFile.close();
                    std::cout << TAG_OK << " Restored clean stock chrome.dll into memory buffer." << std::endl;
                }
            } else {
                std::cout << TAG_ERR << " Backup restore failed (chrome.dll.bak missing? code "
                          << GetLastError() << ")." << std::endl;
                std::cout << "    Attempting idempotent re-patch of the existing file..." << std::endl;
            }
        }
    }

    // Apply Patches
    if (!PatchChromeDllBuffer(buffer)) {
        return Fail(TAG_WARNING + " No patches were applied.", 0);
    }

    // Write Modified Buffer Back to Disk
    std::ofstream outFile(targetPath, std::ios::binary | std::ios::trunc);
    if (!outFile.is_open()) {
        return Fail(TAG_ERR + "Error: Failed to open file for writing (permission denied or file locked).\n"
                    "    Make sure you ran chrome-mv2-patch.exe as Administrator!");
    }

    outFile.write((const char*)buffer.data(), buffer.size());
    outFile.close();
    if (!outFile) {
        return Fail(TAG_ERR + "Error: Failed to write patched bytes to chrome.dll (disk full or file locked).");
    }

    std::cout << TAG_INFO << " Verifying patched chrome.dll on disk..." << std::endl;
    if (!VerifyPatchedFile(targetPath)) {
        return Fail(TAG_ERR + "On-disk verification FAILED! Use 'chrome-mv2-patch.exe --restore' to revert.");
    }

    std::cout << "==========================================================" << std::endl;
    std::cout << TAG_SUCCESS << " chrome.dll successfully patched and verified on disk!" << std::endl;
    std::cout << "          Manifest V2 extension support re-enabled." << std::endl;
    std::cout << "==========================================================" << std::endl;

    return Fail("", 0);  // success: pause (unless --quiet) + exit 0
}
