package app

// Image abstracts the executable container the gates live in: PE (chrome.dll on
// Windows) or ELF (chrome on Linux). The engine only needs .text's location and
// a couple of format-specific hooks, so everything else about PE vs ELF stays
// behind this interface.

import (
	"encoding/binary"
	"fmt"
)

// textSection is .text located in the file buffer.
type textSection struct {
	rva  uint32 // virtual address of .text
	raw  uint32 // file offset of .text
	size uint32 // raw size to scan
}

// Image is a parsed, in-buffer executable. Methods operate on the same []byte
// the engine patches, so header edits (PE) are reflected in what gets written.
type Image interface {
	// format returns "pe" or "elf" - selects which milestone table applies.
	format() string
	// text returns the .text section to scan for gate signatures.
	text() textSection
	// finalize performs format-specific fixups after the flips are written.
	// PE clears the Authenticode Security Directory and recomputes the checksum;
	// ELF has nothing to do.
	finalize(buf []byte) error
	// verifyFinalize re-checks those fixups on the reloaded file.
	verifyFinalize(buf []byte) error
	// isLikelyStock reports whether the buffer looks like an unmodified stock
	// build (used only to keep the .bak copy clean).
	isLikelyStock(buf []byte) bool
}

// openImage detects the container by magic and parses it.
func openImage(buf []byte) (Image, error) {
	if len(buf) >= 2 && buf[0] == 'M' && buf[1] == 'Z' {
		return parsePE(buf)
	}
	if len(buf) >= 4 && buf[0] == 0x7F && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F' {
		return parseELF(buf)
	}
	return nil, fmt.Errorf("unrecognized executable (not PE 'MZ' or ELF '\\x7fELF')")
}

// ---------------------------------------------------------------------------
// PE (chrome.dll) - ported from ValidatePe64 / CalculatePEChecksum /
// IsStockUnpatchedBuffer / the security-dir + checksum fixups.
// ---------------------------------------------------------------------------

const (
	peSecurityDirIndex = 4   // IMAGE_DIRECTORY_ENTRY_SECURITY
	peOptHdr64FixedLen = 112 // bytes of PE32+ optional header before the data dirs
	peOptHdr32FixedLen = 96  // bytes of PE32  optional header before the data dirs
	peChecksumFieldOff = 64  // CheckSum offset within the optional header (same PE32/PE32+)
)

type peImage struct {
	optHdrOff  uint64 // file offset of the optional header
	checksumAt uint64 // file offset of the OptionalHeader.CheckSum field
	secDirAt   uint64 // file offset of the security data-directory entry (VA,Size)
	is32       bool   // PE32 (32-bit) rather than PE32+ (64-bit)
	tsec       textSection
}

// format tags PE32 (x86) and PE32+ (x64) distinctly so a 32-bit target only ever
// probes 32-bit milestone tables and a 64-bit target only 64-bit ones (the gate
// signatures are architecture-specific machine code). Mirrors the pe/elf split.
func (p *peImage) format() string {
	if p.is32 {
		return "pe32"
	}
	return "pe"
}
func (p *peImage) text() textSection { return p.tsec }

// parsePE validates a well-formed PE (PE32 or PE32+) and locates .text, the
// checksum field, and the security data directory. Mirrors ValidatePe64: every
// offset it records is bounds-checked here so later reads/writes are safe. PE32
// and PE32+ differ only in the fixed optional-header length before the data
// directories (96 vs 112); the CheckSum field is at offset 64 in both, and the
// section table, checksum algorithm, and .text lookup are identical.
func parsePE(buf []byte) (*peImage, error) {
	if len(buf) < 64 {
		return nil, fmt.Errorf("not a valid PE: file too small")
	}
	eLfanew := uint64(binary.LittleEndian.Uint32(buf[0x3C:]))

	// Signature(4) + IMAGE_FILE_HEADER(20) must be readable.
	if eLfanew+4+20 > uint64(len(buf)) {
		return nil, fmt.Errorf("not a valid PE: truncated NT headers")
	}
	if buf[eLfanew] != 'P' || buf[eLfanew+1] != 'E' || buf[eLfanew+2] != 0 || buf[eLfanew+3] != 0 {
		return nil, fmt.Errorf("not a valid PE: bad NT signature")
	}
	numSections := binary.LittleEndian.Uint16(buf[eLfanew+6:])
	sizeOfOptHdr := uint64(binary.LittleEndian.Uint16(buf[eLfanew+20:]))

	optOff := eLfanew + 24
	if optOff+2 > uint64(len(buf)) || optOff+sizeOfOptHdr > uint64(len(buf)) {
		return nil, fmt.Errorf("not a valid PE: optional header out of bounds")
	}
	magic := binary.LittleEndian.Uint16(buf[optOff:])
	var fixedLen uint64
	switch magic {
	case 0x20B: // PE32+ (x86-64)
		fixedLen = peOptHdr64FixedLen
	case 0x10B: // PE32 (x86)
		fixedLen = peOptHdr32FixedLen
	default:
		return nil, fmt.Errorf("not a valid PE: unsupported optional header magic 0x%X", magic)
	}
	// The optional header must be large enough to hold the fixed part plus the
	// data directories through the security entry we read below.
	if sizeOfOptHdr < fixedLen+(peSecurityDirIndex+1)*8 {
		return nil, fmt.Errorf("not a valid PE: optional header too small for data directories")
	}

	secOff := optOff + sizeOfOptHdr
	secBytes := uint64(numSections) * 40
	if secOff+secBytes > uint64(len(buf)) {
		return nil, fmt.Errorf("not a valid PE: section table out of bounds")
	}

	p := &peImage{
		optHdrOff:  optOff,
		checksumAt: optOff + peChecksumFieldOff,
		secDirAt:   optOff + fixedLen + peSecurityDirIndex*8,
		is32:       magic == 0x10B,
	}

	// Locate .text.
	for i := uint64(0); i < uint64(numSections); i++ {
		sh := secOff + i*40
		name := trimName(buf[sh : sh+8])
		if name == ".text" {
			p.tsec = textSection{
				rva:  binary.LittleEndian.Uint32(buf[sh+12:]),
				raw:  binary.LittleEndian.Uint32(buf[sh+20:]),
				size: binary.LittleEndian.Uint32(buf[sh+16:]), // SizeOfRawData
			}
			break
		}
	}
	if p.tsec.size == 0 {
		return nil, fmt.Errorf("could not locate .text section")
	}
	return p, nil
}

func (p *peImage) finalize(buf []byte) error {
	// Clear the Security Directory (Authenticode) - the patched bytes invalidate
	// it anyway, and leaving a dangling certificate table can confuse loaders.
	va := binary.LittleEndian.Uint32(buf[p.secDirAt:])
	sz := binary.LittleEndian.Uint32(buf[p.secDirAt+4:])
	if va != 0 || sz != 0 {
		okf("Clearing Security Directory (RVA: 0x%X, Size: 0x%X)", va, sz)
		binary.LittleEndian.PutUint32(buf[p.secDirAt:], 0)
		binary.LittleEndian.PutUint32(buf[p.secDirAt+4:], 0)
	}

	sum := peChecksum(buf, p.checksumAt)
	binary.LittleEndian.PutUint32(buf[p.checksumAt:], sum)
	okf("Recalculated PE CheckSum: 0x%X", sum)
	return nil
}

func (p *peImage) verifyFinalize(buf []byte) error {
	va := binary.LittleEndian.Uint32(buf[p.secDirAt:])
	sz := binary.LittleEndian.Uint32(buf[p.secDirAt+4:])
	if va != 0 || sz != 0 {
		return fmt.Errorf("Security Directory still present on disk (0x%X / 0x%X)", va, sz)
	}
	okf("Verification: Security Directory cleared.")

	onDisk := binary.LittleEndian.Uint32(buf[p.checksumAt:])
	computed := peChecksum(buf, p.checksumAt)
	if onDisk != computed {
		return fmt.Errorf("checksum mismatch (on disk 0x%X vs computed 0x%X)", onDisk, computed)
	}
	okf("Verification: PE checksum matches (0x%X).", computed)
	return nil
}

// isLikelyStock: a non-zero Security Directory means an untouched, signed stock
// chrome.dll (this tool zeroes it when patching).
func (p *peImage) isLikelyStock(buf []byte) bool {
	va := binary.LittleEndian.Uint32(buf[p.secDirAt:])
	sz := binary.LittleEndian.Uint32(buf[p.secDirAt+4:])
	return va != 0 && sz != 0
}

// peChecksum ports CalculatePEChecksum: a 16-bit ones-complement-style sum over
// the whole file (skipping the 4-byte CheckSum field) plus the file size.
func peChecksum(data []byte, checksumOffset uint64) uint32 {
	var checksum uint64
	dwords := uint64(len(data)) / 4
	checksumDwordIndex := checksumOffset / 4

	for i := uint64(0); i < dwords; i++ {
		if i == checksumDwordIndex {
			continue
		}
		checksum += uint64(binary.LittleEndian.Uint32(data[i*4:]))
		if checksum > 0xFFFFFFFF {
			checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32)
		}
	}
	if rem := len(data) % 4; rem != 0 {
		var last uint32
		var shift uint
		for k := 0; k < rem; k++ {
			last |= uint32(data[dwords*4+uint64(k)]) << shift
			shift += 8
		}
		checksum += uint64(last)
		if checksum > 0xFFFFFFFF {
			checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32)
		}
	}
	for checksum>>16 != 0 {
		checksum = (checksum & 0xFFFF) + (checksum >> 16)
	}
	return uint32(checksum + uint64(len(data)))
}

// ---------------------------------------------------------------------------
// ELF (chrome) - minimal ELF64 reader to locate .text. There is no signature
// directory and no checksum, so finalize/verify are no-ops. Stock detection has
// no header marker (see mv2-reversing.md), so it is conservative.
// ---------------------------------------------------------------------------

type elfImage struct {
	tsec textSection
}

func (e *elfImage) format() string              { return "elf" }
func (e *elfImage) text() textSection           { return e.tsec }
func (e *elfImage) finalize(buf []byte) error   { return nil }
func (e *elfImage) verifyFinalize([]byte) error { return nil }

// isLikelyStock: ELF has no equivalent of the PE security directory, and the
// gate table needed to detect applied flips does not exist yet. Treat it as
// stock - the only effect is keeping the .bak copy refreshed, and re-copying an
// identical file is harmless.
func (e *elfImage) isLikelyStock([]byte) bool { return true }

func parseELF(buf []byte) (*elfImage, error) {
	if len(buf) < 64 || buf[4] != 2 || buf[5] != 1 {
		return nil, fmt.Errorf("not a valid little-endian ELF64")
	}
	shoff := binary.LittleEndian.Uint64(buf[0x28:])
	shentsize := binary.LittleEndian.Uint16(buf[0x3A:])
	shnum := binary.LittleEndian.Uint16(buf[0x3C:])
	shstrndx := binary.LittleEndian.Uint16(buf[0x3E:])
	if shoff == 0 || shnum == 0 {
		return nil, fmt.Errorf("ELF has no section table (fully stripped?)")
	}
	if shoff+uint64(shentsize)*uint64(shnum) > uint64(len(buf)) {
		return nil, fmt.Errorf("ELF section table out of bounds")
	}

	// .shstrtab holds section names.
	strHdr := shoff + uint64(shstrndx)*uint64(shentsize)
	strOff := binary.LittleEndian.Uint64(buf[strHdr+0x18:])
	strSize := binary.LittleEndian.Uint64(buf[strHdr+0x20:])
	if strOff+strSize > uint64(len(buf)) {
		return nil, fmt.Errorf("ELF .shstrtab out of bounds")
	}
	strtab := buf[strOff : strOff+strSize]

	e := &elfImage{}
	for i := uint64(0); i < uint64(shnum); i++ {
		sh := shoff + i*uint64(shentsize)
		nameOff := binary.LittleEndian.Uint32(buf[sh:])
		if uint64(nameOff) >= uint64(len(strtab)) {
			continue
		}
		if cstr(strtab[nameOff:]) != ".text" {
			continue
		}
		addr := binary.LittleEndian.Uint64(buf[sh+0x10:])
		off := binary.LittleEndian.Uint64(buf[sh+0x18:])
		size := binary.LittleEndian.Uint64(buf[sh+0x20:])
		e.tsec = textSection{rva: uint32(addr), raw: uint32(off), size: uint32(size)}
		break
	}
	if e.tsec.size == 0 {
		return nil, fmt.Errorf("could not locate .text section")
	}
	return e, nil
}

// trimName turns a fixed 8-byte PE section name field into a string.
func trimName(b []byte) string {
	n := 0
	for n < len(b) && b[n] != 0 {
		n++
	}
	return string(b[:n])
}

// cstr reads a NUL-terminated name from a string table slice.
func cstr(b []byte) string {
	n := 0
	for n < len(b) && b[n] != 0 {
		n++
	}
	return string(b[:n])
}
