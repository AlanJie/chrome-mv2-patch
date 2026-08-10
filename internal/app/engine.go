package app

// ============================================================================
// Core surgical patching engine, ported from the original C++ patcher.
//
// Every MV2 block in Chrome funnels through IsExtensionAffected() (an extension
// is affected iff manifest_version < 3, an extension/user-script/login-screen
// type, and not a component location). The release build INLINES that check
// into each enforcement site, starting with `cmp manifest_version, 2 ; jg
// not_affected`. Flipping that jg to an unconditional jmp at every site makes
// every extension take the "not affected" path.
//
// The exact site set and codegen differ per Chrome milestone, so the engine
// carries one signature table per known milestone (loaded from signatures.json),
// probes each, and applies only the best-matching one.
//
// CARDINAL RULE (learned the hard way, mv2-reversing.md "lessons"): never
// delete or blank a call and never invent control flow - only flip the direction
// of an existing branch to its EXISTING target. Both flips below are pure
// branch-direction changes:
//
//   JG_SHORT  0x7F disp8          -> 0xEB disp8        (jmp short, same disp8)
//   JG_NEAR   0x0F 0x8F disp32     -> 0x90 0xE9 disp32  (nop ; jmp near, same disp32)
//
// If no milestone's signatures match, the engine declines, reports structural
// candidates, and refuses to write.
// ============================================================================

import "fmt"

// jgKind is the encoding of the jg at a site.
type jgKind int

const (
	jgShort jgKind = iota // 0x7F disp8
	jgNear                // 0x0F 0x8F disp32
)

// affectedSite is one inlined IsExtensionAffected manifest-version check. sig is
// a byte run starting at the cmp that contains the jg at index jgOff; the jg
// sits at absolute RVA jgRVA in the milestone's reference build.
//
// expectedMatches is how many .text sites this signature is allowed to match:
// normally 1, but a milestone can fold two gates to byte-identical bodies (152:
// ManifestV2Handler::IsExtensionAffected and ShouldBlockExtensionEnable), and
// then the single signature legitimately matches - and must flip - both. A site
// is accepted only when the match count equals expectedMatches exactly.
type affectedSite struct {
	name            string
	kind            jgKind
	jgRVA           uint32 // fast-path absolute RVA of the jg opcode byte
	sig             []byte // signature starting at the cmp, containing the jg
	jgOff           int    // index of the jg opcode byte within sig
	expectedMatches int
}

// milestone is a Chrome milestone's complete set of inlined sites.
type milestone struct {
	name      string
	container string // "pe" or "elf" - which image format these RVAs describe
	sites     []affectedSite
}

// findAffectedJgSites locates every jg byte for one site. Fast path: if jgRVA
// carries the site's jg opcode (stock or already-flipped) and the full signature
// matches around it, use it. Otherwise scan all of .text. Returns the file
// offset of every jg opcode byte matched; the caller accepts the site only when
// the count equals expectedMatches. relocated reports whether the result came
// from the scan (not the fast path).
//
// Byte matching is exact for every signature byte EXCEPT the jg opcode and its
// displacement, which are masked per encoding:
//
//	JG_SHORT: byte@jgOff in {0x7F stock, 0xEB flipped}; byte@jgOff+1 (disp8) wild.
//	JG_NEAR : byte@jgOff in {0x0F stock, 0x90 flipped}; byte@jgOff+1 in
//	          {0x8F stock, 0xE9 flipped}; bytes@jgOff+2..+5 (disp32) wild.
//
// The displacement is wildcarded because a point release can move the
// not-affected target while leaving every other byte identical; masking only the
// displacement lets such a shift relocate cleanly, while a real layout change
// still MISSES rather than false-matching.
func findAffectedJgSites(buf []byte, textRVA, textRaw, textSize uint32, s affectedSite) (found []uint64, relocated bool) {
	sig := s.sig
	sigLen := len(sig)
	jgOff := s.jgOff

	sigMatchesAt := func(sigStartRaw uint64) bool {
		if sigStartRaw+uint64(sigLen) > uint64(len(buf)) {
			return false
		}
		p := buf[sigStartRaw:]
		for k := 0; k < sigLen; k++ {
			if s.kind == jgShort {
				switch {
				case k == jgOff:
					if p[k] != 0x7F && p[k] != 0xEB {
						return false
					}
				case k == jgOff+1:
					// disp8 wildcard
				default:
					if p[k] != sig[k] {
						return false
					}
				}
			} else { // jgNear: 0F 8F disp32 -> 90 E9 disp32
				switch {
				case k == jgOff:
					if p[k] != 0x0F && p[k] != 0x90 {
						return false
					}
				case k == jgOff+1:
					if p[k] != 0x8F && p[k] != 0xE9 {
						return false
					}
				case k >= jgOff+2 && k <= jgOff+5:
					// disp32 wildcard
				default:
					if p[k] != sig[k] {
						return false
					}
				}
			}
		}
		return true
	}

	// Fast path only when the site is expected to be unique - a shared-body site
	// (expectedMatches > 1) must always scan so it finds every copy.
	if s.expectedMatches == 1 &&
		s.jgRVA >= textRVA && (s.jgRVA-textRVA) < textSize {
		jgRaw := uint64(textRaw) + uint64(s.jgRVA-textRVA)
		if jgRaw >= uint64(jgOff) {
			sigStart := jgRaw - uint64(jgOff)
			if sigMatchesAt(sigStart) {
				return []uint64{jgRaw}, false
			}
		}
	}

	// Slow path: scan .text for the signature (matching the jg per encoding).
	if textSize < uint32(sigLen) {
		return nil, false
	}
	textEndRaw := uint64(textRaw) + uint64(textSize)
	bufLen := uint64(len(buf))
	for r := uint64(textRaw); r+uint64(sigLen) <= textEndRaw && r+uint64(sigLen) <= bufLen; r++ {
		if buf[r] != sig[0] {
			continue // fast filter on the first byte
		}
		if !sigMatchesAt(r) {
			continue
		}
		found = append(found, r+uint64(jgOff))
		// Cap the scan once we have one more than expected: enough to reject the
		// site as ambiguous without walking the rest of .text.
		if len(found) > s.expectedMatches {
			break
		}
	}
	if len(found) > 0 {
		relocated = true
	}
	return found, relocated
}

// writtenPatch records one flipped site (RVA -> replacement bytes) so the
// patched buffer can be re-verified byte-for-byte after writing to disk.
type writtenPatch struct {
	rva   uint32
	bytes []byte
}

// patchResult is the outcome of a milestone patch pass, so the caller can report
// honestly: a partial match (some gates located, some not) must never claim full
// success.
type patchResult struct {
	status    int    // 0 = declined, 1 = flips applied, 2 = all already applied
	milestone string // name of the milestone that best matched
	located   int    // table entries satisfied (exact match count)
	total     int    // table entries in the chosen milestone
	flips     int    // physical jg sites flipped or already flipped
	full      bool   // located == total (every gate covered)
	written   []writtenPatch
}

// patchMilestones probes every milestone and applies the best-matching one.
// For each milestone, an entry is "satisfied" only when its signature matches
// EXACTLY the expected number of times; a wrong count means the layout changed
// and the entry is declined, never guessed. The milestone with the most
// satisfied entries wins.
func patchMilestones(buf []byte, textRVA, textRaw, textSize uint32, milestones []milestone) patchResult {
	type flip struct {
		site      affectedSite
		jgRaw     uint64
		relocated bool
	}
	type candidate struct {
		ms        *milestone
		flips     []flip
		satisfied int
	}

	var best candidate
	for mi := range milestones {
		ms := &milestones[mi]
		c := candidate{ms: ms}
		for _, s := range ms.sites {
			hits, reloc := findAffectedJgSites(buf, textRVA, textRaw, textSize, s)
			if len(hits) == s.expectedMatches {
				c.satisfied++
				for _, jgRaw := range hits {
					c.flips = append(c.flips, flip{site: s, jgRaw: jgRaw, relocated: reloc})
				}
			}
		}
		if c.satisfied > best.satisfied {
			best = c
		}
	}

	var res patchResult
	if best.satisfied == 0 {
		return res // status 0 - no milestone matched
	}

	res.milestone = best.ms.name
	res.located = best.satisfied
	res.total = len(best.ms.sites)
	res.full = best.satisfied == len(best.ms.sites)

	infof("Chrome %s MV2 layout detected (%d/%d inlined IsExtensionAffected sites, %d jg flip(s)).",
		best.ms.name, res.located, res.total, len(best.flips))

	applied, already := 0, 0
	for _, f := range best.flips {
		jgRVA := textRVA + uint32(f.jgRaw-uint64(textRaw))
		ms := best.ms.name

		if f.site.kind == jgShort {
			cur := buf[f.jgRaw]
			if cur == 0xEB {
				fmt.Printf("    [i] %s: %s jg->jmp at RVA 0x%X already applied (no change).\n", ms, f.site.name, jgRVA)
				already++
				res.written = append(res.written, writtenPatch{jgRVA, []byte{0xEB}})
				continue
			}
			if cur != 0x7F {
				fmt.Printf("    %s %s: %s unexpected byte 0x%X at RVA 0x%X (expected 0x7F) - skipping this site.\n",
					tagWarn, ms, f.site.name, cur, jgRVA)
				continue
			}
			buf[f.jgRaw] = 0xEB // jg -> jmp short
			applied++
			res.flips++
			res.written = append(res.written, writtenPatch{jgRVA, []byte{0xEB}})
		} else { // jgNear: 0F 8F disp32 -> 90 E9 disp32
			o0, o1 := buf[f.jgRaw], buf[f.jgRaw+1]
			if o0 == 0x90 && o1 == 0xE9 {
				fmt.Printf("    [i] %s: %s jg->jmp at RVA 0x%X already applied (no change).\n", ms, f.site.name, jgRVA)
				already++
				res.written = append(res.written, writtenPatch{jgRVA, []byte{0x90, 0xE9}})
				continue
			}
			if !(o0 == 0x0F && o1 == 0x8F) {
				fmt.Printf("    %s %s: %s unexpected bytes 0x%X 0x%X at RVA 0x%X (expected 0F 8F) - skipping this site.\n",
					tagWarn, ms, f.site.name, o0, o1, jgRVA)
				continue
			}
			buf[f.jgRaw] = 0x90   // nop
			buf[f.jgRaw+1] = 0xE9 // jmp near (keeps the disp32)
			applied++
			res.flips++
			res.written = append(res.written, writtenPatch{jgRVA, []byte{0x90, 0xE9}})
		}

		suffix := ""
		if f.relocated {
			suffix = "  (RELOCATED - point-release layout)"
		}
		fmt.Printf("    %s %s: %s jg->jmp at RVA 0x%X%s\n", tagOK, ms, f.site.name, jgRVA, suffix)
	}
	res.flips += already // count already-applied sites toward the flip total

	if !res.full {
		fmt.Printf("    %s Chrome %s: %d site(s) not found - this Chrome build may have shifted them. "+
			"MV2 re-enable is PARTIAL and may still be blocked; please report the version.\n",
			tagWarn, best.ms.name, res.total-res.located)
	}

	if applied > 0 {
		res.status = 1
	} else {
		res.status = 2
	}
	return res
}

// reportLayoutCandidates is a report-only structural scan (never writes). When
// the known signatures miss entirely, it scans .text for the structural skeleton
// of the inlined IsExtensionAffected check with every layout-dependent byte
// wildcarded, and prints matches as CANDIDATES for manual review. Nothing is
// ever patched from this scan.
//
// The distinctive core is `cmp <r/m32>, 2 ; jg short` - the manifest_version >=3
// bail-out - in two encodings, both ending in the adjacent bytes `02 7F`:
//
//	83 F8..FF 02 7F            cmp <reg>, 2 ; jg          (mod=11, reg=/7)
//	83 78..7F <disp8> 02 7F    cmp [reg+disp8], 2 ; jg    (mod=01, reg=/7)
//
// To cut false positives, a candidate must ALSO carry, within the next ~40
// bytes, one of the checks that follow the manifest-version test: the
// Manifest::Type enum compare `cmp <reg>, {1,5}` or the location byte test
// `cmp byte [reg+disp32], 0`.
func reportLayoutCandidates(buf []byte, textRVA, textRaw, textSize uint32) {
	const maxDisplay = 20
	if textSize < 8 || uint64(textRaw)+uint64(textSize) > uint64(len(buf)) {
		return
	}

	infof("Scanning .text for the IsExtensionAffected skeleton " +
		"(cmp r/m32,2 ; jg short ; ... ; type/location check)...")

	t := buf[textRaw:]
	tsize := int(textSize)
	total, shown := 0, 0

	for i := 2; i+2 < tsize; i++ {
		// Core: imm8 = 0x02 immediately followed by jg short (0x7F).
		if t[i] != 0x02 || t[i+1] != 0x7F {
			continue
		}

		// Confirm the 0x02 is the immediate of a `cmp r/m32, imm8` (0x83, /7)
		// in one of the two encodings, and find where the cmp begins.
		var cmpStart int
		switch {
		case t[i-2] == 0x83 && (t[i-1]&0xF8) == 0xF8:
			cmpStart = i - 2 // reg form:   83 F8..FF 02
		case i >= 3 && t[i-3] == 0x83 && (t[i-2]&0xF8) == 0x78:
			cmpStart = i - 3 // disp8 form: 83 78..7F disp8 02
		default:
			continue
		}

		// Follow-up within ~40 bytes after the jg.
		follow := false
		end := i + 2 + 40
		if end > tsize {
			end = tsize
		}
		for j := i + 2; j+2 < end; j++ {
			if t[j] == 0x83 && (t[j+1]&0xF8) == 0xF8 && (t[j+2] == 0x01 || t[j+2] == 0x05) {
				follow = true // cmp reg, 1/5 (Manifest::Type enum)
				break
			}
			if t[j] == 0x80 && (t[j+1]&0xF8) == 0xB8 && j+6 < end && t[j+6] == 0x00 {
				follow = true // cmp byte [reg+disp32], 0 (location gate)
				break
			}
		}
		if !follow {
			continue
		}

		total++
		if shown < maxDisplay {
			rva := textRVA + uint32(cmpStart)
			hexEnd := cmpStart + 24
			if hexEnd > tsize {
				hexEnd = tsize
			}
			fmt.Printf("    [candidate] RVA 0x%X: %s\n", rva, hexUpper(t[cmpStart:hexEnd]))
			shown++
		}
	}

	extra := ""
	if total > shown {
		extra = fmt.Sprintf(" (%d not shown)", total-shown)
	}
	infof("Skeleton scan found %d candidate site(s)%s. None were modified - verify each "+
		"against mv2-reversing.md 'Porting to a new Chrome version' before hand-patching.",
		total, extra)
}
