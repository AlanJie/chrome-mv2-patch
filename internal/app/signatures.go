package app

// Loads the milestone signature tables from signatures.json into the engine's
// milestone/affectedSite types. The file is NOT embedded: it is read at runtime
// from next to the executable (falling back to the current directory), so the
// Chrome-version signatures can be updated by shipping a new signatures.json
// without rebuilding the binary. Derive a new milestone's entry with
// scripts/derive_milestone.py.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// signaturesFileName is the external table the patcher reads at runtime. It must
// sit next to the executable (or in the current working directory).
const signaturesFileName = "signatures.json"

type rawSite struct {
	Name            string `json:"name"`
	Kind            string `json:"kind"`
	JgRVA           string `json:"jgRVA"`
	JgOff           int    `json:"jgOff"`
	ExpectedMatches int    `json:"expectedMatches"`
	Sig             string `json:"sig"`
}

type rawMilestone struct {
	Name      string    `json:"name"`
	Container string    `json:"container"`
	Sites     []rawSite `json:"sites"`
}

type rawDoc struct {
	Milestones []rawMilestone `json:"milestones"`
}

// signaturesPath locates signatures.json: next to the executable first, then the
// current working directory. Returns the path checked and whether it exists.
func signaturesPath() (string, bool) {
	var candidates []string
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), signaturesFileName))
	}
	candidates = append(candidates, signaturesFileName) // cwd fallback

	for _, p := range candidates {
		if fileExists(p) {
			return p, true
		}
	}
	// Nothing found: report the exe-adjacent path as the expected location.
	return candidates[0], false
}

// loadMilestones reads and validates signatures.json. Validation is strict: each
// site's sig must contain the jg opcode at jgOff, and that opcode must be the
// stock byte for its encoding (0x7F short / 0x0F near). A missing file is a
// clear, actionable error (the table ships alongside the binary).
func loadMilestones() ([]milestone, error) {
	path, ok := signaturesPath()
	if !ok {
		return nil, fmt.Errorf("%s not found next to the executable or in the current directory - "+
			"it ships alongside the binary; see mv2-reversing.md", signaturesFileName)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var doc rawDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	var out []milestone
	for _, rm := range doc.Milestones {
		ms := milestone{name: rm.Name, container: rm.Container}
		for _, rs := range rm.Sites {
			var kind jgKind
			switch rs.Kind {
			case "short":
				kind = jgShort
			case "near":
				kind = jgNear
			default:
				return nil, fmt.Errorf("milestone %s site %q: unknown kind %q", rm.Name, rs.Name, rs.Kind)
			}

			rva, err := strconv.ParseUint(rs.JgRVA, 0, 32)
			if err != nil {
				return nil, fmt.Errorf("milestone %s site %q: bad jgRVA %q: %w", rm.Name, rs.Name, rs.JgRVA, err)
			}

			sig, err := hex.DecodeString(rs.Sig)
			if err != nil {
				return nil, fmt.Errorf("milestone %s site %q: bad sig hex: %w", rm.Name, rs.Name, err)
			}

			if rs.JgOff < 0 || rs.JgOff >= len(sig) {
				return nil, fmt.Errorf("milestone %s site %q: jgOff %d out of range (sig len %d)", rm.Name, rs.Name, rs.JgOff, len(sig))
			}
			op := sig[rs.JgOff]
			wantShort := kind == jgShort && op != 0x7F
			wantNear := kind == jgNear && op != 0x0F
			if wantShort || wantNear {
				return nil, fmt.Errorf("milestone %s site %q: jgOff points at 0x%02X, not a %v jg opcode", rm.Name, rs.Name, op, rs.Kind)
			}
			if kind == jgNear && rs.JgOff+5 >= len(sig) {
				return nil, fmt.Errorf("milestone %s site %q: near jg needs 6 bytes but sig ends early", rm.Name, rs.Name)
			}
			if rs.ExpectedMatches < 1 {
				return nil, fmt.Errorf("milestone %s site %q: expectedMatches must be >= 1", rm.Name, rs.Name)
			}

			ms.sites = append(ms.sites, affectedSite{
				name:            rs.Name,
				kind:            kind,
				jgRVA:           uint32(rva),
				sig:             sig,
				jgOff:           rs.JgOff,
				expectedMatches: rs.ExpectedMatches,
			})
		}
		out = append(out, ms)
	}
	return out, nil
}

// milestonesForContainer returns only the milestones whose signatures describe
// the given image format ("pe" / "elf"), so a Windows target never probes ELF
// tables and vice-versa.
func milestonesForContainer(all []milestone, container string) []milestone {
	var out []milestone
	for _, ms := range all {
		if ms.container == container {
			out = append(out, ms)
		}
	}
	return out
}
