"""Parse a chrome.dll PE for the fields the 152 port needs:
image base, .text (RVA/raw/size), security directory (stock discriminator),
and the RSDS CodeView key (GUID+age) so we can confirm the PDB matches.
"""
import struct
import sys
from pathlib import Path


def parse_rsds(data: bytes, offset: int):
    d1, d2, d3 = struct.unpack_from("<IHH", data, offset + 4)
    d4 = data[offset + 12 : offset + 20]
    age = struct.unpack_from("<I", data, offset + 20)[0]
    pdb_bytes = data[offset + 24 : offset + 260].split(b"\x00")[0]
    pdb_name = Path(pdb_bytes.decode("utf-8", errors="ignore")).name
    guid_str = f"{d1:08X}{d2:04X}{d3:04X}{d4.hex().upper()}"
    return pdb_name, f"{guid_str}{age:X}"


def pe_info(path: str):
    with open(path, "rb") as f:
        data = f.read()

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00", "not a PE"
    num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    size_of_opt = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    opt = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    assert magic == 0x20B, f"not PE32+ (magic {magic:#x})"

    image_base = struct.unpack_from("<Q", data, opt + 24)[0]

    # Data directories start at opt+112 for PE32+. Entry 4 = SECURITY, 6 = DEBUG.
    sec_rva, sec_size = struct.unpack_from("<II", data, opt + 112 + 4 * 8)
    dbg_rva, dbg_size = struct.unpack_from("<II", data, opt + 112 + 6 * 8)

    sec_off = opt + size_of_opt
    sections = []
    for i in range(num_sections):
        base = sec_off + i * 40
        name = data[base : base + 8].split(b"\x00")[0].decode("latin1")
        v_size, v_addr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, base + 8)
        sections.append((name, v_addr, v_size, raw_ptr, raw_size))

    def rva_to_off(rva):
        for _, v_addr, v_size, raw_ptr, raw_size in sections:
            if v_addr <= rva < v_addr + max(v_size, raw_size):
                return raw_ptr + (rva - v_addr)
        return None

    text = next(s for s in sections if s[0] == ".text")

    # RSDS via debug directory (entry stride 28, type 2 = CODEVIEW).
    pdb_name = rsds_key = None
    dbg_off = rva_to_off(dbg_rva)
    if dbg_off:
        for i in range(dbg_size // 28):
            eo = dbg_off + i * 28
            dtype = struct.unpack_from("<I", data, eo + 12)[0]
            rva, ptr = struct.unpack_from("<II", data, eo + 20)
            if dtype == 2:
                cv = ptr if ptr else rva_to_off(rva)
                if cv and data[cv : cv + 4] == b"RSDS":
                    pdb_name, rsds_key = parse_rsds(data, cv)
                    break

    return {
        "image_base": image_base,
        "text_rva": text[1],
        "text_vsize": text[2],
        "text_raw": text[3],
        "text_rawsize": text[4],
        "text_delta": text[1] - text[3],  # RVA - file offset
        "sec_rva": sec_rva,
        "sec_size": sec_size,
        "is_stock": sec_rva != 0 and sec_size != 0,
        "pdb_name": pdb_name,
        "rsds_key": rsds_key,
    }


if __name__ == "__main__":
    info = pe_info(sys.argv[1])
    for k, v in info.items():
        if isinstance(v, int) and k not in ("sec_size",):
            print(f"{k:14} = {v:#x} ({v})")
        else:
            print(f"{k:14} = {v}")
