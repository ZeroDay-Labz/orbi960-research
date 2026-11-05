#!/usr/bin/env python3
"""Minimal Lua 5.1 bytecode parser — extract constant tables and instruction
streams per function prototype. Enough for forensic diffing; not a full VM."""
from __future__ import annotations
import struct, sys, json
from pathlib import Path

OP_NAMES = [
    "MOVE","LOADK","LOADBOOL","LOADNIL","GETUPVAL","GETGLOBAL","GETTABLE",
    "SETGLOBAL","SETUPVAL","SETTABLE","NEWTABLE","SELF","ADD","SUB","MUL",
    "DIV","MOD","POW","UNM","NOT","LEN","CONCAT","JMP","EQ","LT","LE","TEST",
    "TESTSET","CALL","TAILCALL","RETURN","FORLOOP","FORPREP","TFORLOOP",
    "SETLIST","CLOSE","CLOSURE","VARARG",
]

LUA_TNIL = 0
LUA_TBOOL = 1
LUA_TNUMBER = 3
LUA_TSTRING = 4
# Vendor extension: 4-byte integer constant (value is sint32 LE)
LUA_TINT_VENDOR = 9

class R:
    def __init__(self, data):
        self.d = data; self.i = 0
        self.size_int = 4; self.size_size_t = 4; self.size_ins = 4
        self.size_num = 8; self.num_is_int = 0; self.endian = "<"
    def u8(self):
        v = self.d[self.i]; self.i += 1; return v
    def u32(self):
        v = struct.unpack_from(self.endian+"I", self.d, self.i)[0]; self.i += 4; return v
    def sz(self):
        # size_t
        if self.size_size_t == 4:
            v = struct.unpack_from(self.endian+"I", self.d, self.i)[0]; self.i += 4
        else:
            v = struct.unpack_from(self.endian+"Q", self.d, self.i)[0]; self.i += 8
        return v
    def integer(self):
        return struct.unpack_from(self.endian+"i", self.d, self.i)[0] if self.size_int == 4 else None
    def intval(self):
        v = self.u32()
        return v if v < 0x80000000 else v - 0x100000000
    def number(self):
        v = struct.unpack_from(self.endian+"d", self.d, self.i)[0]; self.i += 8; return v
    def string(self):
        n = self.sz()
        if n == 0: return b""
        s = self.d[self.i:self.i+n-1]  # drop trailing NUL
        self.i += n
        return s

def decode_ins(ins):
    op = ins & 0x3f
    A = (ins >> 6) & 0xff
    C = (ins >> 14) & 0x1ff
    B = (ins >> 23) & 0x1ff
    Bx = (ins >> 14) & 0x3ffff
    sBx = Bx - 131071
    name = OP_NAMES[op] if op < len(OP_NAMES) else f"OP{op}"
    return (op, name, A, B, C, Bx, sBx)

def is_K(x): return x & 0x100  # RK operand -> K if bit 8 set in Lua 5.1 (9-bit)
def K_idx(x): return x & 0xff

def read_header(r):
    sig = r.d[0:4]
    assert sig == b"\x1bLua", f"bad sig {sig!r}"
    r.i = 4
    ver = r.u8()
    fmt = r.u8()
    endian_byte = r.u8()
    r.endian = "<" if endian_byte == 1 else ">"
    r.size_int = r.u8()
    r.size_size_t = r.u8()
    r.size_ins = r.u8()
    r.size_num = r.u8()
    r.num_is_int = r.u8()
    assert ver == 0x51, f"only Lua 5.1 supported, got {ver:#x}"
    return {
        "version": f"5.{ver & 0xf}", "format": fmt, "endian": r.endian,
        "sizeof_int": r.size_int, "sizeof_size_t": r.size_size_t,
        "sizeof_instruction": r.size_ins, "sizeof_number": r.size_num,
        "lua_number_is_int": r.num_is_int,
    }

def read_function(r, parent_name=""):
    src = r.string()
    line_defined = r.intval()
    last_line_defined = r.intval()
    nups = r.u8()
    numparams = r.u8()
    is_vararg = r.u8()
    maxstack = r.u8()
    # code
    ncode = r.intval()
    code = []
    for _ in range(ncode):
        ins = r.u32()
        code.append(ins)
    # constants
    nk = r.intval()
    ks = []
    for _ in range(nk):
        t = r.u8()
        if t == LUA_TNIL:
            ks.append(("nil", None))
        elif t == LUA_TBOOL:
            ks.append(("bool", bool(r.u8())))
        elif t == LUA_TNUMBER:
            ks.append(("num", r.number()))
        elif t == LUA_TSTRING:
            s = r.string()
            try:
                ks.append(("str", s.decode("utf-8")))
            except Exception:
                ks.append(("str", repr(s)))
        elif t == LUA_TINT_VENDOR:
            # vendor-added 4-byte integer constant
            v = r.intval()
            ks.append(("int", v))
        else:
            raise ValueError(f"unknown K type {t} at offset {r.i-1:#x}")
    # nested protos
    np = r.intval()
    protos = []
    for i in range(np):
        protos.append(read_function(r, parent_name + f"/{i}"))
    # debug: line info
    nlines = r.intval()
    lineinfo = [r.intval() for _ in range(nlines)]
    # debug: locals
    nlocvars = r.intval()
    locvars = []
    for _ in range(nlocvars):
        name = r.string()
        start = r.intval(); end = r.intval()
        locvars.append((name.decode("utf-8", "replace"), start, end))
    # debug: upvalue names
    nupvalues = r.intval()
    upvalues = []
    for _ in range(nupvalues):
        upvalues.append(r.string().decode("utf-8", "replace"))
    return {
        "source": src.decode("utf-8", "replace"),
        "line_defined": line_defined,
        "last_line_defined": last_line_defined,
        "nups": nups, "numparams": numparams, "is_vararg": is_vararg,
        "maxstack": maxstack,
        "code": code,
        "constants": ks,
        "protos": protos,
        "lineinfo": lineinfo,
        "locvars": locvars,
        "upvalues": upvalues,
    }

def fmt_K(ks, idx):
    try:
        t, v = ks[idx]
        if t == "str":
            return f'"{v}"'
        return f"{v!r}"
    except Exception:
        return f"K[{idx}]?"

def fmt_RK(ks, x):
    if is_K(x):
        return f"K{K_idx(x)}={fmt_K(ks, K_idx(x))}"
    return f"R{x}"

def dump_function(fn, name="main", depth=0):
    pad = "  " * depth
    out = []
    out.append(f"{pad}== fn {name}  line {fn['line_defined']}-{fn['last_line_defined']}  "
               f"nparams={fn['numparams']} nups={fn['nups']} vararg={fn['is_vararg']} "
               f"maxstack={fn['maxstack']} nconst={len(fn['constants'])} nproto={len(fn['protos'])} ==")
    out.append(f"{pad}constants:")
    for i, (t, v) in enumerate(fn['constants']):
        if t == "str":
            out.append(f"{pad}  K{i}  str  {v!r}")
        else:
            out.append(f"{pad}  K{i}  {t}  {v!r}")
    out.append(f"{pad}code:")
    for pc, ins in enumerate(fn['code']):
        op, nm, A, B, C, Bx, sBx = decode_ins(ins)
        line = fn['lineinfo'][pc] if pc < len(fn['lineinfo']) else 0
        extra = ""
        if nm in ("LOADK", "GETGLOBAL", "SETGLOBAL", "CLOSURE"):
            extra = f"  ; K{Bx}={fmt_K(fn['constants'], Bx) if nm != 'CLOSURE' else 'proto'}"
        elif nm in ("GETTABLE", "SETTABLE", "SELF"):
            extra = f"  ; B={fmt_RK(fn['constants'], B)}  C={fmt_RK(fn['constants'], C)}"
        elif nm in ("ADD","SUB","MUL","DIV","MOD","POW","CONCAT","EQ","LT","LE"):
            extra = f"  ; B={fmt_RK(fn['constants'], B)}  C={fmt_RK(fn['constants'], C)}"
        elif nm in ("CALL","TAILCALL","RETURN"):
            extra = ""
        out.append(f"{pad}  [{pc:3d}] L{line:<4d} {nm:10s} A={A} B={B} C={C} Bx={Bx} sBx={sBx}{extra}")
    for i, p in enumerate(fn['protos']):
        out.append("")
        out.extend(dump_function(p, name=f"{name}/proto{i}", depth=depth+1))
    return out

def main(path, out_prefix):
    data = Path(path).read_bytes()
    # Skip shebang line if present
    off = 0
    if data[:2] == b"#!":
        nl = data.find(b"\n")
        off = nl + 1 if nl >= 0 else 0
    r = R(data[off:])
    hdr = read_header(r)
    fn = read_function(r)
    # Write JSON summary
    def shallow(fn, _depth=0):
        return {
            "source": fn["source"],
            "line_defined": fn["line_defined"],
            "last_line_defined": fn["last_line_defined"],
            "nups": fn["nups"], "numparams": fn["numparams"],
            "is_vararg": fn["is_vararg"], "maxstack": fn["maxstack"],
            "constants": fn["constants"],
            "n_code": len(fn["code"]),
            "protos": [shallow(p, _depth+1) for p in fn["protos"]],
        }
    Path(out_prefix + ".json").write_text(json.dumps({"header": hdr, "main": shallow(fn)}, indent=2, default=str) + "\n")
    # Write text listing
    lines = [f"# {path}  header={hdr}"]
    lines.extend(dump_function(fn, name="MAIN", depth=0))
    Path(out_prefix + ".listing.txt").write_text("\n".join(lines) + "\n")
    print(f"wrote {out_prefix}.{{json,listing.txt}}")

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
