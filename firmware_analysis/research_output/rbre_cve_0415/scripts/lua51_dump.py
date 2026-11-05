#!/usr/bin/env python3
"""Minimal Lua 5.1 bytecode dumper: emits per-function (nested) list of
string constants and flow-control patterns, enough to tell a security-fix
change from a feature extension without a full decompiler.

Output is a tree of functions. Each function shows:
  - source name (if attached)
  - line_defined..last_line_defined
  - numparams, is_vararg, maxstacksize
  - constants: typed list
  - instruction summary: counts of CALL, CLOSURE, GETGLOBAL, SETGLOBAL,
    GETTABLE, SETTABLE, NEWTABLE opcodes (useful for api-shape diffs)
  - nested prototypes, recursively

Lua 5.1 reference: `lopcodes.h`, `lundump.c`.
"""
import sys, struct, json

OP = [
 "MOVE","LOADK","LOADBOOL","LOADNIL","GETUPVAL","GETGLOBAL","GETTABLE",
 "SETGLOBAL","SETUPVAL","SETTABLE","NEWTABLE","SELF","ADD","SUB","MUL","DIV",
 "MOD","POW","UNM","NOT","LEN","CONCAT","JMP","EQ","LT","LE","TEST","TESTSET",
 "CALL","TAILCALL","RETURN","FORLOOP","FORPREP","TFORLOOP","SETLIST","CLOSE",
 "CLOSURE","VARARG",
]

LUA_TNIL, LUA_TBOOLEAN, LUA_TNUMBER, LUA_TSTRING = 0,1,3,4

class R:
    def __init__(self, data, le, intsize, sizesize, instrsize, numsize, int_is_integral):
        self.d = data; self.i = 0; self.le = le
        self.intsize = intsize; self.sizesize = sizesize
        self.instrsize = instrsize; self.numsize = numsize
        self.int_integral = int_is_integral
        self.endian = "<" if le else ">"

    def rd_bytes(self, n):
        v = self.d[self.i:self.i+n]; self.i += n
        return v
    def rd_u(self, n):
        return int.from_bytes(self.rd_bytes(n), "little" if self.le else "big", signed=False)
    def rd_byte(self): return self.rd_u(1)
    def rd_int(self): return self.rd_u(self.intsize)
    def rd_size(self): return self.rd_u(self.sizesize)
    def rd_str(self):
        n = self.rd_size()
        if n == 0: return None
        s = self.rd_bytes(n)
        # Lua strings include terminating NUL
        if s.endswith(b"\x00"): s = s[:-1]
        try: return s.decode("utf-8")
        except UnicodeDecodeError: return s.decode("latin-1", errors="replace")
    def rd_number(self):
        raw = self.rd_bytes(self.numsize)
        if self.numsize == 8 and not self.int_integral:
            return struct.unpack(self.endian+"d", raw)[0]
        if self.numsize == 4 and not self.int_integral:
            return struct.unpack(self.endian+"f", raw)[0]
        return int.from_bytes(raw, "little" if self.le else "big", signed=True)

def decode_instr(raw):
    op = raw & 0x3f
    name = OP[op] if op < len(OP) else f"OP{op}"
    a = (raw >> 6) & 0xff
    c = (raw >> 14) & 0x1ff
    b = (raw >> 23) & 0x1ff
    bx = (raw >> 14) & 0x3ffff
    sbx = bx - 131071
    return name, a, b, c, bx, sbx

def rd_function(r, depth=0):
    f = {}
    f["source"] = r.rd_str()
    f["line_defined"] = r.rd_int()
    f["last_line_defined"] = r.rd_int()
    f["nups"] = r.rd_byte()
    f["numparams"] = r.rd_byte()
    f["is_vararg"] = r.rd_byte()
    f["maxstacksize"] = r.rd_byte()
    n_code = r.rd_int()
    code = []
    op_counts = {}
    getglobal_consts = []
    for _ in range(n_code):
        raw = r.rd_u(r.instrsize)
        name, a, b, c, bx, sbx = decode_instr(raw)
        code.append({"op": name, "a": a, "b": b, "c": c, "bx": bx, "sbx": sbx})
        op_counts[name] = op_counts.get(name, 0) + 1
    # Constants
    n_const = r.rd_int()
    consts = []
    for _ in range(n_const):
        t = r.rd_byte()
        if t == LUA_TNIL: consts.append(("nil", None))
        elif t == LUA_TBOOLEAN: consts.append(("bool", bool(r.rd_byte())))
        elif t == LUA_TNUMBER: consts.append(("num", r.rd_number()))
        elif t == LUA_TSTRING: consts.append(("str", r.rd_str()))
        else: raise RuntimeError(f"unknown const type {t}")
    # Prototypes
    n_proto = r.rd_int()
    protos = [rd_function(r, depth+1) for _ in range(n_proto)]
    # Source line info (int per instruction)
    n_lines = r.rd_int()
    src_lines = [r.rd_int() for _ in range(n_lines)]
    # Locals
    n_loc = r.rd_int()
    locs = []
    for _ in range(n_loc):
        nm = r.rd_str(); sp = r.rd_int(); ep = r.rd_int()
        locs.append({"name": nm, "startpc": sp, "endpc": ep})
    # Upvalues (names)
    n_up = r.rd_int()
    ups = [r.rd_str() for _ in range(n_up)]
    # Bind GETGLOBAL/SETGLOBAL/GETTABLE/SETTABLE/CALL constants for readability
    annotated_code = []
    for i, ins in enumerate(code):
        line = src_lines[i] if i < len(src_lines) else 0
        rec = {"line": line, **ins}
        if ins["op"] in ("GETGLOBAL", "SETGLOBAL"):
            k = consts[ins["bx"]] if ins["bx"] < len(consts) else None
            rec["const"] = k
        elif ins["op"] == "LOADK":
            k = consts[ins["bx"]] if ins["bx"] < len(consts) else None
            rec["const"] = k
        annotated_code.append(rec)
    f["code"] = annotated_code
    f["op_counts"] = op_counts
    f["constants"] = consts
    f["protos"] = protos
    f["locals"] = locs
    f["upvalues"] = ups
    return f

def parse(path):
    data = open(path, "rb").read()
    # skip shebang
    if data.startswith(b"#!"):
        nl = data.index(b"\n")+1
        data = data[nl:]
    assert data[:4] == b"\x1bLua", "not Lua bytecode"
    ver = data[4]
    fmt = data[5]
    hdr = data[6:12]
    endian, intsize, sizesize, instrsize, numsize, int_integral = hdr
    le = bool(endian)
    r = R(data[12:], le, intsize, sizesize, instrsize, numsize, int_integral)
    main = rd_function(r)
    return {"version": hex(ver), "format": fmt, "little_endian": le,
            "intsize": intsize, "sizesize": sizesize,
            "instrsize": instrsize, "numsize": numsize,
            "int_is_integral": bool(int_integral),
            "main": main}

def summarize(f, path="main", depth=0, out=None):
    """Produce a compact per-function list for diffing."""
    if out is None: out = []
    # Extract readable globals accessed
    getg = [c["const"][1] for c in f["code"] if c["op"] == "GETGLOBAL" and c.get("const")]
    setg = [c["const"][1] for c in f["code"] if c["op"] == "SETGLOBAL" and c.get("const")]
    strc = [c[1] for c in f["constants"] if c[0] == "str"]
    numc = [c[1] for c in f["constants"] if c[0] == "num"]
    # Also pull inline LOADK strings in order to preserve call-site flow
    loadk_order = []
    for c in f["code"]:
        if c["op"] == "LOADK" and c.get("const") and c["const"][0] == "str":
            loadk_order.append((c["line"], c["const"][1]))
    out.append({
        "path": path,
        "lines": f"{f['line_defined']}..{f['last_line_defined']}",
        "params": f["numparams"],
        "nups": f["nups"],
        "vararg": f["is_vararg"],
        "op_counts": f["op_counts"],
        "getglobal": getg,
        "setglobal": setg,
        "str_constants": strc,
        "num_constants": numc,
        "loadk_in_flow": loadk_order,
        "upvalues": f["upvalues"],
    })
    for i, p in enumerate(f["protos"]):
        summarize(p, f"{path}/proto[{i}]", depth+1, out)
    return out

if __name__ == "__main__":
    p = sys.argv[1]
    parsed = parse(p)
    summary = summarize(parsed["main"])
    print(json.dumps({"meta": {k:v for k,v in parsed.items() if k!="main"},
                      "functions": summary}, indent=2, default=str))
