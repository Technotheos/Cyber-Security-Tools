#!/usr/bin/env python3
"""asmx - source code -> annotated, syntax-highlighted assembly.

Pure standard library. Wraps the compilers / binutils already on your machine
(gcc, clang, g++, rustc, objdump, c++filt) and adds source mapping, noise
filtering, demangling, highlighting and stats on top.

v2 adds three things on top of that:
  --graph   animated, sci-fi control-flow graph (live signal pulses, loop detection)
  --xray    the deepest low-level view: effects of every instruction, stack frame
            map, call arguments, def-use hints and a vulnerability audit
  --domain  full visual themes, incl. Gojo's "Unlimited Void" and Sukuna's
            "Malevolent Shrine" domain-expansion intros
"""
from __future__ import annotations

import argparse
import dis
import json
import math
import os
import platform
import random
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
import bisect
import codecs
import ctypes
import hashlib
import signal
from array import array
from collections import Counter, defaultdict

__version__ = "2.0.0"

EXIT_FAIL, EXIT_USAGE, EXIT_MISSING = 1, 2, 3
MAX_SOURCE_BYTES = 5 * 1024 * 1024
OPT_LEVELS = ("0", "1", "2", "3", "s", "z", "g", "fast")
EXT_LANG = {".c": "c", ".cc": "c++", ".cpp": "c++", ".cxx": "c++", ".rs": "rust", ".py": "python"}
TOOLS = {"c": ("gcc", "clang", "cc"), "c++": ("g++", "clang++", "c++"), "rust": ("rustc",)}
IS_X86 = platform.machine().lower() in ("x86_64", "amd64", "i386", "i686")
MASK = (1 << 64) - 1



# ===========================================================================
#  OMNI ENGINE  --  build pipeline, ptrace execution recorder, syscalls,
#  heap model, taint + symbolic analysis, DWARF, typed graph, animated UI.
#  Reached from the CLI via --omni (see bottom of this file for the hook).
# ===========================================================================

class AsmxError(Exception):
    def __init__(self, message, code=EXIT_FAIL, detail="", hint=""):
        super().__init__(message)
        self.code, self.detail, self.hint = code, detail, hint




class OmniError(Exception):
    def __init__(self, msg, hint=""):
        super().__init__(msg)
        self.hint = hint


def sh(cmd, timeout=60, cwd=None, inp=None):
    try:
        r = subprocess.run([str(c) for c in cmd], capture_output=True, text=True, errors="replace",
                           timeout=timeout, cwd=cwd, input=inp)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return 127, "", f"{cmd[0]}: not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def hx(v):
    return f"0x{v:x}"


# =========================================================================== #
#  1. BUILD PIPELINE                                                          #
# =========================================================================== #
def find_cc(lang, override):
    if override:
        return override
    for t in (("g++", "clang++", "c++") if lang == "c++" else ("gcc", "clang", "cc")):
        if shutil.which(t):
            return t
    raise OmniError("no C/C++ compiler found", "install gcc or clang")


def _stage(name, cmd, out, cwd, timeout=60):
    t = time.time()
    rc, so, se = sh(cmd, timeout, cwd)
    art = None
    if out and Path(out).exists():
        b = Path(out).read_bytes()
        art = {"path": str(out), "name": Path(out).name, "bytes": len(b), "sha256": hashlib.sha256(b).hexdigest()[:16]}
    return {"stage": name, "cmd": " ".join(shlex.quote(str(c)) for c in cmd), "rc": rc,
            "ms": int((time.time() - t) * 1000), "artifact": art, "stderr": se.strip()[:1800]}


def parse_opt_info(text, srcname):
    """Compiler decisions from gcc -fopt-info-all."""
    kinds = defaultdict(list)
    missed = Counter()
    for ln in text.splitlines():
        m = re.match(r"^(.*?):(\d+):(\d+): (optimized|missed|note): (.*)$", ln)
        if not m or Path(m.group(1)).name != srcname:
            continue
        kind, msg, line = m.group(4), m.group(5).strip(), int(m.group(2))
        low = msg.lower()
        if kind == "missed":
            if "vectoriz" in low or "unroll" in low:
                missed[re.sub(r"\d+", "N", msg)[:90]] += 1
            continue
        if kind != "optimized":
            continue
        cat = ("inlined" if "inlin" in low else "vectorized" if "vectoriz" in low else
               "unrolled" if "unroll" in low else "eliminated" if re.search(r"remov|elimin|dead|propagat|fold", low)
               else "loop" if "loop" in low else "other")
        item = {"line": line, "msg": msg[:140]}
        if item not in kinds[cat] and len(kinds[cat]) < 40:
            kinds[cat].append(item)
    return {"decisions": dict(kinds), "missed": missed.most_common(6)}


def build_pipeline(src: Path, work: Path, opt, cc, flags, static):
    stem = src.stem
    pp = ".ii" if cc.endswith("++") else ".i"
    fx = ["-fcf-protection=none"] if IS_X86 else []
    stages = []
    i_f, s_f, o_f, exe = work / f"{stem}{pp}", work / f"{stem}.s", work / f"{stem}.o", work / "target.bin"
    stages.append(_stage("preprocess", [cc, "-E", src, "-o", i_f, *flags], i_f, src.parent))
    stages.append(_stage("compile", [cc, "-S", f"-O{opt}", "-g", "-fno-pie", *fx, src, "-o", s_f, *flags], s_f, src.parent))
    stages.append(_stage("assemble", [cc, "-c", s_f, "-o", o_f], o_f, work))
    stages.append(_stage("link", [cc, "-no-pie", o_f, "-o", exe, *(["-static"] if static else []), *flags], exe, work))
    for s in stages:
        if s["rc"] != 0:
            raise OmniError(f"{s['stage']} stage failed", s["stderr"] or "(no output)")
    _, _, oi = sh([cc, "-c", f"-O{opt}", "-g", "-fno-pie", *fx, "-fopt-info-all", "-o", "/dev/null", src, *flags], 60, src.parent)
    return stages, exe, parse_opt_info(oi, src.name)


# --------------------------------------------------------------------------- #
#  ELF facts: sections, symbols, relocations, PLT/GOT, libraries               #
# --------------------------------------------------------------------------- #
class SymTab:
    """Address -> symbol for one object (exe or shared lib)."""

    def __init__(self, path: str):
        self.path = path
        best = {}
        _, out, _ = sh(["readelf", "-sW", path])
        for ln in out.splitlines():
            m = re.match(r"^\s*\d+:\s+([0-9a-f]+)\s+(\d+)\s+(\w+)\s+(\w+)\s+\w+\s+(\S+)\s+(\S+)", ln)
            if not m or m.group(5) == "UND" or m.group(3) not in ("FUNC", "OBJECT", "IFUNC", "NOTYPE"):
                continue
            addr, size, name = int(m.group(1), 16), int(m.group(2)), m.group(6).split("@")[0]
            if not addr or not name:
                continue
            cur = best.get(addr)
            key = (name.startswith("_"), len(name))
            if cur is None or key < cur[2]:
                best[addr] = (name, size, key)
        self.addrs = sorted(best)
        self.info = [best[a] for a in self.addrs]
        self.by_name = {best[a][0]: a for a in self.addrs}

    def lookup(self, v):
        i = bisect.bisect_right(self.addrs, v) - 1
        if i < 0:
            return None
        a, (name, size, _) = self.addrs[i], self.info[i]
        if (size and v < a + size) or (not size and v - a < 48):
            return name, v - a
        return None


def elf_facts(exe: str, work: Path):
    facts = {"sections": [], "relocs": [], "needed": [], "libs": [], "plt": {}, "type": "EXEC", "entry": 0}
    _, out, _ = sh(["readelf", "-hW", exe])
    m = re.search(r"Type:\s+(\w+)", out)
    facts["type"] = m.group(1) if m else "EXEC"
    m = re.search(r"Entry point address:\s+(0x[0-9a-f]+)", out)
    facts["entry"] = int(m.group(1), 16) if m else 0
    _, out, _ = sh(["readelf", "-SW", exe])
    for ln in out.splitlines():
        m = re.match(r"^\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-f]{8,16})\s+([0-9a-f]+)\s+([0-9a-f]+)\s+[0-9a-f]+\s+(\S*)", ln)
        if m:
            facts["sections"].append({"name": m.group(1), "type": m.group(2), "addr": int(m.group(3), 16),
                                      "off": int(m.group(4), 16), "size": int(m.group(5), 16), "flags": m.group(6)})
    _, out, _ = sh(["readelf", "-rW", exe])
    sect = ""
    for ln in out.splitlines():
        h = re.match(r"^Relocation section '([^']+)'", ln)
        if h:
            sect = h.group(1).split()[0]
            continue
        m = re.match(r"^([0-9a-f]{8,16})\s+([0-9a-f]+)\s+(\w+)\s+([0-9a-f]+)\s+(\S+)", ln)
        if m:
            facts["relocs"].append({"section": sect, "offset": int(m.group(1), 16), "type": m.group(3),
                                    "sym": m.group(5).split("@")[0]})
    _, out, _ = sh(["readelf", "-dW", exe])
    facts["needed"] = re.findall(r"\(NEEDED\)\s+Shared library: \[(.+?)\]", out)
    _, out, _ = sh(["ldd", exe])
    for ln in out.splitlines():
        m = re.match(r"^\s*(\S+)\s+=>\s+(\S+)", ln)
        if m:
            facts["libs"].append({"soname": m.group(1), "path": m.group(2)})
    # PLT stubs: stub address -> {name, got}
    for sec in (".plt", ".plt.sec", ".plt.got"):
        _, out, _ = sh(["objdump", "-d", "-M", "intel", "-j", sec, exe])
        cur = None
        for ln in out.splitlines():
            h = re.match(r"^([0-9a-f]+) <(.+?)>:", ln)
            if h:
                cur = (int(h.group(1), 16), h.group(2))
                continue
            j = re.search(r"jmp\s+.*#\s+([0-9a-f]+) <([^>]+)>", ln)
            if j and cur:
                nm = cur[1].split("@")[0] if "@" in cur[1] else j.group(2).split("@")[0]
                facts["plt"][cur[0]] = {"name": nm, "got": int(j.group(1), 16)}
                cur = None
    return facts


# --------------------------------------------------------------------------- #
#  DWARF: functions, variables, structs, inlining  (readelf --debug-dump=info) #
# --------------------------------------------------------------------------- #
class Dwarf:
    def __init__(self, exe: str):
        self.dies = {}
        self.funcs = []
        self.structs = []
        self.inl_sites = []
        self.status = {}
        _, out, _ = sh(["readelf", "--debug-dump=info", exe], 60)
        stack, cur = {}, None
        for ln in out.splitlines():
            m = re.match(r"^\s*<(\d+)><([0-9a-f]+)>:\s*Abbrev Number:\s*(\d+)(?:\s*\((\w+)\))?", ln)
            if m:
                d, off = int(m.group(1)), int(m.group(2), 16)
                if m.group(3) == "0":
                    cur = None
                    continue
                cur = {"off": off, "tag": m.group(4) or "", "a": {}, "kids": [], "parent": stack.get(d - 1)}
                self.dies[off] = cur
                stack[d] = off
                if cur["parent"] in self.dies:
                    self.dies[cur["parent"]]["kids"].append(off)
                continue
            m = re.match(r"^\s*<[0-9a-f]+>\s+(DW_AT_\w+)\s*:\s*(.*)$", ln)
            if m and cur is not None:
                cur["a"][m.group(1)] = m.group(2).strip()
        self._extract()

    @staticmethod
    def _s(v):
        m = re.match(r"\((?:indirect|strp|line)[^)]*\):\s*(.*)$", v or "")
        return (m.group(1) if m else (v or "")).strip()

    @staticmethod
    def _i(v, default=None):
        m = re.match(r"\s*(0x[0-9a-fA-F]+|-?\d+)", v or "")
        return int(m.group(1), 0) if m else default

    @staticmethod
    def _ref(v):
        m = re.search(r"<0x([0-9a-f]+)>", v or "")
        return int(m.group(1), 16) if m else None

    def type_name(self, off, depth=0):
        d = self.dies.get(off)
        if d is None or depth > 8:
            return "void"
        t, a = d["tag"], d["a"]
        inner = self._ref(a.get("DW_AT_type"))
        if t == "DW_TAG_base_type":
            return self._s(a.get("DW_AT_name"))
        if t == "DW_TAG_pointer_type":
            return self.type_name(inner, depth + 1) + "*" if inner else "void*"
        if t == "DW_TAG_const_type":
            return "const " + (self.type_name(inner, depth + 1) if inner else "void")
        if t == "DW_TAG_volatile_type":
            return "volatile " + (self.type_name(inner, depth + 1) if inner else "void")
        if t in ("DW_TAG_typedef",):
            return self._s(a.get("DW_AT_name"))
        if t in ("DW_TAG_structure_type", "DW_TAG_union_type", "DW_TAG_class_type"):
            return {"DW_TAG_structure_type": "struct ", "DW_TAG_union_type": "union ", "DW_TAG_class_type": "class "}[t] + (self._s(a.get("DW_AT_name")) or "<anon>")
        if t == "DW_TAG_enumeration_type":
            return "enum " + (self._s(a.get("DW_AT_name")) or "<anon>")
        if t == "DW_TAG_array_type":
            dims = ""
            for k in d["kids"]:
                kd = self.dies[k]
                if kd["tag"] == "DW_TAG_subrange_type":
                    ub = self._i(kd["a"].get("DW_AT_upper_bound"))
                    dims += f"[{ub + 1}]" if ub is not None else "[]"
            return self.type_name(inner, depth + 1) + dims
        return self._s(a.get("DW_AT_name")) or t.replace("DW_TAG_", "")

    def type_size(self, off, depth=0):
        d = self.dies.get(off)
        if d is None or depth > 8:
            return 0
        a = d["a"]
        bs = self._i(a.get("DW_AT_byte_size"))
        if bs is not None:
            return bs
        inner = self._ref(a.get("DW_AT_type"))
        if d["tag"] == "DW_TAG_pointer_type":
            return 8
        if d["tag"] == "DW_TAG_array_type":
            n = 1
            for k in d["kids"]:
                kd = self.dies[k]
                if kd["tag"] == "DW_TAG_subrange_type":
                    ub = self._i(kd["a"].get("DW_AT_upper_bound"))
                    n *= (ub + 1) if ub is not None else 1
            return n * self.type_size(inner, depth + 1)
        return self.type_size(inner, depth + 1) if inner else 0

    def _vars(self, off, out, depth=0):
        for k in self.dies[off]["kids"]:
            kd = self.dies[k]
            if kd["tag"] in ("DW_TAG_variable", "DW_TAG_formal_parameter"):
                loc = re.search(r"DW_OP_fbreg:\s*(-?\d+)", kd["a"].get("DW_AT_location", ""))
                tr = self._ref(kd["a"].get("DW_AT_type"))
                out.append({"name": self._s(kd["a"].get("DW_AT_name")), "fbreg": int(loc.group(1)) if loc else None,
                            "type": self.type_name(tr) if tr else "void", "size": self.type_size(tr) if tr else 0,
                            "param": kd["tag"] == "DW_TAG_formal_parameter", "line": self._i(kd["a"].get("DW_AT_decl_line"), 0),
                            "toff": tr})
            elif kd["tag"] in ("DW_TAG_lexical_block",) and depth < 6:
                self._vars(k, out, depth + 1)

    def _extract(self):
        abstract = {}
        for off, d in self.dies.items():
            if d["tag"] != "DW_TAG_subprogram":
                continue
            a = d["a"]
            name = self._s(a.get("DW_AT_name"))
            lo = self._i(a.get("DW_AT_low_pc"))
            if lo is None:
                if "DW_AT_inline" in a and name:
                    abstract[off] = {"name": name, "sites": 0, "line": self._i(a.get("DW_AT_decl_line"), 0)}
                continue
            hi = self._i(a.get("DW_AT_high_pc"), 0)
            hi = hi if hi > lo else lo + hi
            vs = []
            self._vars(off, vs)
            if not name and a.get("DW_AT_abstract_origin"):
                o = self.dies.get(self._ref(a["DW_AT_abstract_origin"]))
                name = self._s(o["a"].get("DW_AT_name")) if o else ""
            self.funcs.append({"name": name, "low": lo, "high": hi, "vars": vs, "off": off,
                               "line": self._i(a.get("DW_AT_decl_line"), 0), "external": "DW_AT_external" in a})
        for off, d in self.dies.items():
            if d["tag"] == "DW_TAG_inlined_subroutine":
                ref = self._ref(d["a"].get("DW_AT_abstract_origin"))
                if ref in abstract:
                    abstract[ref]["sites"] += 1
                    par, host = d["parent"], ""
                    while par in self.dies:
                        if self.dies[par]["tag"] == "DW_TAG_subprogram":
                            host = self._s(self.dies[par]["a"].get("DW_AT_name"))
                            break
                        par = self.dies[par]["parent"]
                    self.inl_sites.append({"callee": abstract[ref]["name"], "into": host,
                                           "line": self._i(d["a"].get("DW_AT_call_line"), 0)})
            elif d["tag"] in ("DW_TAG_structure_type", "DW_TAG_union_type", "DW_TAG_class_type"):
                nm = self._s(d["a"].get("DW_AT_name"))
                mem = []
                for k in d["kids"]:
                    kd = self.dies[k]
                    if kd["tag"] == "DW_TAG_member":
                        tr = self._ref(kd["a"].get("DW_AT_type"))
                        mem.append({"name": self._s(kd["a"].get("DW_AT_name")), "type": self.type_name(tr) if tr else "void",
                                    "off": self._i(kd["a"].get("DW_AT_data_member_location"), 0),
                                    "size": self.type_size(tr) if tr else 0})
                if mem:
                    self.structs.append({"name": nm or "<anon>", "kind": d["tag"].split("_")[2], "size": self._i(d["a"].get("DW_AT_byte_size"), 0), "members": mem})
        outl = {f["name"] for f in self.funcs}
        for ab in abstract.values():
            self.status[ab["name"]] = ({"state": "inlined", "sites": ab["sites"]} if ab["name"] not in outl and ab["sites"]
                                       else {"state": "eliminated", "sites": 0} if ab["name"] not in outl else {"state": "out-of-line+inlined", "sites": ab["sites"]})
        for f in self.funcs:
            self.status.setdefault(f["name"], {"state": "out-of-line", "sites": 0})

    def func_at(self, pc):
        for f in self.funcs:
            if f["low"] <= pc < f["high"]:
                return f
        return None


class BinInfo:
    def __init__(self, exe: Path, work: Path):
        self.exe = str(exe)
        self.facts = elf_facts(self.exe, work)
        self.sym = SymTab(self.exe)
        self.dwarf = Dwarf(self.exe)
        self.pie = self.facts["type"] == "DYN"
        txt = next((s for s in self.facts["sections"] if s["name"] == ".text"), None)
        if self.dwarf.funcs:
            self.user = sorted((f["low"], f["high"], f["name"]) for f in self.dwarf.funcs)
        elif txt:
            self.user = [(txt["addr"], txt["addr"] + txt["size"], ".text")]
        else:
            self.user = []
        self.user_lo = [u[0] for u in self.user]

    def user_func(self, v):
        i = bisect.bisect_right(self.user_lo, v) - 1
        if i >= 0 and v < self.user[i][1]:
            return self.user[i][2]
        return None


# =========================================================================== #
#  2. EXECUTION ENGINE (ptrace via ctypes)                                    #
# =========================================================================== #
libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.restype = ctypes.c_long
libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]
PT_CONT, PT_KILL, PT_STEP, PT_GETREGS, PT_SETREGS, PT_SETOPTIONS, PT_SYSCALL, PT_GETSIGINFO = 7, 8, 9, 12, 13, 0x4200, 24, 0x4202
RN = "r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs".split()
RI = {n: i for i, n in enumerate(RN)}
RAX, RIP, RSP, RBP, RDI, RSI, RDX, R10, R8, R9, RCX, FSB, GSB = (RI[x] for x in "rax rip rsp rbp rdi rsi rdx r10 r8 r9 rcx fs_base gs_base".split())
GPR = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]


def pt(req, pid, addr=0, data=0):
    return libc.ptrace(req, pid, ctypes.c_void_p(addr), ctypes.c_void_p(data))


def getregs(pid):
    a = (ctypes.c_ulonglong * 27)()
    pt(PT_GETREGS, pid, 0, ctypes.addressof(a))
    return list(a)


def setregs(pid, R):
    a = (ctypes.c_ulonglong * 27)(*R)
    pt(PT_SETREGS, pid, 0, ctypes.addressof(a))


ERRNO = {1: "EPERM", 2: "ENOENT", 4: "EINTR", 9: "EBADF", 11: "EAGAIN", 12: "ENOMEM", 13: "EACCES", 14: "EFAULT", 17: "EEXIST",
         20: "ENOTDIR", 21: "EISDIR", 22: "EINVAL", 24: "EMFILE", 32: "EPIPE", 38: "ENOSYS", 111: "ECONNREFUSED"}
# nr -> (name, arg kinds)  F fd  S cstring  B buffer  I int  X hex/ptr  O open flags  P prot  M mmap flags  N signal
SYS = {0: ("read", "FBI"), 1: ("write", "FBI"), 2: ("open", "SOX"), 3: ("close", "F"), 4: ("stat", "SX"), 5: ("fstat", "FX"), 6: ("lstat", "SX"),
       7: ("poll", "XII"), 8: ("lseek", "FII"), 9: ("mmap", "XIPMFX"), 10: ("mprotect", "XIP"), 11: ("munmap", "XI"), 12: ("brk", "X"),
       13: ("rt_sigaction", "NXX"), 14: ("rt_sigprocmask", "IXX"), 16: ("ioctl", "FXX"), 17: ("pread64", "FBII"), 18: ("pwrite64", "FBII"),
       20: ("writev", "FXI"), 21: ("access", "SI"), 22: ("pipe", "X"), 24: ("sched_yield", ""), 25: ("mremap", "XIIIX"), 28: ("madvise", "XII"),
       32: ("dup", "F"), 33: ("dup2", "FI"), 35: ("nanosleep", "XX"), 39: ("getpid", ""), 41: ("socket", "III"), 42: ("connect", "FXI"),
       43: ("accept", "FXX"), 44: ("sendto", "FBIIXI"), 45: ("recvfrom", "FBIIXX"), 48: ("shutdown", "FI"), 49: ("bind", "FXI"), 50: ("listen", "FI"),
       54: ("setsockopt", "FIIXI"), 56: ("clone", "XXXXX"), 57: ("fork", ""), 58: ("vfork", ""), 59: ("execve", "SXX"), 60: ("exit", "I"),
       61: ("wait4", "IXIX"), 62: ("kill", "IN"), 63: ("uname", "X"), 72: ("fcntl", "FII"), 79: ("getcwd", "XI"), 80: ("chdir", "S"),
       82: ("rename", "SS"), 83: ("mkdir", "SI"), 87: ("unlink", "S"), 89: ("readlink", "SXI"), 96: ("gettimeofday", "XX"), 102: ("getuid", ""),
       104: ("getgid", ""), 107: ("geteuid", ""), 108: ("getegid", ""), 110: ("getppid", ""), 158: ("arch_prctl", "IX"), 186: ("gettid", ""),
       202: ("futex", "XIIXXI"), 218: ("set_tid_address", "X"), 228: ("clock_gettime", "IX"), 231: ("exit_group", "I"), 257: ("openat", "ISOX"),
       262: ("newfstatat", "ISXI"), 273: ("set_robust_list", "XI"), 302: ("prlimit64", "IIXX"), 318: ("getrandom", "XII"), 332: ("statx", "ISIIX"),
       334: ("rseq", "XIII"), 435: ("clone3", "XI")}
OFL = [(1, "O_WRONLY"), (2, "O_RDWR"), (0o100, "O_CREAT"), (0o200, "O_EXCL"), (0o1000, "O_TRUNC"), (0o2000, "O_APPEND"), (0o4000, "O_NONBLOCK"), (0o2000000, "O_CLOEXEC")]
PRF = [(1, "R"), (2, "W"), (4, "X")]
MFL = [(1, "SHARED"), (2, "PRIVATE"), (0x10, "FIXED"), (0x20, "ANON"), (0x100000, "STACK")]


def flags_str(v, table, zero="0"):
    out = [n for b, n in table if v & b]
    return "|".join(out) if out else zero


# --- register / operand tables --------------------------------------------- #
REGMAP = {}
for _b in "abcd":
    REGMAP.update({f"r{_b}x": (f"r{_b}x", 8), f"e{_b}x": (f"r{_b}x", 4), f"{_b}x": (f"r{_b}x", 2), f"{_b}l": (f"r{_b}x", 1), f"{_b}h": (f"r{_b}x", 1)})
for _r in ("si", "di", "bp", "sp"):
    REGMAP.update({f"r{_r}": (f"r{_r}", 8), f"e{_r}": (f"r{_r}", 4), _r: (f"r{_r}", 2), f"{_r}l": (f"r{_r}", 1)})
for _n in range(8, 16):
    REGMAP.update({f"r{_n}": (f"r{_n}", 8), f"r{_n}d": (f"r{_n}", 4), f"r{_n}w": (f"r{_n}", 2), f"r{_n}b": (f"r{_n}", 1), f"r{_n}l": (f"r{_n}", 1)})
for _n in range(32):
    REGMAP.update({f"xmm{_n}": (f"xmm{_n}", 16), f"ymm{_n}": (f"xmm{_n}", 32), f"zmm{_n}": (f"xmm{_n}", 64)})
REGMAP["rip"] = ("rip", 8)
PSIZE = {"BYTE": 1, "WORD": 2, "DWORD": 4, "QWORD": 8, "XMMWORD": 16, "YMMWORD": 32, "ZMMWORD": 64, "TBYTE": 10, "OWORD": 16, "FWORD": 6}
RE_MEM = re.compile(r"^(?:(\w+)\s+PTR\s+)?(?:([a-z]s):)?(?:\[(.*)\]|(-?0x[0-9a-f]+))$")
NONE_MN = {"nop", "endbr64", "hlt", "ud2", "pause", "cpuid", "syscall", "int3", "xgetbv", "rdtsc", "lfence", "mfence", "sfence", "cdq", "cdqe", "cqo",
           "cwde", "cld", "std", "vzeroupper", "vzeroall", "clc", "stc", "sahf", "lahf", "fwait", "emms", "ud1", "rdtscp"}
CC_OP = {"e": "==", "z": "==", "ne": "!=", "nz": "!=", "l": "<", "nge": "<", "le": "<=", "ng": "<=", "g": ">", "nle": ">", "ge": ">=", "nl": ">=",
         "b": "<u", "c": "<u", "nae": "<u", "be": "<=u", "na": "<=u", "a": ">u", "nbe": ">u", "ae": ">=u", "nb": ">=u", "nc": ">=u", "s": "<0", "ns": ">=0"}
INVERT = {"==": "!=", "!=": "==", "<": ">=", ">=": "<", "<=": ">", ">": "<=", "<u": ">=u", ">=u": "<u", "<=u": ">u", ">u": "<=u", "<0": ">=0", ">=0": "<0"}


def split_ops(s):
    out, d, cur = [], 0, ""
    for ch in s:
        if ch == "[":
            d += 1
        elif ch == "]":
            d -= 1
        if ch == "," and d == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def parse_operand(o, mems):
    o = o.strip()
    m = RE_MEM.match(o)
    if m and (m.group(3) is not None or (m.group(4) is not None and m.group(2))):
        size = PSIZE.get((m.group(1) or "").upper(), 8)
        terms, disp = [], 0
        if m.group(3) is not None:
            for sg, tok in re.findall(r"([+-]?)\s*([^+-]+)", m.group(3)):
                tok = tok.strip()
                sign = -1 if sg == "-" else 1
                if "*" in tok:
                    r, sc = tok.split("*")
                    terms.append((REGMAP.get(r.strip(), (r.strip(), 8))[0], int(sc, 0) * sign))
                elif re.match(r"^(0x[0-9a-f]+|\d+)$", tok):
                    disp += sign * int(tok, 0)
                else:
                    terms.append((REGMAP.get(tok, (tok, 8))[0], sign))
        else:
            disp = int(m.group(4), 0)
        mems.append({"size": size, "seg": m.group(2) or "", "terms": terms, "disp": disp})
        return ("m", len(mems) - 1)
    if o in REGMAP:
        return ("r",) + REGMAP[o]
    if re.match(r"^-?(0x)?[0-9a-f]+$", o):
        try:
            return ("i", int(o, 16))
        except ValueError:
            pass
    return ("x", o)


class Plan:
    __slots__ = ("asm", "mn", "cls", "rep", "ops", "mems", "modes", "ln", "rr", "rw", "raw", "cc")


def make_plan(asm, raw, ln):
    s = asm.split("#")[0].strip()
    toks = s.split(None, 1)
    mn, rest, rep = (toks[0] if toks else "nop"), (toks[1] if len(toks) > 1 else ""), False
    while rest and (mn in ("rep", "repz", "repe", "repnz", "repne", "lock", "bnd", "notrack", "cs", "ds", "es", "ss", "fs", "gs", "data16", "addr32") or mn.startswith("rex")):
        rep = rep or mn.startswith("rep")
        t = rest.split(None, 1)
        mn, rest = t[0], (t[1] if len(t) > 1 else "")
    rest = re.sub(r"\s*<[^>]*>\s*$", "", rest)
    mems = []
    ops = [parse_operand(o, mems) for o in split_ops(rest)]
    n = len(ops)
    if mn == "lea": cls = "lea"
    elif mn in ("push", "pop", "call", "leave", "jmp", "xchg"): cls = mn
    elif mn in ("ret", "retn"): cls = "ret"
    elif mn.startswith("j"): cls = "jcc"
    elif mn in ("movs", "stos", "lods", "scas", "cmps"): cls = "str"
    elif mn.startswith("cmov"): cls = "cmov"
    elif mn.startswith("set"): cls = "set"
    elif mn in ("cmp", "test", "bt", "ptest", "vptest") or mn.startswith(("ucomis", "comis", "vucomis", "vcomis")): cls = "cmp"
    elif mn.startswith(("mov", "vmov", "cvt", "vcvt", "lddqu", "vbroadcast", "pbroadcast", "vpbroadcast", "pmovmsk", "vpmovmsk")): cls = "mov"
    elif mn in ("inc", "dec", "neg", "not", "bswap"): cls = "unary"
    elif mn in ("mul", "div", "idiv") or (mn == "imul" and n == 1): cls = "muldiv"
    elif mn in NONE_MN or mn.startswith(("nop", "prefetch", "endbr")): cls = "none"
    elif n >= 2: cls = "alu"
    else: cls = "other"
    modes = {}
    vex = mn.startswith("v")
    for i, o in enumerate(ops):
        if o[0] != "m" or cls in ("lea", "none"):
            continue
        if cls == "mov": m = "w" if i == 0 else "r"
        elif cls in ("alu", "xchg", "unary"): m = ("w" if vex else "rw") if i == 0 else ("rw" if cls == "xchg" else "r")
        elif cls == "set" or cls == "pop": m = "w"
        elif cls == "str":
            m = {"movs": {0: "w", 1: "r"}, "stos": {0: "w"}, "lods": {1: "r"}, "scas": {1: "r"}, "cmps": {0: "r", 1: "r"}}[mn].get(i, "")
        else: m = "r"
        if m:
            modes[o[1]] = m
    rr, rw = set(), set()
    for m in mems:
        rr.update(t[0] for t in m["terms"])
    for i, o in enumerate(ops):
        if o[0] != "r":
            continue
        dest = i == 0 and cls in ("mov", "alu", "unary", "pop", "xchg", "set", "cmov", "lea")
        if dest:
            rw.add(o[1])
        if not (dest and (cls in ("mov", "pop", "set", "lea") or (cls == "alu" and vex))):
            rr.add(o[1])
    if cls == "muldiv":
        rr.add("rax"); rw.update(("rax", "rdx"))
    for x in ("rsp", "rip"):
        rr.discard(x); rw.discard(x)
    p = Plan()
    p.asm, p.mn, p.cls, p.rep, p.ops, p.mems, p.modes, p.ln, p.raw = asm.split("#")[0].strip(), mn, cls, rep, ops, mems, modes, ln, raw
    p.rr, p.rw = tuple(rr), tuple(rw)
    p.cc = CC_OP.get(mn[1:]) if cls == "jcc" else None
    return p


class Maps:
    """/proc/pid/maps tracker + per-object symbol lookup."""

    def __init__(self, pid, info: BinInfo):
        self.pid, self.info, self.reg, self.starts, self.base, self.syms, self.cache = pid, info, [], [], {}, {}, {}
        self.lines = []
        self.syms[info.exe] = info.sym

    def refresh(self):
        try:
            self.lines = Path(f"/proc/{self.pid}/maps").read_text().splitlines()
        except OSError:
            return
        reg = []
        for ln in self.lines:
            m = re.match(r"([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+([0-9a-f]+)\s+\S+\s+\d+\s*(.*)$", ln)
            if m:
                reg.append((int(m.group(1), 16), int(m.group(2), 16), m.group(3), int(m.group(4), 16), m.group(5).strip()))
        reg.sort()
        self.reg, self.starts = reg, [r[0] for r in reg]
        for s, e, pm, off, path in reg:
            if path.startswith("/") and off == 0 and path not in self.base:
                self.base[path] = 0 if (path == self.info.exe and not self.info.pie) else s
        self.cache.clear()

    def find(self, a):
        i = bisect.bisect_right(self.starts, a) - 1
        if i >= 0 and a < self.reg[i][1]:
            return self.reg[i]
        return None

    def vaddr(self, a):
        r = self.find(a)
        if r and r[4].startswith("/") and r[4] in self.base:
            return r[4], a - self.base[r[4]]
        return None

    def sym(self, a):
        if a in self.cache:
            return self.cache[a]
        res = None
        pv = self.vaddr(a)
        if pv:
            path, v = pv
            if path == self.info.exe:
                stub = self.info.facts["plt"]
                for sa, d in stub.items():
                    if sa <= v < sa + 16:
                        res = (d["name"] + "@plt", v - sa, os.path.basename(path))
                        break
            if res is None:
                if path not in self.syms:
                    self.syms[path] = SymTab(path)
                s = self.syms[path].lookup(v)
                res = (s[0], s[1], os.path.basename(path)) if s else (f"{os.path.basename(path)}+{v:#x}", -1, os.path.basename(path))
        else:
            r = self.find(a)
            res = (f"[{r[4].strip('[]') or 'anon'}]" if r else "??", -1, "")
        self.cache[a] = res
        return res

    def snapshot(self):
        out = []
        for s, e, pm, off, path in self.reg:
            out.append([s, e, pm, os.path.basename(path) if path.startswith("/") else path or "anon"])
        return out


class Disasm:
    def __init__(self, maps: Maps):
        self.maps, self.cache, self.bad = maps, {}, set()

    def get(self, rip):
        p = self.cache.get(rip)
        if p is None and rip not in self.bad:
            self.fill(rip)
            p = self.cache.get(rip)
            if p is None:
                self.bad.add(rip)
        return p

    def fill(self, rip):
        pv = self.maps.vaddr(rip)
        if not pv:
            return
        path, v = pv
        base = rip - v
        rc, out, _ = sh(["objdump", "-d", "-M", "intel", "-w", f"--start-address={v:#x}", f"--stop-address={v + 640:#x}", path], 20)
        for ln in out.splitlines():
            parts = ln.split("\t")
            if len(parts) < 3 or ":" not in parts[0]:
                continue
            try:
                a = int(parts[0].strip().rstrip(":"), 16) + base
            except ValueError:
                continue
            raw = parts[1].strip()
            if a not in self.cache:
                self.cache[a] = make_plan(parts[2].strip(), raw, len(raw.split()))


def tmerge(ts):
    n = max((len(t) for t in ts), default=0)
    if not n:
        return ()
    out = []
    for i in range(n):
        v = None
        for t in ts:
            if i < len(t) and t[i] is not None:
                v = t[i]
                break
        out.append(v)
    return tuple(out) if any(x is not None for x in out) else ()


def fmt_sym(e):
    s, m, a = e
    if not s:
        return hx(a & MASK) if a >= 0 else str(a)
    t = s if m == 1 else f"{s}*{m}"
    return t + (f"+{a}" if a > 0 else f"{a}" if a < 0 else "")


ALLOCS = {"malloc", "free", "calloc", "realloc"}
FMT_SINK = {"printf": 0, "fprintf": 1, "sprintf": 1, "snprintf": 2, "dprintf": 1, "syslog": 1}
EXEC_SINK = {"system": 0, "popen": 0, "execl": 0, "execlp": 0, "execv": 0, "execvp": 0}
SIZE_SINK = {"memcpy": 2, "memmove": 2, "strncpy": 2, "memset": 2, "malloc": 0, "calloc": 0, "realloc": 1, "read": 2, "fread": 1, "alloca": 0}
COPY_SINK = {"strcpy", "strcat", "gets", "sprintf", "vsprintf", "stpcpy"}
ARGREG = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class Tracer:
    def __init__(self, info: BinInfo, argv, env, stdin_data: bytes, max_steps, timeout, work: Path, tag="run"):
        self.info, self.argv, self.env, self.stdin = info, argv, env, stdin_data
        self.max_steps, self.deadline, self.work, self.tag = max_steps, time.time() + timeout, work, tag
        # recording
        self.steps = 0
        self.rips = array("Q")
        self.mem = []              # (step, R/W, addr, size, value, rip)
        self.events = []           # condensed timeline
        self.keyframes = []
        self.syscalls = []
        self.findings, self.fkeys = [], set()
        self.maps_snaps = []
        self.calls = Counter()     # (caller, callee) -> n
        self.fn_steps = Counter()
        self.fn_obj = {}
        self.plt_res = {}
        self.succ = Counter()      # user (rip,next) -> n
        self.hits = Counter()      # user rip -> n
        self.defuse = Counter()    # (def_rip,use_rip,via,tainted)
        self.var_access = Counter()  # (rip,var,kind)
        self.heap_access = Counter()  # (rip,alloc_id,kind)
        self.ranges = defaultdict(list)
        self.sym_events, self.constraints, self.flows, self.tainted_branch = [], [], [], {}
        self.tainted_args = defaultdict(set)
        self.indirect = defaultdict(set)
        self.exc = []
        self.sources = []          # label id -> (tag, offset)
        self.fds = {0: {"kind": "stdin", "path": "stdin"}, 1: {"kind": "stdout", "path": "stdout"}, 2: {"kind": "stderr", "path": "stderr"}}
        self.fdnodes = {k: dict(v, reads=0, writes=0, bytes=0) for k, v in self.fds.items()}
        self.fdpos = Counter()
        self.mmaps, self.threads = [], []
        self.exit = {"code": None, "signal": None, "truncated": False}
        self.output = ""
        # state
        self.rt, self.mt, self.rs, self.ms = {}, {}, {}, {}
        self.flag_t, self.last_cmp = (), None
        self.frames, self.slots = [], {}
        self.allocs, self.blocks, self.bstarts = [], {}, []
        self._symseen, self._fvc, self.last_regs = set(), {}, [0] * 27
        self.aid = 0
        self.pending_alloc = []
        self.alloc_depth = 0
        self.lastdef, self.lastdef_mem = {}, {}
        self.pending_plt = {}
        self.cur_span = None
        self.n_user_ev = 0
        self.sys_pending = None
        self.main_regs = None
        self.pid = None

    # ---------------------------------------------------------------- helpers
    def rd(self, a, n):
        try:
            return os.pread(self.memfd, n, a)
        except (OSError, OverflowError, ValueError):
            return None

    def rdi(self, a, n):
        b = self.rd(a, n)
        return int.from_bytes(b, "little") if b else None

    def cstr(self, a, n=160):
        b = self.rd(a, n) or b""
        return b.split(b"\0")[0].decode("latin1")

    def finding(self, sev, kind, title, detail, rip, labels=(), extra=None):
        key = (kind, rip, title[:40])
        if key in self.fkeys:
            return
        self.fkeys.add(key)
        w = self.witness(labels)
        if extra:
            w.update(extra)
        self.findings.append({"sev": sev, "kind": kind, "title": title, "detail": detail, "step": self.steps, "rip": rip, "witness": w})

    def witness(self, labels):
        by = defaultdict(set)
        for l in labels:
            if l is not None and l < len(self.sources):
                tag, off = self.sources[l]
                by[tag].add(off)
        srcs = {}
        for tag, offs in by.items():
            offs, rng = sorted(offs), []
            for o in offs:
                if rng and o == rng[-1][1] + 1:
                    rng[-1][1] = o
                else:
                    rng.append([o, o])
            srcs[tag] = ",".join(f"{a}" if a == b else f"{a}-{b}" for a, b in rng[:8])
        return {"input_bytes": srcs}

    def labels_at(self, a, n):
        out = set()
        for i in range(n):
            v = self.mt.get(a + i)
            if v is not None:
                out.add(v)
        return out

    def symof(self, rip):
        return self.maps.sym(rip)

    def snapshot_maps(self, why):
        self.maps.refresh()
        if len(self.maps_snaps) < 60:
            self.maps_snaps.append({"step": self.steps, "why": why, "maps": self.maps.snapshot()})

    # ---------------------------------------------------------------- process control
    def spawn(self):
        sin = self.work / f"{self.tag}.stdin"
        sin.write_bytes(self.stdin)
        self.out_path, self.err_path = self.work / f"{self.tag}.stdout", self.work / f"{self.tag}.stderr"
        pid = os.fork()
        if pid == 0:
            try:
                libc.personality(0x0040000)
                os.dup2(os.open(str(sin), os.O_RDONLY), 0)
                os.dup2(os.open(str(self.out_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644), 1)
                os.dup2(os.open(str(self.err_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644), 2)
                libc.ptrace(0, 0, None, None)
                os.execve(self.info.exe, [self.info.exe] + self.argv, self.env)
            finally:
                os._exit(127)
        os.waitpid(pid, 0)
        pt(PT_SETOPTIONS, pid, 0, 0x100001)   # EXITKILL | TRACESYSGOOD
        self.pid = pid
        self.memfd = os.open(f"/proc/{pid}/mem", os.O_RDWR)
        self.maps = Maps(pid, self.info)
        self.dis = Disasm(self.maps)
        self.maps.refresh()

    def finish(self, st):
        if os.WIFEXITED(st):
            self.exit["code"] = os.WEXITSTATUS(st)
        elif os.WIFSIGNALED(st):
            self.exit["signal"] = signal.Signals(os.WTERMSIG(st)).name
        self.close_span()
        for p in (self.out_path, self.err_path):
            pass
        self.output = (self.out_path.read_text(errors="replace") if self.out_path.exists() else "")[:4000]
        self.errout = (self.err_path.read_text(errors="replace") if self.err_path.exists() else "")[:2000]
        self.pid = None

    def phase1(self):
        """Fast syscall-only run up to main(): loader, libc init."""
        main = self.info.sym.by_name.get("main")
        if main is None:
            return True
        base = self.maps.base.get(self.info.exe, 0) if self.info.pie else 0
        main += base
        orig = self.rd(main, 1)
        os.pwrite(self.memfd, b"\xcc", main)
        sig, insys, cur = 0, False, None
        while True:
            pt(PT_SYSCALL, self.pid, 0, sig)
            sig = 0
            _, st = os.waitpid(self.pid, 0)
            if os.WIFEXITED(st) or os.WIFSIGNALED(st):
                self.finish(st)
                return False
            s = os.WSTOPSIG(st)
            if s == (signal.SIGTRAP | 0x80):
                R = getregs(self.pid)
                if not insys:
                    cur = self.sys_begin(R, -1)
                    insys = True
                else:
                    insys = False
                    if cur:
                        self.sys_end(cur, R[RAX])
            elif s == signal.SIGTRAP:
                R = getregs(self.pid)
                if R[RIP] - 1 == main:
                    os.pwrite(self.memfd, orig, main)
                    R[RIP] -= 1
                    setregs(self.pid, R)
                    return True
            else:
                sig = s

    # ---------------------------------------------------------------- syscalls
    def sys_begin(self, R, step):
        nr = R[RI["orig_rax"]] if step < 0 else R[RAX]
        name, kinds = SYS.get(nr, (f"syscall_{nr}", ""))
        args = [R[RDI], R[RSI], R[RDX], R[R10], R[R8], R[R9]]
        rec = {"nr": nr, "name": name, "kinds": kinds, "args": args, "step": step, "rip": R[RIP], "fn": ""}
        # taint sinks seen at entry
        if name in ("write", "send", "sendto", "pwrite64") and args[2] < 1 << 16:
            labs = self.labels_at(args[1], min(args[2], 4096))
            if labs:
                fd = self.fds.get(args[0], {})
                self.flows.append({"src": self.witness(labs)["input_bytes"], "sink": f"{name}(fd {args[0]}:{fd.get('path', '?')})", "step": self.steps})
                if fd.get("kind") in ("socket", "file"):
                    self.finding("MEDIUM", "taint-sink", f"input reaches {name}() on {fd.get('kind')} {fd.get('path', '')}", "attacker-influenced bytes leave the process", R[RIP], labs)
        if name in ("open", "openat", "unlink", "rename", "execve", "mkdir", "chdir", "access"):
            ptr = args[1] if name == "openat" else args[0]
            labs = self.labels_at(ptr, 64)
            if labs:
                crit = name == "execve"
                self.finding("CRITICAL" if crit else "HIGH", "taint-sink", f"input reaches {name}() path: \"{self.cstr(ptr, 80)}\"",
                             "tainted file name / program" , R[RIP], labs)
        rec["fn"] = self.symof(R[RIP])[0] if self.pid else ""
        return rec

    def fmt_arg(self, k, v, rec, res):
        if k == "F":
            f = self.fds.get(v)
            return f"fd {v}" + (f"<{f['path']}>" if f and f["kind"] in ("file", "socket") else "")
        if k == "S":
            return '"' + self.cstr(v, 96).encode("unicode_escape").decode() + '"' if v else "NULL"
        if k == "B":
            n = rec["args"][2]
            if rec["name"] in ("read", "recvfrom", "pread64") and res is not None and res >= 0 and res < 1 << 40:
                n = res
            data = self.rd(v, min(n, 24)) if n else b""
            return "buf=" + (repr(data.decode("latin1"))[:40] if data else "NULL") + ("…" if n > 24 else "")
        if k == "O":
            return flags_str(v & 0xffffffff, OFL, "O_RDONLY")
        if k == "P":
            return flags_str(v, PRF, "NONE")
        if k == "M":
            return flags_str(v, MFL)
        if k == "N":
            try:
                return signal.Signals(v).name
            except ValueError:
                return str(v)
        if k == "I":
            return str(v - (1 << 64) if v >= 1 << 63 else v)
        return hx(v) if v else "0"

    def sys_end(self, rec, res):
        name, kinds, args = rec["name"], rec["kinds"], rec["args"]
        sres = None if res is None else (res - (1 << 64) if res >= 1 << 63 else res)
        argt = ", ".join(self.fmt_arg(k, args[i], rec, sres) for i, k in enumerate(kinds))
        if sres is None:
            rtxt = "∅"
        elif -4096 < sres < 0:
            rtxt = f"-{ERRNO.get(-sres, 'E' + str(-sres))}"
        else:
            rtxt = str(sres) if name not in ("mmap", "brk", "mremap") else hx(sres)
        rec["text"], rec["res"] = f"{name}({argt}) → {rtxt}", sres
        # fd table & taint sources
        ok = sres is not None and sres >= 0
        if name in ("open", "openat") and ok:
            path = self.cstr(args[1] if name == "openat" else args[0], 200)
            self.fds[sres] = {"kind": "file", "path": path}
            self.fdnodes.setdefault(sres, {"kind": "file", "path": path, "reads": 0, "writes": 0, "bytes": 0})
            self.fdnodes[sres].update(kind="file", path=path)
            rec["node"] = path
        elif name == "socket" and ok:
            dom = {1: "UNIX", 2: "INET", 10: "INET6"}.get(args[0], str(args[0]))
            self.fds[sres] = {"kind": "socket", "path": f"{dom}/{'STREAM' if args[1] & 15 == 1 else 'DGRAM' if args[1] & 15 == 2 else args[1]}"}
            self.fdnodes[sres] = dict(self.fds[sres], reads=0, writes=0, bytes=0)
        elif name == "accept" and ok:
            self.fds[sres] = {"kind": "socket", "path": "accepted"}
            self.fdnodes[sres] = dict(self.fds[sres], reads=0, writes=0, bytes=0)
        elif name in ("dup", "dup2") and ok and args[0] in self.fds:
            self.fds[sres] = self.fds[args[0]]
        elif name == "close" and ok:
            self.fds.pop(args[0], None)
        elif name == "connect":
            sa = self.rd(args[1], 16) or b""
            if len(sa) >= 8 and sa[0] == 2:
                self.fds.setdefault(args[0], {"kind": "socket", "path": ""})["path"] = f"{'.'.join(str(b) for b in sa[4:8])}:{int.from_bytes(sa[2:4], 'big')}"
                self.fdnodes[args[0]] = dict(self.fds[args[0]], reads=0, writes=0, bytes=0)
                rec["text"] += f"  [{self.fds[args[0]]['path']}]"
        if name in ("clone", "fork", "vfork", "clone3") and ok:
            self.threads.append({"kind": name, "child": sres, "step": self.steps})
        fdi = self.fds.get(args[0], {})
        sysfile = fdi.get("kind") == "file" and fdi.get("path", "").startswith(("/lib", "/usr", "/etc/ld", "/proc", "/sys", "/etc/locale"))
        if name in ("read", "pread64", "recvfrom") and ok and sres > 0 and rec["step"] >= 0 and not sysfile:
            fd = args[0]
            fdn = self.fdnodes.setdefault(fd, {"kind": "file", "path": f"fd{fd}", "reads": 0, "writes": 0, "bytes": 0})
            fdn["reads"] += 1
            fdn["bytes"] += sres
            tag = "stdin" if fd == 0 else f"fd{fd}"
            for i in range(min(sres, 65536)):
                self.sources.append((tag, self.fdpos[fd] + i))
                lid = len(self.sources) - 1
                self.mt[args[1] + i] = lid
                self.ms[args[1] + i] = (f"{'in' if fd == 0 else tag}[{self.fdpos[fd] + i}]", 1, 0)
            self.fdpos[fd] += sres
        if name in ("write", "sendto", "pwrite64") and ok:
            fdn = self.fdnodes.setdefault(args[0], {"kind": "file", "path": f"fd{args[0]}", "reads": 0, "writes": 0, "bytes": 0})
            fdn["writes"] += 1
            fdn["bytes"] += sres
        if name in ("mmap", "munmap", "mprotect", "brk", "mremap"):
            if name == "mmap" and ok:
                self.mmaps.append({"addr": sres & MASK, "len": args[1], "prot": self.fmt_arg("P", args[2], rec, 0), "flags": self.fmt_arg("M", args[3], rec, 0), "fd": args[4] if args[4] < 1 << 63 else -1, "step": self.steps})
            if self.pid:
                self.snapshot_maps(name)
        self.syscalls.append(rec)
        self.close_span()
        self.events.append({"t": "y", "s": rec["step"], "text": rec["text"], "name": name})

    # ---------------------------------------------------------------- main loop
    def run(self):
        self.spawn()
        self.snapshot_maps("exec")
        if not self.phase1():
            return self
        self.snapshot_maps("main")
        R = getregs(self.pid)
        self.main_regs = list(R)
        self.on_main(R)
        self.loop(R)
        return self

    def on_main(self, R):
        argc, argvp = R[RDI], R[RSI]
        self.rs["rdi"] = ("argc", 1, 0)
        self.frames.append({"fn": "main", "ret": None, "cfa": R[RSP] + 8, "slot": R[RSP], "user": True})
        self.slots[R[RSP]] = "main"
        self.argv_seen = []
        for i in range(min(argc, 16)):
            p = self.rdi(argvp + 8 * i, 8)
            if not p:
                break
            s = self.cstr(p, 200)
            self.argv_seen.append(s)
            if i >= 1:
                for j in range(len(s)):
                    self.sources.append((f"argv[{i}]", j))
                    self.mt[p + j] = len(self.sources) - 1
        ep = argvp + 8 * (argc + 1)
        self.env_seen = []
        for i in range(64):
            p = self.rdi(ep + 8 * i, 8)
            if not p:
                break
            self.env_seen.append(self.cstr(p, 120))

    def close_span(self):
        sp = self.cur_span
        if sp and not sp.get("closed"):
            sp["closed"] = True
            sp["chg"] = {n: [sp["r0"][i], self.last_regs[i]] for n, i in RI.items() if n in GPR + ["rsp"] and sp["r0"][i] != self.last_regs[i]}
            sp.pop("r0", None)
        self.cur_span = None

    def loop(self, R):
        pid, info = self.pid, self.info
        pend_sig = 0
        self.last_regs = R
        sysrec = None
        while self.steps < self.max_steps:
            if time.time() > self.deadline:
                self.exit["truncated"] = "timeout"
                break
            rip = R[RIP]
            pl = self.dis.get(rip)
            if rip not in self.maps.cache and self.maps.find(rip) is None:
                self.maps.refresh()
                pl = self.dis.get(rip)
            user = info.user_func(rip - (self.maps.base.get(info.exe, 0) if info.pie else 0)) is not None and self.maps.find(rip) is not None and self.maps.find(rip)[4] == info.exe
            eas, rvals = [], {}
            if pl is not None and pl.mems:
                for m in pl.mems:
                    a = m["disp"]
                    for r, sc in m["terms"]:
                        a += (rip + pl.ln) if r == "rip" else (R[RI[r]] * sc if r in RI else 0)
                    if m["seg"] == "fs": a += R[FSB]
                    elif m["seg"] == "gs": a += R[GSB]
                    eas.append(a & MASK)
                for idx, mode in pl.modes.items():
                    if "r" in mode:
                        rvals[idx] = self.rdi(eas[idx], min(pl.mems[idx]["size"], 16))
            sp_before = R[RSP]
            if pl is not None and pl.mn == "syscall":
                sysrec = self.sys_begin(R, self.steps)
            if pl is not None and pl.cls in ("ret", "pop"):
                stk = self.rdi(sp_before, 8)
            if pl is not None and pl.cls == "ret":
                self.check_ret(sp_before, stk, rip)
            pt(PT_STEP, pid, 0, pend_sig)
            pend_sig = 0
            _, st = os.waitpid(pid, 0)
            if os.WIFEXITED(st) or os.WIFSIGNALED(st):
                if sysrec:
                    self.sys_end(sysrec, None)
                self.rips.append(rip)
                self.finish(st)
                return
            sig = os.WSTOPSIG(st)
            if sig != signal.SIGTRAP:
                pend_sig = sig
                if sig in (signal.SIGSEGV, signal.SIGBUS, signal.SIGILL, signal.SIGFPE, signal.SIGABRT):
                    self.on_crash(sig, rip, R)
                R = getregs(pid)
                continue
            R2 = getregs(pid)
            self.rips.append(rip)
            step = self.steps
            self.record(step, rip, R, R2, pl, eas, rvals, user, stk if (pl is not None and pl.cls in ("ret", "pop")) else None)
            self.last_regs = R2
            if sysrec:
                self.sys_end(sysrec, R2[RAX])
                if len(self.keyframes) < 1500:
                    self.add_keyframe(step, R2)
                sysrec = None
            self.steps += 1
            R = R2
            self.last_regs = R2
        else:
            self.exit["truncated"] = f"max-steps {self.max_steps}"
        if self.exit["truncated"] and self.pid:
            self.close_span()
            os.kill(self.pid, signal.SIGKILL)
            os.waitpid(self.pid, 0)
            self.output = (self.out_path.read_text(errors="replace") if self.out_path.exists() else "")[:4000]
            self.errout = (self.err_path.read_text(errors="replace") if self.err_path.exists() else "")[:2000]
            self.pid = None

    def add_keyframe(self, step, R):
        stack = [self.rdi(R[RSP] + 8 * i, 8) or 0 for i in range(16)]
        self.keyframes.append({"step": step, "ev": len(self.events), "rip": R[RIP], "rsp": R[RSP], "rbp": R[RBP], "stack": stack,
                               "heap": [len(self.live_allocs()), sum(a["size"] for a in self.live_allocs())]})

    def live_allocs(self):
        return [a for a in self.allocs if a["state"] == "live"]

    def on_crash(self, sig, rip, R):
        si = (ctypes.c_char * 128)()
        pt(PT_GETSIGINFO, self.pid, 0, ctypes.addressof(si))
        fault = int.from_bytes(bytes(si)[16:24], "little")
        labs = set()
        for r in ("rip", "rax", "rdi", "rsi"):
            labs.update(x for x in self.rt.get(r, ()) if x is not None)
        sv = signal.Signals(sig).name
        self.finding("CRITICAL" if labs else "HIGH", "crash", f"{sv} in {self.symof(rip)[0]}" + (f" (fault address {fault:#x})" if sig == signal.SIGSEGV else ""),
                     "the recorded input drives the process into a fatal signal" + (" with attacker-tainted registers" if labs else ""), rip, labs, {"fault_addr": fault})

    def check_ret(self, sp, val, rip):
        if val is None:
            return
        labs = self.labels_at(sp, 8)
        if labs:
            self.finding("CRITICAL", "control-hijack", f"return address is attacker-controlled ({val:#x})",
                         "ret pops a value that came from input bytes: the program counter is now attacker-chosen", rip, labs, {"target": val})
        self.slots.pop(sp, None)
        if self.frames and len(self.frames) > 1:
            self.frames.pop()


# --------------------------------------------------------------------------- #
#  per-instruction engine: memory events, taint, symbolic, heap, calls         #
# --------------------------------------------------------------------------- #
REGIDX = [(n, RI[n]) for n in GPR + ["rsp"]]


def _tget(self, op, pl, eas):
    k = op[0]
    if k == "r":
        t = self.rt.get(op[1], ())
        return t[:op[2]] if t else ()
    if k == "m":
        if not self.mt:
            return ()
        a, sz = eas[op[1]], min(pl.mems[op[1]]["size"], 64)
        t = tuple(self.mt.get(a + i) for i in range(sz))
        return t if any(x is not None for x in t) else ()
    return ()


def _tset(self, op, t, pl, eas):
    k = op[0]
    if k == "r":
        if t:
            self.rt[op[1]] = t
        else:
            self.rt.pop(op[1], None)
    elif k == "m":
        a, sz = eas[op[1]], min(pl.mems[op[1]]["size"], 64)
        for i in range(sz):
            lab = t[i] if i < len(t) else None
            if lab is None:
                self.mt.pop(a + i, None)
            else:
                self.mt[a + i] = lab


def taint_step(self, pl, R, R2, eas, rip):
    c, ops = pl.cls, pl.ops
    g, s = self._tget, self._tset
    if c == "mov" and len(ops) > 1:
        s(ops[0], g(ops[1], pl, eas), pl, eas)
    elif c == "alu":
        if pl.mn in ("xor", "sub", "pxor", "vpxor", "xorps") and len(ops) > 1 and ops[0] == ops[1]:
            t = ()
        else:
            srcs = [g(o, pl, eas) for o in ops[1:]]
            t = tmerge(srcs if pl.mn.startswith("v") else [g(ops[0], pl, eas)] + srcs)
        s(ops[0], t, pl, eas)
        self.flag_t = t
    elif c == "cmp" and len(ops) > 1:
        self.flag_t = tmerge([g(ops[0], pl, eas), g(ops[1], pl, eas)])
    elif c == "unary":
        s(ops[0], g(ops[0], pl, eas), pl, eas)
    elif c == "lea" and len(ops) > 1 and ops[1][0] == "m":
        s(ops[0], tmerge([self.rt.get(r, ()) for r, _ in pl.mems[ops[1][1]]["terms"]]), pl, eas)
    elif c == "push" and ops:
        t = g(ops[0], pl, eas)
        for i in range(8):
            lab = t[i] if i < len(t) else None
            if lab is None: self.mt.pop(R[RSP] - 8 + i, None)
            else: self.mt[R[RSP] - 8 + i] = lab
    elif c == "pop" and ops:
        t = tuple(self.mt.get(R[RSP] + i) for i in range(8))
        s(ops[0], t if any(x is not None for x in t) else (), pl, eas)
    elif c == "call":
        for i in range(8):
            self.mt.pop(R[RSP] - 8 + i, None)
    elif c == "leave":
        t = tuple(self.mt.get(R[RBP] + i) for i in range(8))
        self.rt["rbp"] = t if any(x is not None for x in t) else ()
        if not self.rt["rbp"]: self.rt.pop("rbp")
    elif c == "xchg" and len(ops) > 1:
        a, b = g(ops[0], pl, eas), g(ops[1], pl, eas)
        s(ops[0], b, pl, eas); s(ops[1], a, pl, eas)
    elif c == "cmov" and len(ops) > 1:
        s(ops[0], tmerge([g(ops[0], pl, eas), g(ops[1], pl, eas)]), pl, eas)
    elif c == "set" and ops:
        s(ops[0], (), pl, eas)
    elif c == "muldiv" and ops:
        t = tmerge([self.rt.get("rax", ()), g(ops[0], pl, eas)])
        for r in ("rax", "rdx"):
            if t: self.rt[r] = t
            else: self.rt.pop(r, None)
    elif c == "str" and len(eas) >= 1:
        if pl.mn == "movs" and len(eas) > 1:
            for i in range(pl.mems[0]["size"]):
                v = self.mt.get(eas[1] + i)
                if v is None: self.mt.pop(eas[0] + i, None)
                else: self.mt[eas[0] + i] = v
        elif pl.mn == "stos" and len(ops) > 1:
            s(ops[0], g(ops[1], pl, eas), pl, eas)
        elif pl.mn == "lods" and len(ops) > 1:
            s(ops[0], g(ops[1], pl, eas), pl, eas)
    elif pl.mn == "syscall":
        for r in ("rax", "rcx", "r11"):
            self.rt.pop(r, None)
    if c == "jcc" and self.flag_t:
        labs = [x for x in self.flag_t if x is not None]
        d = self.tainted_branch.setdefault(rip, {"n": 0, "labels": set(), "asm": pl.asm, "first": self.steps})
        d["n"] += 1
        if len(d["labels"]) < 6:
            d["labels"].update(labs[:3])
    if c in ("call", "jmp") and ops and ops[0][0] in ("r", "m"):
        t = g(ops[0], pl, eas)
        if t:
            self.finding("CRITICAL", "control-hijack", f"indirect {c} target comes from input", f"{pl.asm} jumps through attacker-controlled data",
                         rip, [x for x in t if x is not None], {"target": R2[RIP]})


def _sget(self, op, pl, eas, R):
    if op[0] == "i":
        return ("", 0, op[1])
    if op[0] == "r":
        return self.rs.get(op[1])
    if op[0] == "m":
        return self.ms.get(eas[op[1]])
    return None


def _sset(self, op, e, eas):
    if op[0] == "r":
        if e and e[0]: self.rs[op[1]] = e
        else: self.rs.pop(op[1], None)
    elif op[0] == "m":
        if e and e[0]: self.ms[eas[op[1]]] = e
        else: self.ms.pop(eas[op[1]], None)


def sym_step(self, pl, R, R2, eas, rip):
    c, ops, mn = pl.cls, pl.ops, pl.mn
    get = lambda o: self._sget(o, pl, eas, R)
    out = None
    dst = ops[0] if ops else None
    if c == "mov" and len(ops) > 1:
        out = get(ops[1]); self._sset(dst, out, eas)
    elif c == "lea" and len(ops) > 1 and ops[1][0] == "m":
        m = pl.mems[ops[1][1]]
        sym, mul, add = None, 0, m["disp"]
        ok = True
        for r, sc in m["terms"]:
            e = self.rs.get(r)
            if e:
                if sym is None or sym == e[0]:
                    sym, mul, add = e[0], mul + e[1] * sc, add + e[2] * sc
                else:
                    ok = False
            else:
                add += ((rip + pl.ln) if r == "rip" else R[RI[r]] * sc if r in RI else 0)
        out = (sym, mul, add) if ok and sym else None
        self._sset(dst, out, eas)
    elif c == "alu" and len(ops) > 1:
        a, b = get(dst), get(ops[-1])
        if mn in ("xor", "sub") and ops[0] == ops[1]:
            out = None
        elif mn in ("add", "sub") and a and b:
            sg = 1 if mn == "add" else -1
            if a[0] and not b[0]: out = (a[0], a[1], a[2] + sg * b[2])
            elif b[0] and not a[0] and mn == "add": out = (b[0], b[1], b[2] + a[2])
        elif mn == "imul":
            src, imm = (get(ops[1]), get(ops[2])) if len(ops) == 3 else (a, b)
            if src and src[0] and imm and not imm[0]: out = (src[0], src[1] * imm[2], src[2] * imm[2])
        elif mn in ("shl", "sal") and a and a[0] and b and not b[0]:
            out = (a[0], a[1] << b[2], a[2] << b[2])
        self._sset(dst, out, eas)
    elif c == "unary" and dst:
        a = get(dst)
        if a and a[0]:
            out = {"inc": (a[0], a[1], a[2] + 1), "dec": (a[0], a[1], a[2] - 1), "neg": (a[0], -a[1], -a[2])}.get(mn)
        self._sset(dst, out, eas)
    elif c == "push" and ops:
        e = get(ops[0])
        if e and e[0]: self.ms[R[RSP] - 8] = e
        else: self.ms.pop(R[RSP] - 8, None)
    elif c == "pop" and ops:
        self._sset(dst, self.ms.get(R[RSP]), eas)
    elif c == "cmp" and len(ops) > 1:
        a, b = get(ops[0]), get(ops[1])
        if pl.mn == "test" and ops[0] == ops[1] and a and a[0]:
            self.last_cmp = (a, 0)
        elif a and a[0] and b and not b[0]:
            self.last_cmp = (a, b[2])
        else:
            self.last_cmp = None
    elif c == "jcc" and self.last_cmp and pl.cc:
        e, k = self.last_cmp
        taken = R2[RIP] != rip + pl.ln
        op = pl.cc if taken else INVERT[pl.cc]
        lhs = e[0] if (e[1] == 1) else fmt_sym((e[0], e[1], 0))
        rhs = k - e[2] if e[1] == 1 else k - e[2]
        text = f"{lhs} {op} {rhs}" if "0" not in op or op in ("<0", ">=0") and False else f"{lhs} {op} {rhs}"
        if op in ("<0", ">=0"):
            text = f"{fmt_sym(e)} {op}"
        if self.constraints and self.constraints[-1]["rip"] == rip and self.constraints[-1]["text"] == text:
            self.constraints[-1]["n"] += 1
        elif len(self.constraints) < 300:
            self.constraints.append({"rip": rip, "text": text, "n": 1, "step": self.steps, "taken": taken})
        self.last_cmp = None
    if c in ("mov", "lea", "alu", "unary") and out and out[0] and (out[1] != 1 or out[2] != 0) and len(self.sym_events) < 1500:
        txt = fmt_sym(out)
        nm = dst[1] if dst[0] == "r" else "mem"
        key = (rip, txt)
        if key not in self._symseen:
            self._symseen.add(key)
            self.sym_events.append({"step": self.steps, "rip": rip, "dst": nm, "expr": txt})


def on_mem(self, k, a, sz, v, rip, pl, step, user):
    # ---- return-address smash
    if k == "W" and self.slots and pl.cls != "call":
        for s, fn in list(self.slots.items()):
            if a <= s < a + sz:
                labs = self.labels_at(s, 8)
                self.finding("CRITICAL", "stack-smash", f"saved return address of {fn}() overwritten at {s:#x}",
                             f"{pl.asm} wrote {sz} bytes over the return slot", rip, labs, {"slot": s, "value": v})
    # ---- heap model
    if self.alloc_depth == 0 and self.bstarts:
        i = bisect.bisect_right(self.bstarts, a) - 1
        if i >= 0:
            rec = self.blocks[self.bstarts[i]]
            st, size = rec["ptr"], rec["size"]
            if rec["state"] == "freed" and st <= a < st + max(size, 1):
                labs = self.labels_at(a, 1) if k == "W" else ()
                self.finding("HIGH", "use-after-free", f"{'write' if k == 'W' else 'read'} of freed block #{rec['id']} ({size}B) at +{a - st}",
                             f"block freed at step {rec['freed_step']}; {pl.asm}", rip, labs, {"block": rec["id"], "alloc": hx(st)})
            elif rec["state"] == "live":
                usable = ((size + 8 + 15) // 16) * 16 - 8
                if st <= a < st + max(size, 1):
                    self.heap_access[(rip, rec["id"], k)] += 1
                elif a + sz > st + usable and a < st + usable + 16:
                    labs = self.labels_at(a, sz) if k == "W" else ()
                    self.finding("HIGH" if k == "W" else "MEDIUM", "heap-overflow",
                                 f"heap {'overflow' if k == 'W' else 'over-read'} past block #{rec['id']} ({size}B)",
                                 f"{pl.asm} touches {a:#x}: {a - (st + size)} bytes beyond the allocation", rip, labs, {"block": rec["id"]})
    # ---- variable naming (DWARF + CFA)
    if user and self.frames:
        fr = self.frames[-1]
        fv = self._fvars(rip)
        for var in fv:
            va = fr["cfa"] + var["fbreg"]
            if va <= a < va + max(var["size"], 1):
                self.var_access[(rip, var["name"], k)] += 1
                if k == "W" and sz <= 8 and v is not None and len(self.ranges[(rip, "v", var["name"])]) < 600:
                    self.ranges[(rip, "v", var["name"])].append(v)
                return var["name"]
    return None


def _fvars(self, rip):
    if rip in self._fvc:
        return self._fvc[rip]
    base = self.maps.base.get(self.info.exe, 0) if self.info.pie else 0
    f = self.info.dwarf.func_at(rip - base)
    vs = [v for v in f["vars"] if v["fbreg"] is not None and v["name"]] if f else []
    self._fvc[rip] = vs
    return vs


def new_alloc(self, ptr, n, step, site):
    self.aid += 1
    rec = {"id": self.aid, "ptr": ptr, "size": n, "step": step, "site": site, "state": "live", "freed_step": None, "free_site": None}
    self.allocs.append(rec)
    if ptr not in self.blocks:
        bisect.insort(self.bstarts, ptr)
    self.blocks[ptr] = rec
    self.close_span()
    self.events.append({"t": "h", "s": step, "text": f"malloc({n}) → {ptr:#x}  [#{rec['id']}]", "id": rec["id"]})


def do_free(self, p, step, site, rip):
    if not p:
        return
    rec = self.blocks.get(p)
    if rec is None:
        i = bisect.bisect_right(self.bstarts, p) - 1
        inner = i >= 0 and self.blocks[self.bstarts[i]]["ptr"] < p < self.blocks[self.bstarts[i]]["ptr"] + self.blocks[self.bstarts[i]]["size"]
        self.finding("HIGH", "invalid-free", f"free({p:#x}) of a pointer malloc never returned" + (" (interior pointer)" if inner else ""), "undefined behaviour in the allocator", site)
    elif rec["state"] == "freed":
        self.finding("CRITICAL", "double-free", f"double free of block #{rec['id']} ({rec['size']}B)",
                     f"first freed at step {rec['freed_step']}, again at step {step}", site, (), {"block": rec["id"], "alloc": hx(p)})
    else:
        rec["state"], rec["freed_step"], rec["free_site"] = "freed", step, site
        self.close_span()
        self.events.append({"t": "h", "s": step, "text": f"free({p:#x})  [#{rec['id']}]", "id": rec["id"]})


def norm_fn(n):
    n = re.sub(r"_chk$", "", n)
    n = re.sub(r"_(avx2|evex|sse2|ssse3|sse4_\d|sse42|avx512\w*|unaligned\w*|erms|generic|avx)(_\w+)?$", "", n)
    return re.sub(r"^__(?=[a-z])", "", n).replace("_IO_puts", "puts")


def entry_hook(self, name, R2, step, rip_from, user_site=True):
    a = [R2[RDI], R2[RSI], R2[RDX], R2[RCX], R2[R8], R2[R9]]
    if name in ALLOCS and self.alloc_depth == 0:
        ret = self.rdi(R2[RSP], 8) or 0
        if name == "free":
            self.do_free(a[0], step, ret, rip_from)
            self.alloc_depth += 1
            self.pending_alloc.append({"fn": "free", "ret": ret, "rsp": R2[RSP], "a": a})
        else:
            self.alloc_depth += 1
            self.pending_alloc.append({"fn": name, "ret": ret, "rsp": R2[RSP], "a": a})
    if not user_site:
        return a
    if name in FMT_SINK:
        ptr = a[FMT_SINK[name]]
        labs = self.labels_at(ptr, 24)
        if labs:
            self.finding("HIGH", "format-string", f"input used as format string in {name}()", f"format \"{self.cstr(ptr, 48)}\" is attacker-influenced → %n / %s read-write primitive", rip_from, labs)
    if name in EXEC_SINK:
        labs = self.labels_at(a[EXEC_SINK[name]], 32)
        if labs:
            self.finding("CRITICAL", "command-injection", f"input reaches {name}(\"{self.cstr(a[0], 60)}\")", "attacker-controlled command line", rip_from, labs)
    if name in COPY_SINK:
        src = a[0] if name == "gets" else a[1]
        labs = self.labels_at(src, 64) if name != "gets" else set()
        n = len(self.cstr(src, 512)) if name != "gets" else -1
        self.finding("HIGH" if name == "gets" else "MEDIUM", "unbounded-copy", f"{name}() with {'unbounded stdin' if name == 'gets' else 'attacker data'} ({n if n >= 0 else '?'} bytes) into {a[0]:#x}",
                     "no length limit: whether this smashes memory depends on the destination size", rip_from, labs, {"dest": hx(a[0]), "len": n})
    if name in SIZE_SINK:
        t = self.rt.get(ARGREG[SIZE_SINK[name]], ())
        if t and any(x is not None for x in t):
            self.finding("MEDIUM", "tainted-size", f"attacker-controlled size passed to {name}() = {a[SIZE_SINK[name]]}", "length/size derives from input", rip_from, [x for x in t if x is not None])
    return a


def alloc_return(self, R2, step):
    pa = self.pending_alloc.pop()
    self.alloc_depth -= 1
    n, a = pa["fn"], pa["a"]
    rax = R2[RAX]
    if n == "malloc" and rax: self.new_alloc(rax, a[0], step, pa["ret"])
    elif n == "calloc" and rax: self.new_alloc(rax, a[0] * a[1], step, pa["ret"])
    elif n == "realloc" and rax:
        if a[0] and a[0] in self.blocks and self.blocks[a[0]]["state"] == "live":
            self.blocks[a[0]]["state"], self.blocks[a[0]]["freed_step"], self.blocks[a[0]]["free_site"] = "freed", step, pa["ret"]
        self.new_alloc(rax, a[1], step, pa["ret"])


def record(self, step, rip, R, R2, pl, eas, rvals, user, stk):
    nxt = R2[RIP]
    sy = self.symof(rip)
    fn = sy[0]
    self.fn_steps[fn] += 1
    self.fn_obj[fn] = sy[2]
    if pl is None:
        self._event(step, rip, fn, sy, None, R, R2, [], user)
        return
    c = pl.cls
    # ---- memory events
    mev = []
    for idx, mode in pl.modes.items():
        sz = pl.mems[idx]["size"]
        if "r" in mode:
            mev.append(["R", eas[idx], sz, rvals.get(idx)])
        if "w" in mode:
            mev.append(["W", eas[idx], sz, self.rdi(eas[idx], min(sz, 16))])
    if c in ("push", "call"):
        mev.append(["W", R[RSP] - 8, 8, self.rdi(R[RSP] - 8, 8)])
    elif c in ("pop", "ret"):
        mev.append(["R", R[RSP], 8, stk])
    elif c == "leave":
        mev.append(["R", R[RBP], 8, self.rdi(R[RBP], 8)])
    # ---- propagate
    tflag = False
    if self.mt or self.rt or self.flag_t:
        tflag = any(self.rt.get(r) for r in pl.rr) or any(m[0] == "R" and self.labels_at(m[1], min(m[2], 16)) for m in mev)
        self.taint_step(pl, R, R2, eas, rip)
    if user:
        self.sym_step(pl, R, R2, eas, rip)
    # ---- memory consumers
    names = []
    for k, a, sz, v in mev:
        if len(self.mem) < 400000:
            self.mem.append((step, k, a, sz, v, rip))
        nm = self.on_mem(k, a, sz, v, rip, pl, step, user)
        if nm:
            names.append(nm)
    # ---- def-use + ranges (user code)
    if user:
        self.hits[rip] += 1
        self.succ[(rip, nxt)] += 1
        if len(self.defuse) < 30000:
            for r in pl.rr:
                d = self.lastdef.get(r)
                if d is not None:
                    self.defuse[(d, rip, r, tflag)] += 1
            for k, a, sz, v in mev:
                if k == "R" and a in self.lastdef_mem:
                    self.defuse[(self.lastdef_mem[a], rip, "mem", tflag)] += 1
        for r in pl.rw:
            self.lastdef[r] = rip
            if r in GPR:
                lst = self.ranges[(rip, "r", r)]
                if len(lst) < 600:
                    lst.append(R2[RI[r]])
        for k, a, sz, v in mev:
            if k == "W":
                self.lastdef_mem[a] = rip
    # ---- call / ret / entry
    if c == "call":
        cs = self.symof(nxt)
        top = self.frames[-1]["fn"] if self.frames else "?"
        self.calls[(top, cs[0])] += 1
        self.frames.append({"fn": cs[0], "ret": rip + pl.ln, "cfa": R[RSP], "slot": R2[RSP], "user": False})
        self.slots[R2[RSP]] = cs[0]
        if user and not self.info.user_func(nxt - (self.maps.base.get(self.info.exe, 0) if self.info.pie else 0)):
            self.lastdef["rax"] = self.lastdef["rdx"] = "fn:" + cs[0]
        if cs[0].endswith("@plt"):
            self.pending_plt[rip + pl.ln] = cs[0]
            self.entry_hook(norm_fn(cs[0][:-4]), R2, step, rip, user)
        if pl.ops and pl.ops[0][0] in ("r", "m"):
            self.indirect[(fn, rip)].add(cs[0])
        if cs[0] in ("__cxa_throw", "_Unwind_RaiseException", "__cxa_allocate_exception") and len(self.exc) < 40:
            self.exc.append({"fn": cs[0], "from": fn, "step": step})
    elif c == "ret" and pl.ops:
        pass
    if nxt in self.pending_plt:
        stub = self.pending_plt.pop(nxt)
        nm = stub[:-4]
        for d in self.info.facts["plt"].values():
            if d["name"] == nm:
                v = self.rdi(d["got"], 8)
                if v:
                    r = self.symof(v)
                    self.plt_res[stub] = {"resolved": r[0], "obj": r[2], "addr": v, "got": d["got"]}
                break
    if nxt != rip + pl.ln or c == "call":
        n2 = self.symof(nxt)
        if n2[1] == 0:
            if not fn.endswith("@plt") and not n2[0].endswith("@plt"):
                self.entry_hook(norm_fn(n2[0]), R2, step, rip, user)
            if self.info.dwarf.func_at(nxt - (self.maps.base.get(self.info.exe, 0) if self.info.pie else 0)) and self.rt:
                for r in ARGREG[:4]:
                    if self.rt.get(r) or (R2[RI[r]] > 0x1000 and self.labels_at(R2[RI[r]], 16)):
                        self.tainted_args[n2[0]].add(r)
    if self.pending_alloc and nxt == self.pending_alloc[-1]["ret"] and R2[RSP] == self.pending_alloc[-1]["rsp"] + 8:
        self.alloc_return(R2, step)
    if step % 250 == 0 and len(self.keyframes) < 1500:
        self.add_keyframe(step, R2)
    self._event(step, rip, fn, sy, pl, R, R2, mev, user, names)


def _event(self, step, rip, fn, sy, pl, R, R2, mev, user, names=()):
    if user and pl is not None and self.n_user_ev < 9000:
        self.close_span()
        self.n_user_ev += 1
        chg = {n: [R[i], R2[i]] for n, i in REGIDX if R[i] != R2[i]}
        self.events.append({"t": "i", "s": step, "rip": rip, "asm": pl.asm, "raw": pl.raw, "fn": fn, "chg": chg,
                            "mem": [[k, a, sz, v] for k, a, sz, v in mev][:4], "var": list(names)[:2]})
        return
    sp = self.cur_span
    if sp and sp["fn"] == fn:
        sp["n"] += 1
    else:
        self.close_span()
        self.cur_span = sp = {"t": "s", "s": step, "fn": fn, "obj": sy[2], "n": 1, "r0": list(R)}
        self.events.append(sp)
    self.last_regs = R2


for _f in (_tget, _tset, taint_step, _sget, _sset, sym_step, on_mem, _fvars, new_alloc, do_free, entry_hook, alloc_return, record, _event):
    setattr(Tracer, _f.__name__.lstrip("_") if _f.__name__.startswith(("_tget", "_tset", "_sget", "_sset")) else _f.__name__, _f)
Tracer._tget, Tracer._tset, Tracer._sget, Tracer._sset, Tracer._fvars, Tracer._event = _tget, _tset, _sget, _sset, _fvars, _event


# =========================================================================== #
#  5/6. WHOLE-PROGRAM STRUCTURE + TYPED GRAPH MODEL                           #
# =========================================================================== #
def basic_blocks(tr: Tracer, info: BinInfo):
    """Derive basic blocks for user functions from the recorded successor edges."""
    leaders = defaultdict(set)
    heads = defaultdict(lambda: None)
    fn_of = {}
    for rip in tr.hits:
        fn_of[rip] = tr.symof(rip)[0]
    for rip in tr.hits:
        leaders[fn_of[rip]].add(rip)
    for (a, b), n in tr.succ.items():
        fa, fb = fn_of.get(a), fn_of.get(b)
        if fb and (fb != fa or b != a + 1):
            leaders[fb].add(b)
    blocks = {}
    for fn, lp in leaders.items():
        addrs = sorted(lp)
        ends = {addrs[i]: addrs[i + 1] for i in range(len(addrs) - 1)}
        for i, a in enumerate(addrs):
            bid = f"{fn}:{a:#x}"
            blocks[bid] = {"id": bid, "fn": fn, "lo": a, "hi": ends.get(a), "hits": sum(tr.hits[x] for x in tr.hits if x >= a and (ends.get(a) is None or x < ends[a]) and fn_of.get(x) == fn)}
    bedges = []
    for (a, b), n in tr.succ.items():
        fa, fb = fn_of.get(a), fn_of.get(b)
        if fa is None or fb is None:
            continue
        ba = next((bid for bid, bd in blocks.items() if bd["fn"] == fa and bd["lo"] <= a < (bd["hi"] or 1 << 63)), None)
        bb = next((bid for bid, bd in blocks.items() if bd["fn"] == fb and bd["lo"] == b), None)
        if ba and bb and ba != bb:
            bedges.append({"from": ba, "to": bb, "n": n})
    return blocks, bedges


def build_graph(tr: Tracer, info: BinInfo, src_name: str):
    nodes, edges = {}, []

    def add(nid, typ, **kw):
        if nid not in nodes:
            nodes[nid] = {"id": nid, "type": typ, **kw}
        else:
            nodes[nid].update(kw)
        return nid

    def E(a, b, typ, **kw):
        edges.append({"from": a, "to": b, "type": typ, **kw})

    add("process", "process", label=Path(info.exe).name, pid=tr.pid, exit=tr.exit, argv=getattr(tr, "argv_seen", []))
    add("thread:main", "thread", label="main thread", parent="process")
    E("process", "thread:main", "spawn")
    for th in tr.threads:
        tid = f"thread:{th['child']}"
        add(tid, "thread", label=f"{th['kind']} → tid {th['child']}", parent="process", step=th["step"])
        E("thread:main", tid, "spawn", step=th["step"])

    fstatus = info.dwarf.status
    allf = set(tr.fn_steps) | set(tr.hits and {tr.symof(r)[0] for r in tr.hits})
    for fn in sorted(allf):
        obj = tr.fn_obj.get(fn, info.exe if fn in info.sym.by_name else "")
        isuser = bool(info.dwarf.func_at(info.sym.by_name.get(fn, -1))) if fn in info.sym.by_name else False
        nid = f"fn:{fn}"
        add(nid, "function", label=fn, steps=tr.fn_steps.get(fn, 0), obj=os.path.basename(obj) if obj else "?",
            user=isuser, tainted_args=sorted(tr.tainted_args.get(fn, ())), compiler=fstatus.get(fn))
    for (a, b), n in tr.calls.items():
        E(f"fn:{a}", f"fn:{b}", "call", n=n)
    for (fn, rip), targets in tr.indirect.items():
        for t in targets:
            E(f"fn:{fn}", f"fn:{t}", "indirect-call", rip=rip)

    blocks, bedges = basic_blocks(tr, info)
    for bid, b in blocks.items():
        add(bid, "block", parent=f"fn:{b['fn']}", lo=hx(b["lo"]), hi=hx(b["hi"]) if b["hi"] else None, hits=b["hits"])
        E(f"fn:{b['fn']}", bid, "contains")
    for be in bedges:
        E(be["from"], be["to"], "cflow", n=be["n"])

    for name, fd in tr.fdnodes.items():
        nid = f"fd:{name}"
        typ = {"file": "file", "socket": "socket"}.get(fd.get("kind"), "stream")
        add(nid, typ, label=fd.get("path", str(name)), reads=fd.get("reads", 0), writes=fd.get("writes", 0), bytes=fd.get("bytes", 0))
        if fd.get("reads"):
            E(nid, "thread:main", "read", n=fd["reads"])
        if fd.get("writes"):
            E("thread:main", nid, "write", n=fd["writes"])
    syscnt = Counter(s["name"] for s in tr.syscalls)
    for nm, n in syscnt.items():
        nid = f"sys:{nm}"
        add(nid, "syscall", label=nm, n=n)
        E("thread:main", nid, "syscall", n=n)

    for lib in info.facts["libs"]:
        nid = f"lib:{lib['soname']}"
        add(nid, "library", label=lib["soname"], path=lib["path"])
        E("process", nid, "link")

    for a in tr.allocs:
        nid = f"heap:{a['id']}"
        add(nid, "heap_block", label=f"#{a['id']} {a['size']}B", size=a["size"], state=a["state"],
            alloc_step=a["step"], free_step=a["freed_step"], addr=hx(a["ptr"]))
        site = tr.symof(a["site"])[0] if a["site"] else "?"
        E(f"fn:{site}", nid, "alloc", step=a["step"])
        for (rip, aid, k), n in tr.heap_access.items():
            if aid == a["id"]:
                E(f"fn:{tr.symof(rip)[0]}", nid, "read" if k == "R" else "write", n=n)

    for f in tr.findings:
        nid = f"finding:{len(nodes)}"
        add(nid, "finding", label=f["title"], sev=f["sev"], kind=f["kind"], step=f["step"], detail=f["detail"], witness=f["witness"])
        site = tr.symof(f["rip"])[0] if isinstance(f["rip"], int) else "?"
        E(f"fn:{site}", nid, "finds", step=f["step"])
        for tag in f["witness"]["input_bytes"]:
            snode = f"src:{tag}"
            add(snode, "input_source", label=tag)
            E(snode, nid, "taint", offsets=f["witness"]["input_bytes"][tag])

    for (d, u, via, t), n in tr.defuse.items():
        if t and n >= 1 and isinstance(d, int) and isinstance(u, int):
            E(f"fn:{tr.symof(d)[0]}", f"fn:{tr.symof(u)[0]}", "dataflow", via=via, n=n, tainted=True)

    struct_nodes = []
    for s in info.dwarf.structs[:60]:
        nid = f"struct:{s['name']}:{s['size']}"
        add(nid, "struct", label=s["name"], size=s["size"], members=s["members"], kind=s["kind"])
        struct_nodes.append(nid)
    return {"nodes": list(nodes.values()), "edges": edges}, blocks, bedges


def call_graph_text(tr: Tracer):
    out, seen = [], set()
    order = sorted(tr.calls, key=lambda k: -tr.calls[k])
    children = defaultdict(list)
    for (a, b), n in tr.calls.items():
        children[a].append((b, n))
    roots = set(children) - {b for lst in children.values() for b, _ in lst}

    def walk(fn, d, path):
        if d > 6 or fn in path:
            return [f"{'  ' * d}{fn} (recursion)" if fn in path else ""]
        rows = []
        kids = sorted(children.get(fn, []), key=lambda x: -x[1])
        for k, n in kids[:8]:
            rows.append(f"{'  ' * d}└─ {k}  ×{n}")
            rows += walk(k, d + 1, path | {fn})
        return rows
    for r in sorted(roots or {"main"}):
        out.append(r)
        out += walk(r, 1, set())
    return out


# --------------------------------------------------------------------------- #
#  two-run diff                                                                #
# --------------------------------------------------------------------------- #
def diff_runs(a: Tracer, b: Tracer):
    n = min(len(a.rips), len(b.rips))
    lo, hi = 0, n
    # binary search for first divergence for speed on long traces
    step = 4096
    i = 0
    while i < n and a.rips[i] == b.rips[i]:
        i += 1
    point = i
    window = []
    for j in range(max(0, point - 3), min(n, point + 12)):
        window.append({"step": j, "a": hx(a.rips[j]) if j < len(a.rips) else None, "b": hx(b.rips[j]) if j < len(b.rips) else None,
                       "sym_a": a.symof(a.rips[j])[0] if j < len(a.rips) else None, "sym_b": b.symof(b.rips[j])[0] if j < len(b.rips) else None})
    sys_a = [s["text"] for s in a.syscalls]
    sys_b = [s["text"] for s in b.syscalls]
    k = 0
    while k < min(len(sys_a), len(sys_b)) and sys_a[k] == sys_b[k]:
        k += 1
    return {
        "diverged_at_step": point if point < n else None,
        "window": window,
        "len_a": len(a.rips), "len_b": len(b.rips),
        "syscall_divergence": k if k < min(len(sys_a), len(sys_b)) else None,
        "syscalls_a_tail": sys_a[k:k + 6], "syscalls_b_tail": sys_b[k:k + 6],
        "exit_a": a.exit, "exit_b": b.exit,
        "findings_only_a": [f["title"] for f in a.findings if f["title"] not in {g["title"] for g in b.findings}],
        "findings_only_b": [f["title"] for f in b.findings if f["title"] not in {g["title"] for g in a.findings}],
    }


def to_dot(graph):
    shape = {"process": "doubleoctagon", "thread": "octagon", "function": "box", "block": "ellipse",
             "file": "folder", "socket": "component", "syscall": "diamond", "heap_block": "note",
             "finding": "octagon", "library": "tab", "struct": "record", "input_source": "cds"}
    color = {"finding": "#ff5566", "function": "#8be9fd", "syscall": "#ffcc66", "heap_block": "#bd93f9",
             "file": "#6ee7b0", "socket": "#6ee7b0", "library": "#626496", "input_source": "#ff79c6"}
    lines = ["digraph asmx_omni {", '  bgcolor="#0b0d1a"; fontcolor="white"; node [style=filled,fontsize=10];']
    for n in graph["nodes"]:
        if n["type"] == "block":
            continue
        lines.append(f'  "{n["id"]}" [label="{n.get("label", n["id"])[:40]}",shape={shape.get(n["type"], "box")},'
                     f'fillcolor="{color.get(n["type"], "#2a2d55")}",fontcolor="#0b0d1a"];')
    for e in graph["edges"]:
        if e["from"].startswith(("fn:",)) is False and e["type"] == "contains":
            continue
        if any(x.split(":")[0] == "block" and ":" in x for x in (e["from"],)) and e["type"] in ("contains", "cflow"):
            continue
        lines.append(f'  "{e["from"]}" -> "{e["to"]}" [label="{e["type"]}",color="#555a99",fontcolor="#8888bb",fontsize=8];')
    lines.append("}")
    return "\n".join(lines)
HTML_TEMPLATE = r"""<!doctype html><html><head><meta charset="utf-8">
<title>asmx \u03a9 :: __TITLE__</title>
<style>
:root{--bg:#060714;--bg2:#0b0e22;--panel:#0d1026ee;--line:#262b55;--txt:#dce2ff;--dim:#6b72a8;
--accent:#7df9ff;--pink:#ff5fb0;--gold:#ffd27a;--bad:#ff4d6d;--ok:#5dffb0;--warn:#ffb454;--purple:#b388ff;}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(ellipse at 50% -10%,#141a3d 0%,var(--bg) 55%);color:var(--txt);
font:13px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow:hidden}
#stars{position:fixed;inset:0;z-index:0;pointer-events:none}
#domain{position:fixed;inset:0;z-index:50;background:#000;display:flex;align-items:center;justify-content:center;
flex-direction:column;transition:opacity 1.1s ease;color:#fff;text-align:center}
#domain h1{font-size:min(7vw,64px);letter-spacing:.15em;margin:0;font-weight:200;
background:linear-gradient(90deg,var(--accent),var(--pink),var(--gold));-webkit-background-clip:text;background-clip:text;color:transparent;
text-shadow:0 0 60px rgba(125,249,255,.3)}
#domain p{color:var(--dim);letter-spacing:.3em;text-transform:uppercase;font-size:11px;margin-top:10px}
#domain.hide{opacity:0;pointer-events:none}
#app{position:relative;z-index:1;display:grid;grid-template-columns:280px 1fr 320px;grid-template-rows:48px 1fr 150px;
height:100vh;gap:1px;background:var(--line)}
header{grid-column:1/4;display:flex;align-items:center;gap:14px;padding:0 14px;background:var(--panel);backdrop-filter:blur(6px)}
header .logo{font-weight:700;letter-spacing:.08em;background:linear-gradient(90deg,var(--accent),var(--pink));
-webkit-background-clip:text;background-clip:text;color:transparent}
header .meta{color:var(--dim);font-size:11px}
header .sev{display:flex;gap:8px;margin-left:auto}
.badge{padding:2px 9px;border-radius:20px;font-size:11px;border:1px solid var(--line)}
#left{background:var(--panel);overflow-y:auto;padding:10px}
#center{background:#070915;position:relative;overflow:hidden}
#right{background:var(--panel);overflow-y:auto;padding:10px}
#bottom{grid-column:1/4;background:var(--panel);display:flex;flex-direction:column;padding:8px 14px;gap:6px}
h3{margin:14px 0 6px;font-size:10px;text-transform:uppercase;letter-spacing:.15em;color:var(--dim)}
h3:first-child{margin-top:0}
.row{display:flex;align-items:center;justify-content:space-between;padding:4px 6px;border-radius:5px;cursor:pointer;font-size:12px}
.row:hover{background:#ffffff0c}
.row.sel{background:#7df9ff22;border:1px solid #7df9ff55}
.chip{display:inline-block;padding:1px 6px;border-radius:9px;font-size:10px;margin-left:6px}
.c-CRITICAL{background:#ff4d6d33;color:#ff9fb0}.c-HIGH{background:#ffb45433;color:#ffcf9b}
.c-MEDIUM{background:#ffd27a33;color:#ffe3ab}.c-LOW{background:#5dffb033;color:#a9ffd9}.c-INFO{background:#6b72a833;color:#b7bbe6}
button,select,input[type=text]{background:#12152f;border:1px solid var(--line);color:var(--txt);border-radius:6px;
padding:5px 9px;font:inherit;cursor:pointer}
button:hover{border-color:var(--accent)}
button.on{background:var(--accent);color:#06121a;font-weight:700}
#filters{display:flex;gap:6px;flex-wrap:wrap;padding:8px 0;border-bottom:1px solid var(--line);margin-bottom:8px}
#filters button{padding:3px 8px;font-size:11px}
#svgwrap{width:100%;height:100%;cursor:grab}
#svgwrap:active{cursor:grabbing}
.nlabel{fill:var(--txt);font-size:9px;pointer-events:none;font-family:inherit}
.elabel{fill:var(--dim);font-size:8px;pointer-events:none}
#tooltip{position:absolute;background:#0a0c20ee;border:1px solid var(--accent);border-radius:8px;padding:8px 10px;
font-size:11px;pointer-events:none;max-width:320px;z-index:20;display:none;box-shadow:0 0 30px #7df9ff33}
#tooltip b{color:var(--accent)}
#crumbs{position:absolute;top:10px;left:10px;display:flex;gap:6px;z-index:5;font-size:11px}
#crumbs span{background:#0a0c20cc;border:1px solid var(--line);border-radius:5px;padding:3px 9px;cursor:pointer}
#crumbs span:hover{border-color:var(--accent)}
#legend{position:absolute;bottom:10px;right:10px;background:#0a0c20cc;border:1px solid var(--line);border-radius:8px;
padding:8px 10px;font-size:10px;z-index:5;display:grid;grid-template-columns:1fr;gap:3px}
#legend i{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
#timeline{flex:1;position:relative;background:#070915;border-radius:6px;border:1px solid var(--line);overflow:hidden}
#tl-canvas{width:100%;height:100%;display:block}
#playbar{display:flex;align-items:center;gap:8px}
#scrub{flex:1}
.asmline{white-space:pre;font-size:11px;padding:1px 4px}
.asmline.cur{background:#7df9ff22;border-left:2px solid var(--accent)}
.mono{font-family:inherit}
#detail pre{white-space:pre-wrap;font-size:11px;color:#b9c1ff;background:#06081a;padding:8px;border-radius:6px;border:1px solid var(--line)}
a{color:var(--accent)}
::-webkit-scrollbar{width:8px;height:8px}::-webkit-scrollbar-thumb{background:#262b55;border-radius:4px}
.flowpulse{filter:drop-shadow(0 0 4px var(--accent))}
</style></head>
<body>
<canvas id="stars"></canvas>
<div id="domain"><h1 id="domtitle">UNLIMITED VOID</h1><p id="domsub">binding vow · asmx \u03a9 engine</p></div>
<div id="app">
<header>
  <span class="logo">ASMX \u03a9</span>
  <span class="meta" id="hdrmeta">__META__</span>
  <div class="sev" id="hdrsev"></div>
</header>
<div id="left">
  <h3>Domain</h3>
  <div style="display:flex;gap:6px;flex-wrap:wrap">
    <button data-dom="gojo">Gojo</button><button data-dom="sukuna">Sukuna</button><button data-dom="cosmos" class="on">Cosmos</button>
  </div>
  <h3>Level</h3>
  <div id="levelBtns" style="display:flex;gap:6px;flex-wrap:wrap"></div>
  <h3>Node types</h3>
  <div id="typeToggles"></div>
  <h3>Search</h3>
  <input type="text" id="search" placeholder="function, file, finding\u2026" style="width:100%">
  <div id="searchResults"></div>
  <h3>Findings (<span id="fcount">0</span>)</h3>
  <div id="findingsList"></div>
  <h3>Export</h3>
  <div style="display:flex;gap:6px;flex-wrap:wrap">
    <button id="expjson">JSON</button><button id="expdot">DOT</button><button id="exphtml">standalone</button>
  </div>
</div>
<div id="center">
  <div id="crumbs"></div>
  <div id="legend"></div>
  <div id="tooltip"></div>
  <svg id="svgwrap" xmlns="http://www.w3.org/2000/svg"></svg>
</div>
<div id="right">
  <h3>Selection</h3>
  <div id="detail">click a node to inspect it</div>
</div>
<div id="bottom">
  <div id="playbar">
    <button id="playpause">\u25b6</button>
    <span id="stepLabel" class="mono" style="min-width:150px">step 0 / 0</span>
    <input type="range" id="scrub" min="0" max="1000" value="0">
    <select id="speed"><option value="4">0.25x</option><option value="2">0.5x</option><option value="1" selected>1x</option>
      <option value="0.25">4x</option><option value="0.05">20x</option></select>
    <span class="meta" id="runmeta"></span>
  </div>
  <div id="timeline"><canvas id="tl-canvas"></canvas></div>
</div>
</div>
<script>
const DATA = __DATA_JSON__;
</script>
<script>
__APP_JS__
</script>
</body></html>"""
APP_JS = r"""
// ---------------------------------------------------------------- starfield
(function(){
  const c=document.getElementById('stars'),ctx=c.getContext('2d');
  function size(){c.width=innerWidth;c.height=innerHeight;}
  size(); addEventListener('resize',size);
  const N=160, stars=Array.from({length:N},()=>({x:Math.random()*c.width,y:Math.random()*c.height,r:Math.random()*1.3+.2,p:Math.random()*6.28,s:Math.random()*.02+.005}));
  function tick(){ctx.clearRect(0,0,c.width,c.height);
    for(const s of stars){s.p+=s.s;const a=.35+.5*Math.abs(Math.sin(s.p));
      ctx.beginPath();ctx.arc(s.x,s.y,s.r,0,6.28);ctx.fillStyle=`rgba(180,200,255,${a})`;ctx.fill();}
    requestAnimationFrame(tick);}
  tick();
})();

// ---------------------------------------------------------------- domain intro
const DOMAIN_TXT = {gojo:["UNLIMITED VOID","infinite information \u00b7 binding vow"],
  sukuna:["MALEVOLENT SHRINE","dismantle \u00b7 cleave \u00b7 reveal"],
  cosmos:["ASMX \u03a9 DOMAIN","every byte, every cycle, observed"]};
function playDomain(name){
  const d=document.getElementById('domain');
  document.getElementById('domtitle').textContent=DOMAIN_TXT[name][0];
  document.getElementById('domsub').textContent=DOMAIN_TXT[name][1];
  d.classList.remove('hide'); d.style.background = name==='sukuna' ? 'radial-gradient(circle,#2a0008,#000)' :
    name==='gojo' ? 'radial-gradient(circle,#06111f,#000)' : 'radial-gradient(circle,#0a0820,#000)';
  clearTimeout(window.__dht);
  window.__dht=setTimeout(()=>d.classList.add('hide'), 1900);
}
document.querySelectorAll('[data-dom]').forEach(b=>b.addEventListener('click',()=>{
  document.querySelectorAll('[data-dom]').forEach(x=>x.classList.remove('on')); b.classList.add('on');
  playDomain(b.dataset.dom);
}));
setTimeout(()=>playDomain('cosmos'),80);

// ---------------------------------------------------------------- data shaping
const G = DATA.graph, META = DATA.meta, FIND = DATA.findings, EVENTS = DATA.events, SYS = DATA.syscalls;
const TYPE_COLOR = {process:'#ffffff',thread:'#b388ff',function:'#7df9ff',block:'#4d6fff',instruction:'#4d6fff',
  file:'#5dffb0',socket:'#5dffb0',syscall:'#ffd27a',heap_block:'#ff9fe0',finding:'#ff4d6d',library:'#6b72a8',
  input_source:'#ff5fb0',struct:'#c9ffb0',stream:'#5dffb0'};
const TYPE_SHAPE = {process:9,thread:7,function:6,block:3.5,file:6,socket:6,syscall:5,heap_block:5.5,finding:6,library:4,input_source:5,struct:4};

document.getElementById('hdrmeta').textContent = META.summary;
const sevCounts = {}; for(const f of FIND) sevCounts[f.sev]=(sevCounts[f.sev]||0)+1;
document.getElementById('hdrsev').innerHTML = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'].filter(s=>sevCounts[s])
  .map(s=>`<span class="badge c-${s}">${sevCounts[s]} ${s}</span>`).join('');
document.getElementById('fcount').textContent = FIND.length;
document.getElementById('runmeta').textContent = META.run_meta;

// ---------------------------------------------------------------- level / filter state
const LEVELS = ['system','functions','dataflow'];
let level='functions', focusFn=null;
const levelBtns=document.getElementById('levelBtns');
LEVELS.forEach(l=>{const b=document.createElement('button');b.textContent=l;b.className=l===level?'on':'';
  b.onclick=()=>{level=l;focusFn=null;document.querySelectorAll('#levelBtns button').forEach(x=>x.classList.remove('on'));b.classList.add('on');renderGraph();};
  levelBtns.appendChild(b);});

const ALLTYPES = [...new Set(G.nodes.map(n=>n.type))];
const hiddenTypes = new Set();
const tt=document.getElementById('typeToggles');
ALLTYPES.forEach(t=>{const row=document.createElement('div');row.className='row';
  row.innerHTML=`<span><i style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${TYPE_COLOR[t]||'#888'};margin-right:6px"></i>${t}</span>`;
  const btn=document.createElement('button'); btn.textContent='on'; btn.style.fontSize='10px'; btn.style.padding='1px 6px';
  btn.onclick=()=>{if(hiddenTypes.has(t)){hiddenTypes.delete(t);btn.textContent='on';btn.classList.add('on');}else{hiddenTypes.add(t);btn.textContent='off';btn.classList.remove('on');} renderGraph();};
  btn.className='on'; row.appendChild(btn); tt.appendChild(row);});

document.getElementById('legend').innerHTML = Object.entries(TYPE_COLOR).slice(0,9).map(([k,v])=>`<div><i style="background:${v}"></i>${k}</div>`).join('');

// ---------------------------------------------------------------- findings list
const flist=document.getElementById('findingsList');
FIND.slice(0,250).forEach((f,i)=>{const row=document.createElement('div');row.className='row';
  row.innerHTML=`<span>${f.title.slice(0,34)}</span><span class="chip c-${f.sev}">${f.sev}</span>`;
  row.onclick=()=>{showDetail(Object.assign({type:'finding'},f)); seekStep(f.step);};
  flist.appendChild(row);});

// ---------------------------------------------------------------- graph view (SVG, simple force layout)
const svg=document.getElementById('svgwrap'); const tooltip=document.getElementById('tooltip'); const crumbs=document.getElementById('crumbs');
let viewBox={x:0,y:0,w:1000,h:700}, panStart=null;
function applyVB(){svg.setAttribute('viewBox',`${viewBox.x} ${viewBox.y} ${viewBox.w} ${viewBox.h}`);}
svg.addEventListener('wheel',e=>{e.preventDefault();const f=e.deltaY>0?1.1:0.9;
  const mx=viewBox.x+viewBox.w*(e.offsetX/svg.clientWidth), my=viewBox.y+viewBox.h*(e.offsetY/svg.clientHeight);
  viewBox.w*=f; viewBox.h*=f; viewBox.x=mx-viewBox.w*(e.offsetX/svg.clientWidth); viewBox.y=my-viewBox.h*(e.offsetY/svg.clientHeight); applyVB();});
svg.addEventListener('mousedown',e=>{panStart={x:e.clientX,y:e.clientY,vb:{...viewBox}};});
addEventListener('mouseup',()=>panStart=null);
addEventListener('mousemove',e=>{if(!panStart)return;const dx=(e.clientX-panStart.x)*viewBox.w/svg.clientWidth, dy=(e.clientY-panStart.y)*viewBox.h/svg.clientHeight;
  viewBox.x=panStart.vb.x-dx; viewBox.y=panStart.vb.y-dy; applyVB();});

function levelFilter(){
  if(level==='system') return n=>['process','thread','library','file','socket','syscall'].includes(n.type);
  if(level==='functions') return n=>['function','file','socket','syscall','heap_block','finding','input_source'].includes(n.type) && (!focusFn || n.id==='fn:'+focusFn || true);
  return n=>['function','finding','input_source','heap_block'].includes(n.type);
}
let posCache={};
function layout(nodes, edges){
  const idx={}; nodes.forEach((n,i)=>idx[n.id]=i);
  const n=nodes.length; if(!n) return {};
  let pos = nodes.map(nd=>posCache[nd.id]||{x:(Math.random()-.5)*600,y:(Math.random()-.5)*600});
  const deg=new Array(n).fill(0);
  edges.forEach(e=>{if(idx[e.from]!=null)deg[idx[e.from]]++; if(idx[e.to]!=null)deg[idx[e.to]]++;});
  const iters = n>120?70:140;
  const k=900/Math.sqrt(n+1);
  for(let it=0;it<iters;it++){
    const disp=pos.map(()=>({x:0,y:0}));
    for(let i=0;i<n;i++)for(let j=i+1;j<n;j++){
      let dx=pos[i].x-pos[j].x, dy=pos[i].y-pos[j].y; let d=Math.hypot(dx,dy)||0.01;
      const f=(k*k)/d; dx/=d;dy/=d;
      disp[i].x+=dx*f; disp[i].y+=dy*f; disp[j].x-=dx*f; disp[j].y-=dy*f;
    }
    edges.forEach(e=>{const i=idx[e.from],j=idx[e.to]; if(i==null||j==null)return;
      let dx=pos[i].x-pos[j].x, dy=pos[i].y-pos[j].y; let d=Math.hypot(dx,dy)||0.01;
      const f=(d*d)/k; dx/=d;dy/=d;
      disp[i].x-=dx*f; disp[i].y-=dy*f; disp[j].x+=dx*f; disp[j].y+=dy*f;});
    const temp=30*(1-it/iters)+1;
    for(let i=0;i<n;i++){const d=Math.hypot(disp[i].x,disp[i].y)||0.01; const lim=Math.min(d,temp);
      pos[i].x+=disp[i].x/d*lim; pos[i].y+=disp[i].y/d*lim;
      pos[i].x=Math.max(-1200,Math.min(1200,pos[i].x)); pos[i].y=Math.max(-900,Math.min(900,pos[i].y));}
  }
  const out={}; nodes.forEach((nd,i)=>{out[nd.id]=pos[i]; posCache[nd.id]=pos[i];}); return out;
}

let curStep=0, curNodes=[], curEdges=[];
function renderGraph(){
  const f=levelFilter();
  let nodes=G.nodes.filter(nd=>f(nd) && !hiddenTypes.has(nd.type));
  const ids=new Set(nodes.map(n=>n.id));
  let edges=G.edges.filter(e=>ids.has(e.from)&&ids.has(e.to));
  if(level==='dataflow'){ edges=edges.filter(e=>e.type==='dataflow'||e.type==='taint'||e.type==='finds'); }
  if(nodes.length>260){ nodes=[...nodes].sort((a,b)=>(b.steps||b.n||0)-(a.steps||a.n||0)).slice(0,260); const ids2=new Set(nodes.map(n=>n.id)); edges=edges.filter(e=>ids2.has(e.from)&&ids2.has(e.to)); }
  curNodes=nodes; curEdges=edges;
  const pos=layout(nodes,edges);
  svg.innerHTML='';
  const defs=document.createElementNS('http://www.w3.org/2000/svg','defs');
  defs.innerHTML=`<marker id="arrow" markerWidth="7" markerHeight="7" refX="6" refY="3" orient="auto"><path d="M0,0L6,3L0,6Z" fill="#555a99"/></marker>`;
  svg.appendChild(defs);
  const eg=document.createElementNS('http://www.w3.org/2000/svg','g');
  edges.forEach(e=>{const a=pos[e.from],b=pos[e.to]; if(!a||!b)return;
    const ln=document.createElementNS('http://www.w3.org/2000/svg','line');
    ln.setAttribute('x1',a.x);ln.setAttribute('y1',a.y);ln.setAttribute('x2',b.x);ln.setAttribute('y2',b.y);
    const taint=e.type==='taint'||e.tainted; 
    ln.setAttribute('stroke', taint?'#ff5fb0': e.type==='finds'?'#ff4d6d': '#555a9980');
    ln.setAttribute('stroke-width', taint?1.6:1); ln.setAttribute('marker-end','url(#arrow)');
    if(taint) ln.setAttribute('stroke-dasharray','3,3');
    eg.appendChild(ln);});
  svg.appendChild(eg);
  const ng=document.createElementNS('http://www.w3.org/2000/svg','g');
  nodes.forEach(nd=>{const p=pos[nd.id]; if(!p)return;
    const g=document.createElementNS('http://www.w3.org/2000/svg','g'); g.setAttribute('transform',`translate(${p.x},${p.y})`); g.style.cursor='pointer';
    const r=TYPE_SHAPE[nd.type]||4;
    const c=document.createElementNS('http://www.w3.org/2000/svg','circle'); c.setAttribute('r',r);
    let fill=TYPE_COLOR[nd.type]||'#8888bb';
    if(nd.type==='finding') fill = {CRITICAL:'#ff2d55',HIGH:'#ff7a45',MEDIUM:'#ffd27a',LOW:'#5dffb0',INFO:'#6b72a8'}[nd.sev]||fill;
    c.setAttribute('fill',fill); c.setAttribute('fill-opacity', nd.type==='finding'?'0.95':'0.85');
    c.setAttribute('stroke', nd.type==='finding' ? '#fff' : fill); c.setAttribute('stroke-opacity','0.5');
    g.appendChild(c);
    const t=document.createElementNS('http://www.w3.org/2000/svg','text'); t.setAttribute('class','nlabel');
    t.setAttribute('x',r+3); t.setAttribute('y',3); t.textContent=(nd.label||nd.id).toString().slice(0,26);
    g.appendChild(t);
    g.addEventListener('mouseenter',ev=>{tooltip.style.display='block'; tooltip.innerHTML=tipFor(nd);
      const rect=svg.getBoundingClientRect(); tooltip.style.left=(ev.clientX-rect.left+14)+'px'; tooltip.style.top=(ev.clientY-rect.top+10)+'px';});
    g.addEventListener('mouseleave',()=>tooltip.style.display='none');
    g.addEventListener('click',()=>{ showDetail(nd);
      if(nd.type==='function'&&level==='functions'){focusFn=nd.label; }
    });
    g.addEventListener('dblclick',()=>{ if(nd.type==='function'){level='dataflow';focusFn=nd.label;
      document.querySelectorAll('#levelBtns button').forEach(x=>x.classList.toggle('on',x.textContent===level)); renderGraph();}});
    ng.appendChild(g); nd.__pos=p;
  });
  svg.appendChild(ng);
  viewBox={x:-650,y:-500,w:1300,h:1000}; applyVB();
  crumbs.innerHTML = `<span onclick="level='system';focusFn=null;renderGraph();document.querySelectorAll('#levelBtns button').forEach(x=>x.classList.toggle('on',x.textContent==='system'))">system</span>`+
    `<span onclick="level='functions';renderGraph();document.querySelectorAll('#levelBtns button').forEach(x=>x.classList.toggle('on',x.textContent==='functions'))">functions</span>` +
    (focusFn? `<span>\u25b8 ${focusFn}</span>`:'');
}
function tipFor(nd){
  let rows=`<b>${nd.label||nd.id}</b><br><span style="color:var(--dim)">${nd.type}</span>`;
  if(nd.type==='function') rows+=`<br>steps: ${nd.steps||0} \u00b7 obj: ${nd.obj||''}` + (nd.compiler? `<br>compiler: ${nd.compiler.state}${nd.compiler.sites?(' \u00d7'+nd.compiler.sites):''}`:'') + (nd.tainted_args&&nd.tainted_args.length? `<br style="color:var(--pink)">tainted args: ${nd.tainted_args.join(',')}`:'');
  if(nd.type==='finding') rows+=`<br>${nd.detail||''}`;
  if(nd.type==='heap_block') rows+=`<br>size ${nd.size}B \u00b7 ${nd.state}`;
  if(nd.type==='syscall'||nd.type==='file'||nd.type==='socket') rows+=`<br>n=${nd.n||''} reads=${nd.reads||''} writes=${nd.writes||''}`;
  return rows;
}
function showDetail(nd){
  const d=document.getElementById('detail'); let h=`<div style="color:var(--accent);font-weight:700">${nd.label||nd.title||nd.id}</div>`;
  h+=`<div style="color:var(--dim);margin:4px 0">${nd.type||nd.kind||''}</div>`;
  if(nd.detail) h+=`<pre>${esc(nd.detail)}</pre>`;
  if(nd.witness && nd.witness.input_bytes && Object.keys(nd.witness.input_bytes).length)
    h+=`<div>witness bytes: ${Object.entries(nd.witness.input_bytes).map(([k,v])=>`<b>${k}</b>[${v}]`).join(', ')}</div>`;
  if(nd.compiler) h+=`<div>compiler: ${nd.compiler.state} (${nd.compiler.sites||0} call sites)</div>`;
  if(nd.members) h+=`<pre>${nd.members.map(m=>`+${m.off.toString().padStart(3)}  ${m.type} ${m.name};`).join('\n')}</pre>`;
  d.innerHTML=h;
}
function esc(s){return (s+'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
renderGraph();

// ---------------------------------------------------------------- search
const search=document.getElementById('search'), sres=document.getElementById('searchResults');
search.addEventListener('input',()=>{const q=search.value.toLowerCase(); sres.innerHTML='';
  if(q.length<2) return;
  G.nodes.filter(n=>(n.label||'').toLowerCase().includes(q)).slice(0,30).forEach(n=>{
    const row=document.createElement('div'); row.className='row'; row.textContent=n.label+' ('+n.type+')';
    row.onclick=()=>{showDetail(n); const p=n.__pos; if(p){viewBox.x=p.x-150;viewBox.y=p.y-100;viewBox.w=300;viewBox.h=220;applyVB();}};
    sres.appendChild(row);});
});

// ---------------------------------------------------------------- timeline + playback
const tlc=document.getElementById('tl-canvas'); const tlx=tlc.getContext('2d');
function sizeTl(){tlc.width=tlc.clientWidth*2;tlc.height=tlc.clientHeight*2;tlx.scale(2,2);}
sizeTl();
const maxStep = META.total_steps||EVENTS.length;
document.getElementById('scrub').max=maxStep;
function drawTimeline(){
  const w=tlc.clientWidth,h=tlc.clientHeight; tlx.clearRect(0,0,w,h);
  tlx.fillStyle='#0a0c1e'; tlx.fillRect(0,0,w,h);
  const fnColor={}; let ci=0; const palette=['#7df9ff','#ff5fb0','#ffd27a','#5dffb0','#b388ff','#ff9f6b','#6ee7ff'];
  EVENTS.forEach(e=>{ if(e.fn && !(e.fn in fnColor)){fnColor[e.fn]=palette[ci++%palette.length];} });
  const n=EVENTS.length||1;
  EVENTS.forEach((e,i)=>{ const x=(i/n)*w;
    if(e.t==='i'||e.t==='s'){ tlx.fillStyle=fnColor[e.fn]||'#4d6fff'; tlx.fillRect(x,h*0.35,Math.max(1,w/n),h*0.4);} });
  SYS.forEach(s=>{ const i=s.step/((META.total_steps)||1)*n; const x=(i/n)*w; tlx.fillStyle='#ffd27a'; tlx.fillRect(x,h*0.1,1.4,h*0.25);});
  FIND.forEach(f=>{ const i=(f.step/((META.total_steps)||1))*n; const x=(i/n)*w; tlx.fillStyle='#ff4d6d'; tlx.fillRect(x,h*0.78,2,h*0.22);});
  const cx=(curStep/maxStep)*w; tlx.strokeStyle='#fff'; tlx.lineWidth=1.5; tlx.beginPath();tlx.moveTo(cx,0);tlx.lineTo(cx,h);tlx.stroke();
}
drawTimeline(); addEventListener('resize',()=>{sizeTl();drawTimeline();});
tlc.addEventListener('click',e=>{const r=tlc.getBoundingClientRect(); seekStep(Math.round((e.clientX-r.left)/r.width*maxStep));});

function nearestEvent(step){
  let lo=0,hi=EVENTS.length-1,best=EVENTS[0];
  while(lo<=hi){const m=(lo+hi)>>1; const s=EVENTS[m].s;
    if(s===step)return EVENTS[m]; if(s<step){best=EVENTS[m];lo=m+1;}else hi=m-1;}
  return best;
}
function seekStep(step){
  curStep=Math.max(0,Math.min(maxStep,step));
  document.getElementById('scrub').value=curStep;
  document.getElementById('stepLabel').textContent=`step ${curStep} / ${maxStep}`;
  const ev=nearestEvent(curStep); if(!ev) return;
  let h='';
  if(ev.t==='i'){ h+=`<div class="mono" style="color:var(--accent)">${ev.fn}</div><div class="asmline cur">${ev.rip?.toString(16)?('0x'+ev.rip.toString(16)):''}  ${esc(ev.asm||'')}</div>`;
    if(ev.chg&&Object.keys(ev.chg).length) h+=`<div>changed: ${Object.entries(ev.chg).map(([k,v])=>`${k}=${v[1].toString?v[1].toString(16):v[1]}`).join(', ')}</div>`;
    if(ev.mem&&ev.mem.length) h+=`<div>mem: ${ev.mem.map(m=>`${m[0]} *${m[1].toString(16)} (${m[2]}B)=${m[3]}`).join('; ')}</div>`;
    if(ev.var&&ev.var.length) h+=`<div>var: ${ev.var.join(', ')}</div>`;
  } else if(ev.t==='s'){ h+=`<div class="mono" style="color:var(--dim)">running in <b>${ev.fn}</b> (${ev.obj}) \u00d7${ev.n} steps</div>`; }
  else if(ev.t==='y'){ h+=`<div style="color:var(--gold)">${esc(ev.text)}</div>`; }
  else if(ev.t==='h'){ h+=`<div style="color:var(--purple)">${esc(ev.text)}</div>`; }
  document.getElementById('detail').innerHTML = h + document.getElementById('detail').innerHTML;
  drawTimeline();
  if(ev.fn){ const nid='fn:'+ev.fn; const nd=curNodes.find(n=>n.id===nid);
    if(nd && nd.__pos){ highlightPulse(nd.__pos); } }
}
function highlightPulse(p){
  const c=document.createElementNS('http://www.w3.org/2000/svg','circle');
  c.setAttribute('cx',p.x);c.setAttribute('cy',p.y);c.setAttribute('r',4);c.setAttribute('fill','none');
  c.setAttribute('stroke','#fff');c.setAttribute('class','flowpulse');c.setAttribute('stroke-width','2');
  svg.appendChild(c);
  let r=4; const anim=setInterval(()=>{r+=3;c.setAttribute('r',r);c.setAttribute('opacity',Math.max(0,1-r/40));
    if(r>40){clearInterval(anim);c.remove();}},16);
}
document.getElementById('scrub').addEventListener('input',e=>seekStep(+e.target.value));
let playing=false, playTimer=null;
document.getElementById('playpause').addEventListener('click',()=>{
  playing=!playing; document.getElementById('playpause').textContent = playing?'\u23f8':'\u25b6';
  if(playing) tickPlay();
});
function tickPlay(){ if(!playing) return;
  const speed = +document.getElementById('speed').value;
  seekStep(curStep + Math.max(1, Math.round(maxStep/400)));
  if(curStep>=maxStep){playing=false; document.getElementById('playpause').textContent='\u25b6'; return;}
  playTimer=setTimeout(tickPlay, 16*speed);
}
seekStep(0);

// ---------------------------------------------------------------- export
function dl(name,content,type){const a=document.createElement('a'); a.href=URL.createObjectURL(new Blob([content],{type})); a.download=name; a.click();}
document.getElementById('expjson').onclick=()=>dl('asmx_omni_graph.json',JSON.stringify(G,null,1),'application/json');
document.getElementById('expdot').onclick=()=>dl('asmx_omni_graph.dot',DATA.dot||'','text/vnd.graphviz');
document.getElementById('exphtml').onclick=()=>dl('asmx_omni_report.html',document.documentElement.outerHTML,'text/html');
"""


# =========================================================================== #
#  CLI                                                                        #
# =========================================================================== #
def human(n):
    for u in ("", "K", "M", "G"):
        if abs(n) < 1024:
            return f"{n:.0f}{u}"
        n /= 1024
    return f"{n:.0f}T"


def run_one(args, src_or_bin, work: Path, tag="run"):
    is_bin = sniff_bin(src_or_bin)
    opt_info = {"decisions": {}, "missed": []}
    stages = []
    if is_bin:
        exe = src_or_bin
        rc, _, _ = sh(["chmod", "+x", str(exe)])
    else:
        src = Path(src_or_bin).resolve()
        if not src.is_file():
            raise OmniError(f"no such file: {src}")
        cc = find_cc("c++" if src.suffix in (".cc", ".cpp", ".cxx") else "c", args.cc)
        stages, exe, opt_info = build_pipeline(src, work, args.opt, cc, parse_flags_(args.flags), args.static)
    info = BinInfo(exe, work)
    argv = parse_flags_(args.args)
    stdin_data = args.input.encode("latin1", "replace") if args.input is not None else (Path(args.stdin_file).read_bytes() if args.stdin_file else b"")
    env = dict(os.environ)
    env["PATH"] = env.get("PATH", "/usr/bin:/bin")
    tr = Tracer(info, argv, env, stdin_data, args.max_steps, args.timeout, work, tag).run()
    return info, tr, stages, opt_info


def sniff_bin(path):
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except OSError:
        return False


def parse_flags_(s):
    return shlex.split(s) if s else []


def summarize(tr: Tracer, info: BinInfo):
    sev = Counter(f["sev"] for f in tr.findings)
    bits = [f"{tr.steps} instr", f"{len(tr.syscalls)} syscalls", f"{len(tr.allocs)} allocs",
            f"{len(tr.calls)} call-edges", human(len(tr.mem)) + " mem ops"]
    if sev:
        bits.append(" ".join(f"{sev[s]} {s}" for s in SEV if sev.get(s)))
    return " \u00b7 ".join(bits)


def render_report(tr: Tracer, info: BinInfo, opt_info, stages, src_name):
    L = []
    L.append(f"  asmx \u03a9  omni report  \u00b7  {Path(info.exe).name}")
    L.append("  " + "\u2500" * 70)
    if stages:
        L.append("  build pipeline:")
        for s in stages:
            art = s["artifact"]
            L.append(f"    {s['stage']:<10} {s['ms']:>5}ms  " + (f"{art['name']} ({human(art['bytes'])}B, sha256 {art['sha256']})" if art else "(no artifact)"))
        for cat, items in opt_info["decisions"].items():
            if items:
                L.append(f"    {cat}: " + "; ".join(f"L{i['line']} {i['msg'][:60]}" for i in items[:4]) + (f"  (+{len(items)-4} more)" if len(items) > 4 else ""))
        if opt_info["missed"]:
            L.append("    missed: " + "; ".join(f"{m}x{n}" for m, n in opt_info["missed"]))
    L.append(f"  binary: type={info.facts['type']} entry={hx(info.facts['entry'])} needed={','.join(info.facts['needed']) or '(static)'}")
    if tr.plt_res:
        L.append("  dynamic resolution: " + ", ".join(f"{k}→{v['resolved']}@{v['obj']}" for k, v in list(tr.plt_res.items())[:8]))
    L.append("  " + "\u2500" * 70)
    L.append("  execution: " + summarize(tr, info))
    if tr.exit.get("truncated"):
        L.append(f"  \u26a0 truncated: {tr.exit['truncated']}")
    if tr.exit.get("signal"):
        L.append(f"  process terminated by {tr.exit['signal']}")
    elif tr.exit.get("code") is not None:
        L.append(f"  process exited with code {tr.exit['code']}")
    if tr.output:
        L.append("  stdout: " + repr(tr.output[:300]))
    L.append("  " + "\u2500" * 70)
    L.append("  call graph (top call counts):")
    for ln in call_graph_text(tr)[:30]:
        L.append("    " + ln)
    if tr.findings:
        L.append("  " + "\u2500" * 70)
        L.append(f"  findings ({len(tr.findings)}):")
        for f in sorted(tr.findings, key=lambda f: SEV.index(f["sev"]))[:40]:
            w = f["witness"]["input_bytes"]
            wit = ("  witness: " + ", ".join(f"{k}[{v}]" for k, v in w.items())) if w else ""
            L.append(f"    [{f['sev']:<8}] {f['title']}")
            L.append(f"               {f['detail']}{wit}")
    if tr.constraints:
        L.append("  " + "\u2500" * 70)
        L.append("  path constraints (symbolic):")
        for c in tr.constraints[:20]:
            L.append(f"    {tr.symof(c['rip'])[0]:<16} {c['text']}" + (f"  (x{c['n']})" if c["n"] > 1 else ""))
    if info.dwarf.structs:
        L.append("  " + "\u2500" * 70)
        L.append("  structures (DWARF):")
        for s in info.dwarf.structs[:12]:
            L.append(f"    {s['kind']} {s['name']}  ({s['size']}B)")
            for m in s["members"][:10]:
                L.append(f"      +{m['off']:<3} {m['type']} {m['name']};")
    return "\n".join(L) + "\n"


def make_html(tr: Tracer, info: BinInfo, graph, title):
    ev = []
    for e in tr.events:
        d = {"t": e["t"], "s": e["s"]}
        if e["t"] == "i":
            d.update(rip=e["rip"], asm=e["asm"], fn=e["fn"], chg=e["chg"], mem=e["mem"], var=e.get("var", []))
        elif e["t"] == "s":
            d.update(fn=e["fn"], obj=e.get("obj", ""), n=e["n"])
        elif e["t"] == "y":
            d.update(text=e["text"])
        elif e["t"] == "h":
            d.update(text=e["text"])
        ev.append(d)
    findings = [{"sev": f["sev"], "kind": f["kind"], "title": f["title"], "detail": f["detail"], "step": f["step"], "witness": f["witness"]} for f in tr.findings]
    data = {
        "graph": graph,
        "events": ev,
        "findings": findings,
        "syscalls": [{"step": s["step"], "name": s["name"], "text": s["text"]} for s in tr.syscalls],
        "dot": to_dot(graph),
        "meta": {"summary": summarize(tr, info), "total_steps": tr.steps,
                 "run_meta": f"exit={tr.exit} \u00b7 {Path(info.exe).name}"},
    }
    js = json.dumps(data, separators=(",", ":"))
    html = HTML_TEMPLATE.replace("__TITLE__", title).replace("__META__", summarize(tr, info)).replace("__DATA_JSON__", js).replace("__APP_JS__", APP_JS)
    return html


def omni_main(argv=None):
    ap = argparse.ArgumentParser(prog="asmx-omni", description="whole-program / whole-run analysis engine for asmx",
                                 epilog="examples:\n  asmx_omni.py prog.c -O1 --input 'AAAA...' --html out.html\n"
                                 "  asmx_omni.py ./a.out --args '-x 3' --stdin-file in.bin --json out.json\n"
                                 "  asmx_omni.py prog.c --diff-against goodinput.c --html diff.html\n",
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", help="C/C++ source file or an existing ELF binary")
    ap.add_argument("-O", dest="opt", default="0", choices=("0", "1", "2", "3", "s"))
    ap.add_argument("--cc", help="compiler override")
    ap.add_argument("--flags", default="", help="extra compiler flags")
    ap.add_argument("--static", action="store_true", help="link statically (simplifies the library graph)")
    ap.add_argument("--args", default="", help="argv passed to the target, shlex-quoted")
    ap.add_argument("--input", help="literal bytes piped to stdin (supports \\n, \\x41 escapes)")
    ap.add_argument("--stdin-file", help="file whose bytes are piped to stdin")
    ap.add_argument("--max-steps", type=int, default=400000, help="instruction budget (default 400000)")
    ap.add_argument("--timeout", type=int, default=25, help="wall-clock seconds for the run (default 25)")
    ap.add_argument("--html", help="write the animated graph/timeline UI here")
    ap.add_argument("--json", help="write the raw typed graph + events as JSON")
    ap.add_argument("--dot", help="write the call/data graph as Graphviz DOT")
    ap.add_argument("-o", "--output", help="write the text report here instead of stdout")
    ap.add_argument("--quiet", "-q", action="store_true")
    ap.add_argument("--diff-against", metavar="FILE", help="build/run a second target with the same --args/--input and report where the two runs diverge")
    args = ap.parse_args(argv)
    if args.input is not None:
        args.input = codecs.escape_decode(args.input.encode())[0].decode("latin1")

    with tempfile.TemporaryDirectory(prefix="asmx-omni-") as tmp:
        work = Path(tmp)
        try:
            info, tr, stages, oi = run_one(args, args.file, work, "a")
        except OmniError as e:
            print(f"\u2716 {e}", file=sys.stderr)
            if e.hint:
                print(e.hint, file=sys.stderr)
            return 1
        graph, blocks, bedges = build_graph(tr, info, Path(args.file).name)
        report = render_report(tr, info, oi, stages, Path(args.file).name)
        if not args.quiet:
            sys.stderr.write(f"  \u25b8 recorded {tr.steps} instructions, {len(tr.syscalls)} syscalls, {len(tr.findings)} findings\n")

        diff = None
        if args.diff_against:
            info2, tr2, _, _ = run_one(args, args.diff_against, work, "b")
            diff = diff_runs(tr, tr2)
            report += "\n  " + "\u2500" * 70 + "\n  diff vs " + args.diff_against + ":\n"
            if diff["diverged_at_step"] is None:
                report += "    runs matched for the entire common prefix\n"
            else:
                report += f"    first instruction divergence at step {diff['diverged_at_step']}\n"
                for w in diff["window"]:
                    mark = " <<<" if w["step"] == diff["diverged_at_step"] else ""
                    report += f"      step {w['step']:<6} a:{w['sym_a']}@{w['a']}  b:{w['sym_b']}@{w['b']}{mark}\n"
            if diff["syscalls_a_tail"] != diff["syscalls_b_tail"]:
                report += "    syscalls diverge:\n      a: " + " | ".join(diff["syscalls_a_tail"]) + "\n      b: " + " | ".join(diff["syscalls_b_tail"]) + "\n"
            if diff["findings_only_a"] or diff["findings_only_b"]:
                report += f"    findings only in A: {diff['findings_only_a']}\n    findings only in B: {diff['findings_only_b']}\n"

        if args.output:
            Path(args.output).write_text(report)
        else:
            sys.stdout.write(report)
        if args.json:
            Path(args.json).write_text(json.dumps({"graph": graph, "findings": tr.findings, "syscalls": tr.syscalls,
                                                    "diff": diff}, indent=1, default=str))
        if args.dot:
            Path(args.dot).write_text(to_dot(graph))
        if args.html:
            Path(args.html).write_text(make_html(tr, info, graph, Path(args.file).name))
            if not args.quiet:
                sys.stderr.write(f"  \u25b8 wrote {args.html}\n")
    return 0


# --------------------------------------------------------------------------- #
#  Theme                                                                      #
# --------------------------------------------------------------------------- #
PALETTE = {
    "accent": (0, 255, 170), "cyan": (0, 229, 255), "pink": (255, 0, 170),
    "label": (255, 204, 102), "label_local": (160, 140, 90),
    "flow": (255, 85, 130), "stack": (189, 147, 249), "math": (110, 231, 140),
    "move": (102, 204, 255), "danger": (255, 60, 60), "reg": (255, 150, 110),
    "imm": (241, 250, 140), "sym": (139, 233, 253), "dim": (98, 114, 164), "bytes": (120, 135, 190),
    "comment": (98, 114, 164), "src": (80, 250, 170), "srcnum": (98, 114, 164),
    "err": (255, 85, 85), "warn": (255, 184, 108), "ok": (80, 250, 123),
}


class Painter:
    """24-bit ANSI colouring. Disabled painters return text untouched."""

    def __init__(self, enabled: bool):
        self.enabled = enabled

    def __call__(self, text: str, role: str, bold: bool = False) -> str:
        if not self.enabled or not text:
            return text
        r, g, b = PALETTE[role]
        return f"\x1b[{'1;' if bold else ''}38;2;{r};{g};{b}m{text}\x1b[0m"

    def gradient(self, text: str, start="cyan", end="pink") -> str:
        if not self.enabled:
            return text
        (r1, g1, b1), (r2, g2, b2) = PALETTE[start], PALETTE[end]
        n, out = max(len(text) - 1, 1), []
        for i, ch in enumerate(text):
            t = i / n
            c = (int(r1 + (r2 - r1) * t), int(g1 + (g2 - g1) * t), int(b1 + (b2 - b1) * t))
            out.append(ch if ch == " " else f"\x1b[1;38;2;{c[0]};{c[1]};{c[2]}m{ch}\x1b[0m")
        return "".join(out)


BANNER = ("▄▀█ █▀ █▀▄▀█ ▀▄▀", "█▀█ ▄█ █░▀░█ █░█")


def print_banner(p: Painter) -> None:
    for row in BANNER:
        print("  " + p.gradient(row), file=sys.stderr)
    print("  " + p(f"source ⟶ assembly  //  v{__version__}", "dim") + "\n", file=sys.stderr)


# --------------------------------------------------------------------------- #
#  Data model                                                                 #
# --------------------------------------------------------------------------- #
@dataclass
class Item:
    kind: str                 # label | ins | data
    text: str = ""            # label name / raw directive text
    mnem: str = ""
    ops: str = ""
    comment: str = ""
    addr: str = ""
    src: int | None = None    # source line this instruction came from
    section: str = "text"
    local: bool = False
    text_d: str = ""          # demangled variants (display only)
    ops_d: str = ""
    raw: str = ""             # machine-code bytes (hex), real binaries only


# --------------------------------------------------------------------------- #
#  Parsing: gcc / clang / rustc assembly                                      #
# --------------------------------------------------------------------------- #
_FILE = re.compile(r"^\s*\.file\s+(\d+)\s+(.*)$")
_LOC = re.compile(r"^\s*\.loc\s+(\d+)\s+(\d+)")
_LABEL = re.compile(r'^\s*([A-Za-z_.$][\w.$@]*|"[^"]+"):(.*)$')
_SECTION = re.compile(r"^\.(text|data|bss|section|rodata)\b\s*(.*)$")
_DATA_DIR = re.compile(
    r"^\.(string|ascii|asciz|byte|word|short|value|long|int|quad|zero|space|double|float|octa|[248]byte)\b")
_COMMENT = re.compile(r"\s(?:#(?:\s|$)|//)")
_INS = re.compile(r"^\s*([A-Za-z][\w.]*)(?:\s+(.*?))?\s*$")
_SYMBOL = re.compile(r"[A-Za-z_.$][\w.$@]*")


def _is_local(name: str) -> bool:
    return name.startswith(".L") or bool(re.match(r"^L(?:BB|FB|FE|C|JTI)\d", name))


def parse_asm(text: str, src_name: str, raw: bool) -> list[Item]:
    items: list[Item] = []
    main_ids: set[int] = set()
    cur_src: int | None = None
    section = "text"

    for line in text.splitlines():
        m = _FILE.match(line)
        if m:
            names = re.findall(r'"([^"]*)"', m.group(2))
            if names and Path(names[-1]).name == src_name:
                main_ids.add(int(m.group(1)))
            if raw:
                items.append(Item("data", text=line.strip(), section=section))
            continue
        m = _LOC.match(line)
        if m:
            fid, ln = int(m.group(1)), int(m.group(2))
            cur_src = ln if fid in main_ids and ln > 0 else None
            if raw:
                items.append(Item("data", text=line.strip(), section=section))
            continue

        m = _LABEL.match(line)
        if m:
            name = m.group(1).strip('"')
            items.append(Item("label", text=name, section=section, local=_is_local(name)))
            line = m.group(2)

        s = line.strip()
        if not s or s.startswith(("#", "//", ";", "@")):
            continue
        if s.startswith("."):
            sm = _SECTION.match(s)
            if sm:
                kind, rest = sm.groups()
                name = rest.strip() if kind == "section" else "." + kind
                if name.startswith(".text"):
                    section = "text"
                elif name.startswith((".data", ".bss", ".rodata", ".tdata", ".tbss")):
                    section = "data"
                else:
                    section = "skip"  # .debug_*, .note.*, .eh_frame ...
            if raw or _DATA_DIR.match(s):
                items.append(Item("data", text=re.sub(r"\s+", " ", s, count=1), section=section))
            continue

        comment = ""
        cm = _COMMENT.search(line)
        if cm:
            comment, line = line[cm.start():].strip(), line[:cm.start()]
        im = _INS.match(line)
        if im:
            items.append(Item("ins", mnem=im.group(1), ops=(im.group(2) or "").strip(),
                              comment=comment, src=cur_src, section=section))
    return items if raw else [i for i in items if i.section != "skip"]


# --------------------------------------------------------------------------- #
#  Parsing: objdump (compiled binaries)                                       #
# --------------------------------------------------------------------------- #
_OBJ_FUNC = re.compile(r"^([0-9a-f]+) <(.+)>:$")
_OBJ_INS = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f]{2}(?: [0-9a-f]{2})*)\s*(?:\t(.*))?$")
_OBJ_LINE = re.compile(r"^(\S.*):(\d+)(?: \(discriminator \d+\))?$")
_OBJ_COMMENT = re.compile(r"\s+#\s")


def parse_objdump(text: str, src_name: str | None = None) -> list[Item]:
    """Parse `objdump -d -l`: real addresses, machine-code bytes, source lines."""
    items: list[Item] = []
    cur_src: int | None = None
    for line in text.splitlines():
        m = _OBJ_FUNC.match(line)
        if m:
            items.append(Item("label", text=m.group(2), addr=m.group(1).lstrip("0") or "0"))
            cur_src = None
            continue
        m = _OBJ_INS.match(line)
        if m:
            addr, raw, body = m.group(1), m.group(2).strip(), (m.group(3) or "").strip()
            if not body:  # continuation line of a long instruction: more bytes only
                for prev in reversed(items):
                    if prev.kind == "ins":
                        prev.raw += " " + raw
                        break
                continue
            comment = ""
            cm = _OBJ_COMMENT.search(body)
            if cm:
                comment, body = body[cm.start():].strip(), body[:cm.start()]
            parts = body.split(None, 1)
            if parts:
                ops = re.sub(r",(?=\S)", ", ", parts[1].strip()) if len(parts) > 1 else ""
                items.append(Item("ins", mnem=parts[0], ops=ops, comment=comment,
                                  addr=addr, raw=raw, src=cur_src))
            continue
        m = _OBJ_LINE.match(line)
        if m and src_name:
            ln = int(m.group(2))
            cur_src = ln if Path(m.group(1)).name == src_name and ln > 0 else None
    return items


# --------------------------------------------------------------------------- #
#  Python bytecode (CPython VM "assembly")                                    #
# --------------------------------------------------------------------------- #
def python_items(source: str, name: str) -> list[Item]:
    try:
        code = compile(source, name, "exec")
    except SyntaxError as exc:
        raise AsmxError("python syntax error", detail=f"{name}:{exc.lineno}: {exc.msg}") from exc

    items: list[Item] = []

    def walk(co) -> None:
        items.append(Item("label", text=getattr(co, "co_qualname", co.co_name)))
        prev = None
        for ins in dis.get_instructions(co):
            pos = getattr(ins, "positions", None)
            ln = pos.lineno if pos is not None and pos.lineno else None
            if ln is None:
                sl = getattr(ins, "line_number", None) or ins.starts_line
                ln = sl if isinstance(sl, int) and not isinstance(sl, bool) else prev
            prev = ln
            items.append(Item("ins", mnem=ins.opname, ops=ins.argrepr, addr=f"{ins.offset:04d}", src=ln))
        for const in co.co_consts:
            if hasattr(const, "co_code"):
                walk(const)

    walk(code)
    return items


# --------------------------------------------------------------------------- #
#  Toolchain                                                                  #
# --------------------------------------------------------------------------- #
def run(cmd: list[str], cwd: Path | None, timeout: int, env: dict | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                              errors="replace", timeout=timeout, env=env)
    except subprocess.TimeoutExpired as exc:
        raise AsmxError(f"{Path(cmd[0]).name} timed out after {timeout}s",
                        hint="raise it with --timeout") from exc
    except OSError as exc:
        raise AsmxError(f"cannot run {cmd[0]}: {exc}", EXIT_MISSING) from exc


def find_tool(lang: str, override: str | None) -> str:
    if override:
        found = shutil.which(override)
        if not found:
            raise AsmxError(f"compiler not found: {override}", EXIT_MISSING)
        return found
    for cand in TOOLS[lang]:
        found = shutil.which(cand)
        if found:
            return found
    pkg = {"c": "gcc", "c++": "g++", "rust": "rustc"}[lang]
    raise AsmxError(f"no {lang} compiler found (tried {', '.join(TOOLS[lang])})", EXIT_MISSING,
                    hint=f"install one, e.g.  sudo apt install {pkg}")


def tool_version(tool: str) -> str:
    try:
        out = subprocess.run([tool, "--version"], capture_output=True, text=True, timeout=5).stdout
        return out.splitlines()[0].strip() if out else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def compile_to_asm(lang, src: Path, opt, flags, att, tool, timeout, workdir: Path) -> tuple[str, str]:
    out = workdir / "out.s"
    if lang == "rust":
        level = {"g": "1", "fast": "3"}.get(opt, opt)
        crate = "bin" if re.search(r"\bfn\s+main\s*\(", src.read_text(errors="replace")) else "lib"
        cmd = [tool, "--emit", "asm", "-C", f"opt-level={level}", "-C", "debuginfo=1",
               "--crate-type", crate, "--edition", "2021", "-o", str(out), str(src)]
        if IS_X86 and not att:
            cmd += ["-C", "llvm-args=-x86-asm-syntax=intel"]
    else:
        cmd = [tool, "-S", f"-O{opt}", "-g1", "-fno-asynchronous-unwind-tables", "-fno-ident"]
        if IS_X86:
            cmd.append("-fcf-protection=none")
            if not att:
                cmd.append("-masm=intel")
        cmd += ["-o", str(out), str(src)]
    cmd += flags

    proc = run(cmd, src.parent, timeout)
    if proc.returncode != 0 or not out.exists():
        raise AsmxError("compilation failed", detail=proc.stderr.strip() or "(no compiler output)")
    return out.read_text(errors="replace"), proc.stderr.strip()


def parse_flags(flags: str) -> list[str]:
    try:
        return shlex.split(flags)
    except ValueError as exc:
        raise AsmxError(f"bad --flags: {exc}", EXIT_USAGE) from exc


def ensure_source(lang: str, path: Path | None, text: str, workdir: Path) -> Path:
    if path is not None:
        return path
    src = workdir / ("stdin" + {"c": ".c", "c++": ".cpp", "rust": ".rs"}[lang])
    src.write_text(text)
    return src


def disassemble_binary(path: Path, att: bool, timeout: int, src_name: str | None = None) -> list[Item]:
    objdump = shutil.which("objdump")
    if not objdump:
        raise AsmxError("objdump not found", EXIT_MISSING, hint="install it:  sudo apt install binutils")

    def attempt(syntax: list[str]):
        return run([objdump, "-d", "-l", "-C", *syntax, str(path)], None, timeout)

    proc = attempt([] if att else ["-M", "intel"])
    if proc.returncode != 0 and "disassembler option" in proc.stderr:
        proc = attempt([])  # non-x86 target: no intel syntax
    if proc.returncode != 0:
        raise AsmxError("objdump failed", detail=proc.stderr.strip())
    return parse_objdump(proc.stdout, src_name)


def compile_to_exe(lang: str, src: Path, opt: str, flags: list[str], tool: str,
                   timeout: int, workdir: Path) -> Path:
    """Build a real executable: fixed (non-PIE) addresses, full debug info for gdb."""
    exe = workdir / "target.bin"
    cmd = [tool, f"-O{opt}", "-g", "-no-pie", "-fno-pie"]
    if IS_X86:
        cmd.append("-fcf-protection=none")
    cmd += ["-o", str(exe), str(src)] + flags
    proc = run(cmd, src.parent, timeout)
    if proc.returncode != 0 or not exe.exists():
        raise AsmxError("build failed", detail=proc.stderr.strip() or "(no compiler output)",
                        hint="--deep/--trace need a program that links (it must define main)")
    return exe


def keep_user_functions(items: list[Item]) -> list[Item]:
    """Drop CRT / PLT boilerplate: keep only functions that map back to your source."""
    blocks: list[list[Item]] = []
    for it in items:
        if it.kind == "label" or not blocks:
            blocks.append([])
        blocks[-1].append(it)
    kept = [b for b in blocks if any(i.src for i in b if i.kind == "ins")]
    return [i for b in kept for i in b] or items


# gdb runs this script (gdb embeds Python): break, then single-step and log JSON lines.
GDB_TRACER = r'''
import gdb, json, os

OUT = open(os.environ["ASMX_OUT"], "w")
FUNC = os.environ["ASMX_FUNC"]
STEPS = int(os.environ["ASMX_STEPS"])
REGS = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11",
        "r12", "r13", "r14", "r15", "rip", "eflags"]
MASK = (1 << 64) - 1


def emit(kind, **kw):
    kw["t"] = kind
    OUT.write(json.dumps(kw) + "\n")
    OUT.flush()


def regs():
    frame = gdb.selected_frame()
    out = {}
    for name in REGS:
        val = frame.read_register(name)
        out[name] = str(val) if name == "eflags" else int(val) & MASK
    return out


def qword(addr):
    return int.from_bytes(bytes(gdb.selected_inferior().read_memory(addr, 8)), "little")


def symbol(pc):
    try:
        s = gdb.execute("info symbol %d" % pc, to_string=True).strip()
    except gdb.error:
        return None
    return None if s.startswith("No symbol") else s.split(" in section")[0]


def alive():
    return gdb.selected_inferior().pid != 0


def run_trace():
    gdb.execute("set pagination off")
    gdb.execute("set confirm off")
    gdb.execute("set disassembly-flavor intel")
    gdb.execute("break " + FUNC, to_string=True)
    gdb.execute("run > '%s'" % os.environ["ASMX_PROG_OUT"].replace("'", ""), to_string=True)
    if not alive():
        emit("error", msg="the program exited before reaching '%s' (not found, inlined away, or never called)" % FUNC)
        return
    inf = gdb.selected_inferior()
    prev = regs()
    stack = []
    for i in range(16):
        try:
            stack.append(qword(prev["rsp"] + 8 * i))
        except gdb.MemoryError:
            break
    with open("/proc/%d/maps" % inf.pid) as fh:
        maps = fh.read().splitlines()
    emit("start", func=FUNC, regs=prev, stack=stack, maps=maps)

    done = 0
    while done < STEPS:
        frame = gdb.selected_frame()
        pc = int(frame.pc())
        insn = frame.architecture().disassemble(pc)[0]
        sal = gdb.find_pc_line(pc)
        ev = dict(i=done, pc=pc, asm=insn["asm"],
                  raw=bytes(inf.read_memory(pc, insn["length"])).hex(" "),
                  line=sal.line if sal.symtab else 0,
                  file=sal.symtab.filename if sal.symtab else "",
                  sym=symbol(pc))
        is_call = insn["asm"].split()[0].startswith("call")
        gdb.execute("stepi", to_string=True)
        if not alive():
            emit("step", chg={}, **ev)
            emit("exit")
            return
        if is_call and not gdb.find_pc_line(int(gdb.selected_frame().pc())).symtab:
            # landed in code without debug info (libc, PLT): run until it returns
            ret = qword(int(gdb.selected_frame().read_register("rsp")) & MASK)
            gdb.execute("tbreak *%d" % ret, to_string=True)
            gdb.execute("continue", to_string=True)
            ev["skipped"] = True
            if not alive():
                emit("step", chg={}, **ev)
                emit("exit")
                return
        cur = regs()
        ev["chg"] = {k: [prev[k], cur[k]] for k in REGS if k != "rip" and prev[k] != cur[k]}
        prev = cur
        emit("step", **ev)
        done += 1
    emit("end", steps=done)


try:
    run_trace()
except gdb.error as exc:
    emit("error", msg=str(exc))
except Exception as exc:  # never leave the host tool hanging without a reason
    emit("error", msg="%s: %s" % (type(exc).__name__, exc))
'''


def trace_binary(exe: Path, func: str, steps: int, prog_args: list[str],
                 timeout: int, workdir: Path) -> tuple[list[dict], str]:
    gdb = shutil.which("gdb")
    if not gdb:
        raise AsmxError("gdb not found", EXIT_MISSING, hint="install it:  sudo apt install gdb")
    script, out, prog = workdir / "tracer.py", workdir / "trace.jsonl", workdir / "program.out"
    script.write_text(GDB_TRACER)
    env = dict(os.environ, ASMX_OUT=str(out), ASMX_FUNC=func, ASMX_STEPS=str(steps),
               ASMX_PROG_OUT=str(prog))
    proc = run([gdb, "-q", "-batch", "-nx", "-x", str(script), "--args", str(exe), *prog_args],
               None, timeout, env=env)
    if not out.exists():
        raise AsmxError("gdb produced no trace", detail=(proc.stderr or proc.stdout).strip(),
                        hint="does your gdb have Python support?  gdb -batch -ex 'python print(1)'")
    events = []
    for line in out.read_text().splitlines():
        try:
            events.append(json.loads(line))
        except ValueError:
            continue
    for ev in events:
        if ev.get("t") == "error":
            raise AsmxError(f"trace failed: {ev.get('msg', 'unknown error')}",
                            detail=proc.stderr.strip()[-600:])
    return events, prog.read_text(errors="replace") if prog.exists() else ""


def demangle(items: list[Item]) -> None:
    exe = shutil.which("c++filt")
    if not exe:
        return
    pending = []
    for it in items:
        if it.kind == "label" and ("_Z" in it.text or "_R" in it.text):
            pending.append((it, "text_d", it.text))
        elif it.kind == "ins" and ("_Z" in it.ops or "_R" in it.ops):
            pending.append((it, "ops_d", it.ops))
    if not pending:
        return
    try:
        proc = subprocess.run([exe], input="\n".join(p[2] for p in pending) + "\n",
                              capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return
    lines = proc.stdout.splitlines()
    if proc.returncode == 0 and len(lines) == len(pending):
        for (it, attr, _), val in zip(pending, lines):
            setattr(it, attr, val)


# --------------------------------------------------------------------------- #
#  Selection / filtering                                                      #
# --------------------------------------------------------------------------- #
def select(items: list[Item], func: str | None, raw: bool) -> list[Item]:
    if func:
        kept, on = [], False
        for it in items:
            if it.section == "text":
                if it.kind == "label" and not it.local:
                    on = func in it.text or func in it.text_d
                if on:
                    kept.append(it)
            else:
                kept.append(it)  # data candidates, pruned below
        items = kept
    if raw:
        return items

    refs: set[str] = set()
    for it in items:
        if it.kind in ("ins", "data"):
            refs.update(_SYMBOL.findall(it.ops if it.kind == "ins" else it.text))

    code, data, keep_group = [], [], not func
    for it in items:
        if it.section == "text":
            if it.kind == "label" and it.local and it.text not in refs:
                continue
            code.append(it)
        else:
            if it.kind == "label":
                keep_group = (not func) or it.text in refs
            if keep_group:
                data.append(it)
    return code + data  # constants / strings go after the code


# --------------------------------------------------------------------------- #
#  Highlighting + rendering                                                   #
# --------------------------------------------------------------------------- #
_PY_FLOW = re.compile(r"^(CALL|JUMP|POP_JUMP|RETURN|FOR_ITER|RAISE|SEND|YIELD)")
_PY_STACK = re.compile(r"^(PUSH_|POP_TOP|COPY|SWAP|DUP_TOP|ROT_)")
_PY_MATH = re.compile(r"^(BINARY_|UNARY_|COMPARE_|CONTAINS_OP|IS_OP|INPLACE_)")
_FLOW = re.compile(r"^(?:j[a-z]{1,4}|call[a-z]?|ret[a-z]?|loop[a-z]{0,2}|bl?r?|b\.[a-z]{2}|cbn?z|tbn?z)$")
_STACK = re.compile(r"^(?:push|pop|leave|enter)[a-z]?$")
_MATH = re.compile(
    r"^(?:add|sub|adc|sbb|mul|imul|div|idiv|inc|dec|neg|not|and|or|xor|shl|shr|sal|sar|rol|ror|cmp|test|lea)[bwlq]?$")
_DANGER = re.compile(r"^(?:syscall|sysenter|sysret|int3?|ud2|hlt|svc|brk|cli|sti|cpuid|rdtsc|rdmsr|wrmsr)$")
_NOP = re.compile(r"^(?:nop[a-z]?|endbr(?:32|64))$")

_REGS = (r"[re]?[abcd]x|[abcd][lh]|[re]?[sd]il?|[re]?[sb]pl?|r(?:8|9|1[0-5])[dwb]?|"
         r"[xyz]mm\d{1,2}|[re]?ip|[c-gs]s|st(?:\(\d\))?|[xw]\d{1,2}|sp|lr|pc|xzr|wzr|[vqds]\d{1,2}")
_OPERAND = re.compile(
    r"(?P<kw>\b(?:BYTE|WORD|DWORD|QWORD|TBYTE|XMMWORD|YMMWORD|ZMMWORD|OFFSET|PTR|FLAT)\b)"
    rf"|(?P<reg>%?\b(?:{_REGS})\b)"
    r"|(?P<num>\$?-?(?:0x[0-9a-fA-F]+|\d+)\b|#-?(?:0x[0-9a-fA-F]+|\d+)\b)"
    r"|(?P<lbl>\.L[\w.$]+)"
    r"|(?P<sym>[A-Za-z_][\w.$@]*)")
_ROLE = {"kw": "dim", "reg": "reg", "num": "imm", "lbl": "label", "sym": "sym"}


def classify(mnem: str, lang: str) -> str:
    if lang == "python":
        m = mnem.upper()
        if _PY_FLOW.match(m):
            return "flow"
        if _PY_STACK.match(m):
            return "stack"
        return "math" if _PY_MATH.match(m) else "move"
    m = mnem.lower()
    if _DANGER.match(m):
        return "danger"
    if _FLOW.match(m):
        return "flow"
    if _STACK.match(m):
        return "stack"
    if _MATH.match(m):
        return "math"
    return "dim" if _NOP.match(m) else "move"


def highlight_ops(ops: str, p: Painter) -> str:
    if not p.enabled or not ops:
        return ops
    return _OPERAND.sub(lambda m: p(m.group(), _ROLE[m.lastgroup]), ops)


def render(items: list[Item], src_lines: list[str], p: Painter, lang: str, show_src: bool,
           show_bytes: bool = False) -> list[str]:
    out: list[str] = []
    aw = max((len(i.addr) for i in items if i.kind == "ins"), default=0)
    bw = min(23, max((len(i.raw) for i in items if i.kind == "ins"), default=0)) if show_bytes else 0
    last_src, in_data = None, False
    for it in items:
        if it.section != "text" and not in_data:
            in_data = True
            out += ["", p("; ─── data ───", "dim")]
        if it.kind == "label":
            if not it.local and not in_data:
                if out:
                    out.append("")
                last_src = None
            line = p((it.text_d or it.text) + ":", "label_local" if it.local else "label", bold=not it.local)
            if it.addr and not it.local:
                line += p(f"  @ 0x{it.addr}", "dim")
            out.append(line)
        elif it.kind == "data":
            out.append("    " + p(it.text, "dim"))
        else:
            if show_src and it.src and it.src != last_src and 0 < it.src <= len(src_lines):
                out.append(p("  ▍", "accent") + p(f"{it.src:>4} │ ", "srcnum")
                           + p(src_lines[it.src - 1].strip(), "src"))
                last_src = it.src
            cat = classify(it.mnem, lang)
            mn = p(it.mnem, cat, bold=cat in ("flow", "danger")) + " " * max(1, 8 - len(it.mnem))
            addr = p(it.addr.rjust(aw) + "  ", "dim") if aw else ""
            raw = ""
            if bw:
                shown = it.raw if len(it.raw) <= bw else it.raw[:bw - 1] + "…"
                raw = p(shown.ljust(bw), "bytes") + "  "
            line = f"    {addr}{raw}{mn}{highlight_ops(it.ops_d or it.ops, p)}"
            if it.comment:
                line += "  " + p(it.comment, "comment")
            out.append(line.rstrip())
    return out


# --------------------------------------------------------------------------- #
#  Dynamic trace rendering                                                    #
# --------------------------------------------------------------------------- #
def _parse_maps(lines: list[str]) -> list[tuple[int, int, str, str]]:
    out = []
    for ln in lines:
        parts = ln.split(None, 5)
        if len(parts) < 5:
            continue
        try:
            lo, hi = (int(x, 16) for x in parts[0].split("-"))
        except ValueError:
            continue
        out.append((lo, hi, Path(parts[5]).name if len(parts) > 5 else "anon", parts[1]))
    return out


def _region(addr: int, maps) -> str:
    if addr < 0x1000:
        return ""
    for lo, hi, name, _ in maps:
        if lo <= addr < hi:
            return name
    return ""


def _ascii_hint(v: int) -> str:
    bs = v.to_bytes(8, "little").rstrip(b"\0")
    return f"'{bs.decode()}'" if len(bs) >= 3 and all(32 <= b < 127 for b in bs) else ""


def render_trace(events: list[dict], p: Painter, src_lines: list[str], src_name: str | None,
                 prog_out: str, func: str) -> list[str]:
    start = next((e for e in events if e["t"] == "start"), None)
    if start is None:
        raise AsmxError("trace produced no data")
    steps = [e for e in events if e["t"] == "step"]
    end = next((e for e in reversed(events) if e["t"] in ("end", "exit")), None)
    maps = _parse_maps(start["maps"])

    def section(title: str) -> str:
        return p("━━ ", "pink") + p(title, "accent", bold=True) + " " + p("━" * max(4, 62 - len(title)), "pink")

    def note(v: int) -> str:
        r = _region(v, maps)
        return p(f"‹{r}›", "dim") if r else ""

    out = ["", section(f"REGISTERS  ·  breakpoint at {func}")]
    for name, val in start["regs"].items():
        if name == "eflags":
            out.append(f"  {p(name.ljust(8), 'reg')}{p(val, 'imm')}")
        else:
            out.append(f"  {p(name.ljust(8), 'reg')}{p('0x%016x' % val, 'imm')}  {note(val)}")

    rsp = start["regs"]["rsp"]
    out += ["", section("STACK  ·  16 qwords from rsp")]
    for i, v in enumerate(start["stack"]):
        out.append(f"  {p('0x%x' % (rsp + 8 * i), 'dim')}  {p(f'rsp+0x{8 * i:02x}', 'dim')}  "
                   f"{p('0x%016x' % v, 'imm')}  {note(v)} {p(_ascii_hint(v), 'src')}".rstrip())

    out += ["", section("MEMORY MAP")]
    for lo, hi, name, perms in maps[:18]:
        out.append(f"  {p('0x%012x-0x%012x' % (lo, hi), 'dim')}  {p(perms, 'bytes')}  {p(name, 'sym')}")
    if len(maps) > 18:
        out.append(p(f"  … {len(maps) - 18} more", "dim"))

    out += ["", section(f"EXECUTION  ·  {len(steps)} instructions"), ""]
    bw = min(23, max((len(e["raw"]) for e in steps), default=0))
    last_line = None
    for ev in steps:
        if ev["line"] and ev["line"] != last_line:
            last_line = ev["line"]
            name = Path(ev["file"]).name
            if name == src_name and 0 < ev["line"] <= len(src_lines):
                out.append(p("  ▍", "accent") + p(f"{ev['line']:>4} │ ", "srcnum")
                           + p(src_lines[ev["line"] - 1].strip(), "src"))
            else:
                out.append(p("  ▍ ", "accent") + p(f"{name}:{ev['line']}", "dim"))
        mnem, _, ops = ev["asm"].strip().partition(" ")
        ops = re.sub(r",(?=\S)", ", ", ops.strip())
        cat = classify(mnem, "x86")
        plain_len = 8 + len(ops)
        raw = ev["raw"] if len(ev["raw"]) <= bw else ev["raw"][:bw - 1] + "…"
        line = (f"  {p('%04d' % ev['i'], 'dim')}  {p('0x%x' % ev['pc'], 'label')}  "
                f"{p(raw.ljust(bw), 'bytes')}  "
                f"{p(mnem, cat, bold=cat in ('flow', 'danger'))}{' ' * max(1, 8 - len(mnem))}"
                f"{highlight_ops(ops, p)}")
        if ev["chg"]:
            changes = []
            for name, (old, new) in ev["chg"].items():
                a, b = (old, new) if name == "eflags" else ("0x%x" % old, "0x%x" % new)
                changes.append(f"{p(name, 'reg')} {p(a, 'dim')} {p('➜', 'pink')} {p(b, 'ok', bold=True)}")
            line += " " * max(2, 36 - plain_len) + p("‹ ", "dim") + "  ".join(changes) + p(" ›", "dim")
        out.append(line)
        if ev.get("skipped"):
            out.append(p("          ⤷ stepped over a call into code without debug info", "dim"))

    out.append("")
    if end and end["t"] == "exit":
        out.append(p("  ■ ", "pink") + "program exited during trace")
    else:
        out.append(p("  ■ ", "pink") + f"stopped after {len(steps)} instructions (raise with --steps)")
    if prog_out.strip():
        out += ["", section("PROGRAM OUTPUT")] + [p("  " + ln, "dim") for ln in prog_out.rstrip().splitlines()]
    return out


def compute_stats(items: list[Item], lang: str = "x86") -> dict[str, int]:
    ins = [i for i in items if i.kind == "ins"]
    low = [i.mnem.lower() for i in ins]
    calls = sum(1 for m in low if m.startswith("call"))
    rets = sum(1 for m in low if m.startswith(("ret", "return")))
    flow = sum(1 for i in ins if classify(i.mnem, lang) == "flow")
    mem = sum(1 for i in ins if "[" in i.ops or "(%" in i.ops)
    stats = {"instructions": len(ins), "calls": calls, "branches": max(flow - calls - rets, 0),
             "memory ops": mem}
    size = sum((len(i.raw) + 1) // 3 for i in ins)
    if size:
        stats["bytes"] = size
    return stats


def print_stats(items: list[Item], p: Painter, info: str, lang: str = "x86") -> None:
    parts = [f"{p(str(v), 'accent', bold=True)} {p(k, 'dim')}" for k, v in compute_stats(items, lang).items()]
    print("\n  " + p(" ▸ ", "pink").join(parts), file=sys.stderr)
    if info:
        print("  " + p(info, "dim"), file=sys.stderr)


# --------------------------------------------------------------------------- #
#  Domains: palettes, frame buffer, domain-expansion intros                   #
# --------------------------------------------------------------------------- #
THEMES = {"cyber": dict(PALETTE)}
DOMAINS = {
    "cyber": dict(en="NEURAL LINK", jp="", sub="source ⟶ silicon", mark="◢◤", pal={}),
    "matrix": dict(
        en="THE CONSTRUCT", jp="", sub="there is no spoon, only registers", mark="▒▓",
        pal=dict(accent=(0, 255, 65), cyan=(0, 210, 80), pink=(0, 120, 45), label=(160, 255, 160),
                 label_local=(70, 150, 80), flow=(190, 255, 110), stack=(0, 175, 120), math=(90, 255, 140),
                 move=(60, 205, 95), reg=(120, 255, 170), imm=(215, 255, 190), sym=(100, 235, 150),
                 dim=(0, 115, 45), bytes=(20, 145, 65), comment=(0, 115, 45), src=(120, 255, 140),
                 srcnum=(0, 115, 45), ok=(0, 255, 100))),
    "gojo": dict(
        en="UNLIMITED VOID", jp="無量空処", sub="every byte, every branch, perceived at once", mark="∞",
        pal=dict(accent=(120, 200, 255), cyan=(0, 229, 255), pink=(150, 110, 255), label=(210, 235, 255),
                 label_local=(110, 130, 170), flow=(130, 160, 255), stack=(180, 130, 255), math=(120, 235, 255),
                 move=(80, 150, 255), danger=(255, 90, 140), reg=(170, 205, 255), imm=(235, 245, 255),
                 sym=(110, 240, 255), dim=(75, 95, 150), bytes=(85, 105, 185), comment=(75, 95, 150),
                 src=(150, 215, 255), srcnum=(75, 95, 150), err=(255, 90, 140), warn=(255, 215, 120),
                 ok=(120, 255, 225))),
    "sukuna": dict(
        en="MALEVOLENT SHRINE", jp="伏魔御廚子", sub="dismantle every instruction. cleave every branch.", mark="◢◣",
        pal=dict(accent=(255, 50, 60), cyan=(255, 140, 50), pink=(190, 0, 40), label=(255, 215, 180),
                 label_local=(160, 110, 90), flow=(255, 70, 70), stack=(210, 90, 70), math=(255, 175, 80),
                 move=(235, 125, 105), danger=(255, 245, 160), reg=(255, 155, 115), imm=(255, 230, 180),
                 sym=(255, 195, 130), dim=(150, 70, 85), bytes=(160, 85, 100), comment=(150, 70, 85),
                 src=(255, 195, 175), srcnum=(150, 70, 85), err=(255, 80, 80), warn=(255, 200, 90),
                 ok=(255, 170, 60))),
}
DOMAIN = {"name": "cyber"}


def apply_domain(name: str) -> None:
    DOMAIN["name"] = name
    PALETTE.clear()
    PALETTE.update(THEMES["cyber"])
    PALETTE.update(DOMAINS[name]["pal"])


def dom() -> dict:
    return DOMAINS[DOMAIN["name"]]


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def dw(s: str) -> int:
    """Display width (CJK = 2 cells)."""
    n = 0
    for ch in s:
        if unicodedata.combining(ch):
            continue
        n += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return n


def vlen(s: str) -> int:
    return dw(_ANSI.sub("", s))


def scale(rgb, f):
    return tuple(max(0, min(255, int(c * f))) for c in rgb)


def mix(a, b, t):
    return tuple(int(x + (y - x) * t) for x, y in zip(a, b))


def rstyle(role: str, f: float = 1.0, bold: bool = False, bg=None):
    return (scale(PALETTE[role], f), bold, bg)


def _sgr(st) -> str:
    if st is None:
        return "\x1b[0m"
    fg, bold, bg = st
    codes = ["0"]
    if bold:
        codes.append("1")
    if fg:
        codes += ["38", "2", *map(str, fg)]
    if bg:
        codes += ["48", "2", *map(str, bg)]
    return "\x1b[" + ";".join(codes) + "m"


class Frame:
    """Cell grid: each cell is (char, style). Style = (fg_rgb, bold, bg_rgb) or None."""

    def __init__(self, w: int, h: int, fill=(" ", None)):
        self.w, self.h = w, h
        self.cells = [[fill] * w for _ in range(h)]

    def put(self, x: int, y: int, text: str, style=None) -> None:
        if not 0 <= y < self.h:
            return
        for ch in text:
            n = dw(ch)
            if n == 0:
                continue
            if 0 <= x < self.w and (n == 1 or x + 1 < self.w):
                self.cells[y][x] = (ch, style)
                if n == 2:
                    self.cells[y][x + 1] = ("", style)
            x += n

    def segs(self, x: int, y: int, parts) -> int:
        for text, style in parts:
            self.put(x, y, text, style)
            x += dw(text)
        return x

    def fade(self, k: float) -> None:
        for row in self.cells:
            for i, (ch, st) in enumerate(row):
                if st and st[0]:
                    row[i] = (ch, (scale(st[0], k), st[1], st[2]))

    def lines(self, color: bool = True) -> list[str]:
        out = []
        for row in self.cells:
            if not color:
                out.append("".join(ch for ch, _ in row).rstrip())
                continue
            buf, cur = [], object()
            for ch, st in row:
                if st != cur:
                    buf.append(_sgr(st))
                    cur = st
                buf.append(ch)
            buf.append("\x1b[0m")
            out.append("".join(buf))
        return out


class Screen:
    """Alternate-screen animation surface (writes to stderr so stdout stays pipeable)."""

    def __init__(self, out=None, speed: float = 1.0, size=None, dry: bool = False):
        self.out = out or sys.stderr
        self.dt = 1.0 / min(60.0, 24.0 * max(0.25, speed))
        self._size, self.dry, self._next = size, dry, 0.0

    def size(self) -> tuple[int, int]:
        if self._size:
            return self._size
        c, r = shutil.get_terminal_size((100, 30))
        return max(40, c - 1), max(14, r - 1)

    def __enter__(self):
        self.out.write("\x1b[?1049h\x1b[?25l\x1b[2J")
        self.out.flush()
        self._next = time.perf_counter()
        return self

    def __exit__(self, *exc):
        self.out.write("\x1b[0m\x1b[?25h\x1b[?1049l")
        self.out.flush()
        return False

    def show(self, fr: Frame) -> None:
        self.out.write("\x1b[H" + "\r\n".join(fr.lines()))
        self.out.flush()
        if self.dry:
            return
        self._next += self.dt
        lag = self._next - time.perf_counter()
        if lag > 0:
            time.sleep(lag)
        else:
            self._next = time.perf_counter()


def _ctext(fr: Frame, y: int, text: str, style, n: int | None = None) -> None:
    shown = text if n is None else text[:max(0, n)]
    fr.put((fr.w - dw(text)) // 2, y, shown, style)


def _backdrop(fr: Frame, cx: int, top: int, rows: int, half: int) -> None:
    for yy in range(top, top + rows):
        fr.put(cx - half, yy, " " * (2 * half))


def intro_gojo(scr: Screen) -> None:
    """領域展開 無量空処 — Unlimited Void: a sphere of infinite information swallows the screen."""
    w, h = scr.size()
    rng = random.Random(1618)
    cx, cy = w // 2, h // 2
    far = math.hypot(cx / 2.0, cy) + 3
    stars = [(rng.randrange(w), rng.randrange(h), rng.choice("··∙+*"), rng.random())
             for _ in range(max(60, w * h // 10))]
    streams = [(x, rng.random() * (h + 10), 0.5 + rng.random() * 1.2) for x in range(1, w, 3)]
    total = 64
    lines = [("領域展開", "imm"), ("無量空処", "accent"), ("U N L I M I T E D   V O I D", "cyan")]
    sub = "∞  every byte · every branch · perceived at once  ∞"
    for f in range(total):
        fr = Frame(w, h)
        r = far * min(1.0, (f / 24.0) ** 1.7)
        for x, y, ch, ph in stars:
            if math.hypot((x - cx) / 2.0, y - cy) < r:
                tw = 0.5 + 0.5 * math.sin(f * 0.4 + ph * 6.28)
                fr.put(x, y, ch, rstyle("cyan" if ph > 0.55 else "accent", 0.3 + 0.7 * tw))
        if f > 10:
            for x, y0, sp in streams:
                if abs(x - cx) / 2.0 > r:
                    continue
                head = int((y0 + f * sp * 1.4) % (h + 10)) - 2
                for k in range(7):
                    yy = head - k
                    if 0 <= yy < h and math.hypot((x - cx) / 2.0, yy - cy) < r:
                        digit = "0123456789abcdef"[(x * 7 + yy * 13 + f // 2) % 16]
                        fr.put(x, yy, digit, rstyle("accent" if k == 0 else "dim", 1.0 if k == 0 else 1.0 - k * 0.11, k == 0))
        if r < far * 0.98:
            for a in range(0, 360, 2):
                t = math.radians(a)
                fr.put(cx + int(r * 2 * math.cos(t)), cy + int(r * math.sin(t)), "◦", rstyle("imm", 1.0, True))
        if f >= 26:
            top = cy - 3
            _backdrop(fr, cx, top - 1, 8, 26)
            for i, (t, rl) in enumerate(lines):
                _ctext(fr, top + i * 2, t, rstyle(rl, 1.0, True), (f - 26 - i * 5) * 2)
            if f >= 44:
                _ctext(fr, top + 6, sub, rstyle("dim", 1.5), (f - 44) * 3)
        if total - 6 <= f < total - 4:
            fr = Frame(w, h, (" ", (None, False, (230, 242, 255))))
        elif f >= total - 4:
            fr.fade(max(0.0, 1.0 - (f - (total - 5)) * 0.3))
        scr.show(fr)


_SHRINE = [
    "▄██▄",
    "▄▄▀▀██▀▀▄▄",
    "▄▄▀▀▀▀▀▀▀▀▀▀▀▀▄▄",
    "▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀",
    "║ ▐▌ ▐▌ ▐▌ ▐▌ ║",
    "▄▄▄▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▄▄▄",
    "▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀",
    "║  ▐▌   ╔═══╗   ▐▌  ║",
    "║  ▐▌   ║▐▌▐▌║   ▐▌  ║",
    "▄▄▄▄▄▄▄▄▄╩═══╩▄▄▄▄▄▄▄▄▄▄",
    "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓",
    "▒░▒░▒░▒░▒░▒░▒░▒░▒░▒░▒░▒░▒░▒░▒░▒░",
]


def _line_cells(x0, y0, ang, w, h):
    """Cells of a straight slash through (x0,y0) at angle `ang`, wide-cell aware."""
    cs, sn = math.cos(ang), math.sin(ang)
    s = abs(sn) / (abs(cs) * 2 + 1e-9)
    ch = "─" if s < 0.35 else "│" if s > 2.8 else ("╱" if cs * sn < 0 else "╲")
    cells, seen = [], set()
    for k in range(-(w + h) * 2, (w + h) * 2):
        t = k / 2.0
        x, y = int(round(x0 + t * cs * 2)), int(round(y0 + t * sn))
        if 0 <= x < w and 0 <= y < h and (x, y) not in seen:
            seen.add((x, y))
            cells.append((x, y, ch))
    return cells


def intro_sukuna(scr: Screen) -> None:
    """領域展開 伏魔御廚子 — Malevolent Shrine: the screen is cleaved apart, a shrine rises."""
    w, h = scr.size()
    rng = random.Random(666)
    cx = w // 2
    slashes = [_line_cells(cx + rng.randint(-w // 4, w // 4), h // 2 + rng.randint(-h // 4, h // 4),
                           rng.choice((-1, 1)) * rng.uniform(0.2, 1.25) + (math.pi / 2 if i % 3 == 0 else 0), w, h)
               for i in range(9)]
    embers = [(rng.randrange(w), rng.random() * h, 0.15 + rng.random() * 0.5) for _ in range(max(30, w // 2))]
    total = 68
    art_h = len(_SHRINE)
    big = h >= art_h + 12
    lines = [("領域展開", "imm"), ("伏魔御廚子", "accent"), ("M A L E V O L E N T   S H R I N E", "cyan")]
    sub = "「 dismantle  ·  cleave  ·  every instruction laid bare 」"
    for f in range(total):
        fr = Frame(w, h)
        for x, y0, sp in embers:
            yy = int((y0 - f * sp) % h)
            fr.put(x, yy, "·" if (x + f) % 3 else "∙", rstyle("cyan", 0.35 + 0.3 * ((x * 7 + f) % 3) / 2))
        for i, cells in enumerate(slashes):
            p = min(1.0, max(0.0, (f - i * 3) / 4.0))
            if p <= 0:
                continue
            n = int(len(cells) * p)
            for j, (x, y, ch) in enumerate(cells[:n]):
                head = p < 1.0 and j > n - max(6, len(cells) // 8)
                fr.put(x, y, ch, rstyle("imm", 1.0, True) if head else rstyle("pink", 0.55 + 0.45 * (i / 9.0)))
        if big and f >= 24:
            rows = int(art_h * min(1.0, (f - 24) / 16.0))
            y_top = h - art_h - 1
            for i in range(art_h - rows, art_h):
                row = _SHRINE[i]
                x = (w - len(row)) // 2
                mixv = i / art_h
                fr.put(x, y_top + i, row, (mix(PALETTE["imm"], PALETTE["accent"], mixv), mixv < 0.3, None))
        if f >= 38:
            top = 2 if big else h // 2 - 3
            _backdrop(fr, cx, top - 1, 8, 28)
            for i, (t, rl) in enumerate(lines):
                _ctext(fr, top + i * 2, t, rstyle(rl, 1.0, True), (f - 38 - i * 5) * 2)
            if f >= 54:
                _ctext(fr, top + 6, sub, rstyle("dim", 1.6), (f - 54) * 3)
        if total - 6 <= f < total - 4:
            fr = Frame(w, h, (" ", (None, False, (170, 10, 25))))
        elif f >= total - 4:
            fr.fade(max(0.0, 1.0 - (f - (total - 5)) * 0.3))
        scr.show(fr)


def maybe_intro(args, err: Painter) -> None:
    """Play the domain-expansion intro on a real terminal; never let it break the tool."""
    if (args.domain not in ("gojo", "sukuna") or args.no_anim or args.quiet
            or not sys.stderr.isatty() or os.environ.get("ASMX_NO_ANIM")):
        return
    try:
        with Screen(sys.stderr, args.speed) as scr:
            (intro_gojo if args.domain == "gojo" else intro_sukuna)(scr)
    except (KeyboardInterrupt, OSError, ValueError):
        pass


# --------------------------------------------------------------------------- #
#  Functions + control-flow graph                                             #
# --------------------------------------------------------------------------- #
@dataclass
class Edge:
    id: int
    src: int
    dst: int
    kind: str                      # fall | taken | jump
    back: bool = False
    path: list = field(default_factory=list)

    @property
    def role(self) -> str:
        return "stack" if self.back else {"fall": "cyan", "taken": "flow", "jump": "ok"}[self.kind]


@dataclass
class Block:
    id: int
    idx: list
    label: str = ""
    succ: list = field(default_factory=list)
    pred: list = field(default_factory=list)
    depth: int = 0
    header: bool = False
    exit: bool = False
    indirect: bool = False
    tail: str = ""
    layer: int = 0


@dataclass
class Func:
    name: str
    dname: str
    addr: str = ""
    ins: list = field(default_factory=list)
    labels: dict = field(default_factory=dict)
    amap: dict = field(default_factory=dict)
    blocks: list = field(default_factory=list)
    edges: list = field(default_factory=list)
    block_of: dict = field(default_factory=dict)


_PREFIX = {"rep", "repz", "repnz", "repe", "repne", "lock", "bnd", "notrack", "data16", "cs", "ds", "es", "ss",
           "fs", "gs", "addr32", "xacquire", "xrelease"}
_RET = {"ret", "retq", "retn", "retf", "iret", "iretd", "iretq", "sysret", "sysretq", "hlt", "ud2", "eret"}
_UNCOND = {"jmp", "jmpq", "b", "br"}
_COND_RE = re.compile(r"^(?:j(?!mp)[a-z]{1,4}|loop[a-z]{0,2}|b\.[a-z]{2}|b(?:eq|ne|cs|cc|hs|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)"
                      r"|cbn?z|tbn?z)$")
_CALL_RE = re.compile(r"^(?:call[a-z]?|bl|blr)$")
_NORET = {"exit", "_exit", "abort", "__stack_chk_fail", "__assert_fail", "longjmp", "__longjmp_chk", "quick_exit",
          "pthread_exit", "__cxa_throw", "_Unwind_Resume", "__fortify_fail", "__chk_fail", "err", "errx", "verr"}


def norm_ins(it: Item) -> tuple[str, str]:
    """(mnemonic, operands) with prefixes like rep/lock/notrack folded away."""
    mn, ops = it.mnem, (it.ops_d or it.ops)
    while mn.lower() in _PREFIX and ops:
        mn, _, ops = ops.partition(" ")
        ops = ops.strip()
    return mn, ops


def call_name(ops: str) -> str:
    m = re.search(r"<([^>]+)>", ops)
    name = m.group(1) if m else ops.strip()
    name = re.sub(r"@plt$|@PLT$|\+0x[0-9a-f]+$", "", name)
    name = re.sub(r"@\w+$", "", name)
    return name.split("(")[0].strip() or ops.strip()


def branch_kind(mn: str, ops: str = "") -> str:
    m = mn.lower()
    if m in _RET or (m == "bx" and ops.strip() == "lr"):
        return "ret"
    if m in _UNCOND or m == "bx":
        return "jmp"
    if _CALL_RE.match(m):
        return "noret" if call_name(ops) in _NORET else "call"
    if _COND_RE.match(m):
        return "cond"
    return ""


_HEXT = re.compile(r"^(?:0x)?[0-9a-fA-F]+(?:\s*<.*>)?$")


def _resolve(fn: Func, it: Item, ops: str):
    """Return (target ins index | None, indirect?, tail text)."""
    tgt = ops.strip().split(",")[-1].strip()
    if not tgt:
        return None, True, ""
    if it.addr:
        if _HEXT.match(tgt) and not tgt.startswith("["):
            val = int(tgt.split()[0].replace("0x", ""), 16)
            idx = fn.amap.get(val)
            return idx, False, "" if idx is not None else call_name(tgt)
        return None, True, ""
    if tgt in fn.labels:
        return fn.labels[tgt], False, ""
    if re.match(r"^[A-Za-z_.$][\w.$@]*$", tgt) and not tgt.startswith("."):
        return None, False, tgt.split("@")[0]       # tail call to an external symbol
    return None, True, ""


def split_functions(items: list[Item]) -> list[Func]:
    funcs: list[Func] = []
    cur, pending = None, []
    for it in items:
        if it.section != "text":
            continue
        if it.kind == "label":
            if it.local and cur is not None:
                pending.append(it.text)
                continue
            cur = Func(name=it.text, dname=it.text_d or it.text, addr=it.addr)
            funcs.append(cur)
            pending = []
        elif it.kind == "ins" and cur is not None:
            for nm in pending:
                cur.labels[nm] = len(cur.ins)
            pending = []
            cur.ins.append(it)
    for fn in funcs:                                   # strip alignment padding after the last ret
        while fn.ins:
            mn, ops = norm_ins(fn.ins[-1])
            low = mn.lower()
            if low.startswith("nop") or low in ("int3", "data16") or (low == "xchg" and ops.replace(" ", "") == "ax,ax"):
                fn.ins.pop()
            else:
                break
        for i, it in enumerate(fn.ins):
            if it.addr:
                try:
                    fn.amap[int(it.addr, 16)] = i
                except ValueError:
                    pass
    return [f for f in funcs if f.ins]


def pick_function(funcs: list[Func], name: str | None) -> tuple[Func, list[Func]]:
    if name:
        exact = [f for f in funcs if name in (f.name, f.dname)]
        sub = [f for f in funcs if name in f.name or name in f.dname]
        chosen = exact or sub
        if not chosen:
            mine = [f for f in funcs if any(i.src for i in f.ins)] or funcs
            raise AsmxError(f"no function matching '{name}'",
                            hint="available: " + ", ".join(f.dname for f in mine[:12]))
        return chosen[0], chosen
    mains = [f for f in funcs if f.name == "main"]
    withsrc = [f for f in funcs if any(i.src for i in f.ins)]
    chosen = mains or withsrc or funcs
    return chosen[0], chosen


def build_cfg(fn: Func) -> None:
    ins, n = fn.ins, len(fn.ins)
    info, leaders = [], {0}
    for i, it in enumerate(ins):
        mn, ops = norm_ins(it)
        k = branch_kind(mn, ops)
        tgt, indirect, tail = None, False, ""
        if k in ("jmp", "cond"):
            tgt, indirect, tail = _resolve(fn, it, ops)
            if tgt is not None:
                leaders.add(tgt)
            if i + 1 < n:
                leaders.add(i + 1)
        elif k in ("ret", "noret") and i + 1 < n:
            leaders.add(i + 1)
        info.append((k, tgt, indirect, tail))
    starts = sorted(leaders)
    inv = {}
    for name, idx in fn.labels.items():
        inv.setdefault(idx, name)
    fn.blocks = []
    for bi, s in enumerate(starts):
        e = starts[bi + 1] if bi + 1 < len(starts) else n
        blk = Block(bi, list(range(s, e)))
        if bi == 0:
            blk.label = fn.dname
        elif s in inv:
            blk.label = inv[s]
        elif ins[s].addr:
            blk.label = f"0x{ins[s].addr}"
        fn.blocks.append(blk)
        for i in blk.idx:
            fn.block_of[i] = bi

    fn.edges = []
    seen = set()

    def link(a: int, b: int, kind: str) -> None:
        if (a, b, kind) in seen:
            return
        seen.add((a, b, kind))
        e = Edge(len(fn.edges), a, b, kind)
        fn.edges.append(e)
        fn.blocks[a].succ.append(e)
        fn.blocks[b].pred.append(e)

    for blk in fn.blocks:
        last = blk.idx[-1]
        k, tgt, indirect, tail = info[last]
        nxt = fn.block_of.get(last + 1)
        if k == "jmp":
            if tgt is not None:
                link(blk.id, fn.block_of[tgt], "jump")
            else:
                blk.exit, blk.indirect, blk.tail = True, indirect, tail
        elif k == "cond":
            if tgt is not None:
                link(blk.id, fn.block_of[tgt], "taken")
            else:
                blk.indirect, blk.tail = indirect, tail
            if nxt is not None:
                link(blk.id, nxt, "fall")
        elif k in ("ret", "noret"):
            blk.exit = True
        elif nxt is not None:
            link(blk.id, nxt, "fall")
        else:
            blk.exit = True

    # DFS: back edges, then natural loops -> depth
    color = [0] * len(fn.blocks)
    roots = [0] + [b.id for b in fn.blocks[1:]]
    post: list[int] = []
    for root in roots:
        if color[root]:
            continue
        color[root] = 1
        stack = [(root, 0)]
        while stack:
            b, i = stack.pop()
            if i < len(fn.blocks[b].succ):
                stack.append((b, i + 1))
                e = fn.blocks[b].succ[i]
                if color[e.dst] == 0:
                    color[e.dst] = 1
                    stack.append((e.dst, 0))
                elif color[e.dst] == 1:
                    e.back = True
            else:
                color[b] = 2
                post.append(b)
    rpo = post[::-1]
    for b in rpo:
        for e in fn.blocks[b].succ:
            if not e.back:
                fn.blocks[e.dst].layer = max(fn.blocks[e.dst].layer, fn.blocks[b].layer + 1)
    bodies: dict[int, set] = {}
    for e in fn.edges:
        if e.back:
            body = bodies.setdefault(e.dst, {e.dst})
            work = [e.src]
            while work:
                x = work.pop()
                if x not in body:
                    body.add(x)
                    work += [pe.src for pe in fn.blocks[x].pred]
    for h, body in bodies.items():
        fn.blocks[h].header = True
        for b in body:
            fn.blocks[b].depth += 1


# --------------------------------------------------------------------------- #
#  X-ray engine: operands, effects, stack frame, def-use, audit (x86-64)      #
# --------------------------------------------------------------------------- #
REGMAP: dict[str, tuple[str, int]] = {}


def _init_regs() -> None:
    legacy = {"rax": ("eax", "ax", "al", "ah"), "rbx": ("ebx", "bx", "bl", "bh"),
              "rcx": ("ecx", "cx", "cl", "ch"), "rdx": ("edx", "dx", "dl", "dh"),
              "rsi": ("esi", "si", "sil", None), "rdi": ("edi", "di", "dil", None),
              "rbp": ("ebp", "bp", "bpl", None), "rsp": ("esp", "sp", "spl", None)}
    for r, (d, w, b, h) in legacy.items():
        REGMAP[r], REGMAP[d], REGMAP[w], REGMAP[b] = (r, 64), (r, 32), (r, 16), (r, 8)
        if h:
            REGMAP[h] = (r, 8)
    for i in range(8, 16):
        r = f"r{i}"
        REGMAP[r], REGMAP[r + "d"], REGMAP[r + "w"], REGMAP[r + "b"] = (r, 64), (r, 32), (r, 16), (r, 8)
    for i in range(16):
        REGMAP[f"xmm{i}"], REGMAP[f"ymm{i}"] = (f"xmm{i}", 128), (f"xmm{i}", 256)
    REGMAP["rip"] = ("rip", 64)


_init_regs()
ARGREGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
CALLER_SAVED = ("rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11")
CALLEE_SAVED = ("rbx", "r12", "r13", "r14", "r15")
_SIZES = {"BYTE": 1, "WORD": 2, "DWORD": 4, "QWORD": 8, "TBYTE": 10, "FWORD": 6, "OWORD": 16,
          "XMMWORD": 16, "YMMWORD": 32, "ZMMWORD": 64}


def canon(tok: str) -> str:
    return REGMAP.get(tok.lower().strip(), ("", 0))[0]


@dataclass
class Op:
    kind: str                       # reg | mem | imm | other
    text: str
    reg: str = ""
    bits: int = 0
    size: int = 0
    base: str = ""
    index: str = ""
    scale: int = 1
    disp: int = 0
    seg: str = ""
    val: int = 0


_PTR = re.compile(r"^(?:(BYTE|WORD|DWORD|QWORD|TBYTE|FWORD|OWORD|XMMWORD|YMMWORD|ZMMWORD)\s+PTR\s+)?(.*)$")
_IMM = re.compile(r"^-?(?:0x[0-9a-fA-F]+|\d+)$")


def parse_op(s: str) -> Op:
    s = s.strip()
    m = _PTR.match(s)
    size, rest = _SIZES.get(m.group(1) or "", 0), m.group(2).strip()
    seg = ""
    sm = re.match(r"^([cdefgs]s):(.*)$", rest)
    if sm:
        seg, rest = sm.group(1), sm.group(2).strip()
    if rest.startswith("[") and "]" in rest:
        op = Op("mem", s, size=size, seg=seg)
        inner = rest[1:rest.rindex("]")]
        for sign, tok in re.findall(r"([+-]?)\s*([^+\-\s]+)", inner):
            tok = tok.strip()
            if "*" in tok:
                reg, _, sc = tok.partition("*")
                op.index, op.scale = canon(reg) or reg, int(sc, 0) if sc else 1
            elif canon(tok):
                if op.base:
                    op.index = canon(tok)
                else:
                    op.base = canon(tok)
            elif _IMM.match(tok):
                op.disp += (-1 if sign == "-" else 1) * int(tok, 0)
        return op
    if seg and _IMM.match(rest):
        return Op("mem", s, size=size, seg=seg, disp=int(rest, 0))
    if canon(rest):
        c, b = REGMAP[rest.lower()]
        return Op("reg", rest.lower(), reg=c, bits=b)
    if _IMM.match(rest):
        return Op("imm", rest, val=int(rest, 0))
    return Op("other", s)


_COND = {"e": "ZF", "z": "ZF", "ne": "ZF", "nz": "ZF", "a": "CF ZF", "ae": "CF", "b": "CF", "be": "CF ZF",
         "na": "CF ZF", "nae": "CF", "nb": "CF", "nbe": "CF ZF", "c": "CF", "nc": "CF", "g": "ZF SF OF",
         "ge": "SF OF", "l": "SF OF", "le": "ZF SF OF", "ng": "ZF SF OF", "nge": "SF OF", "nl": "SF OF",
         "nle": "ZF SF OF", "o": "OF", "no": "OF", "s": "SF", "ns": "SF", "p": "PF", "np": "PF", "pe": "PF", "po": "PF"}
_ARITH = {"add", "sub", "adc", "sbb", "cmp", "neg", "imul", "mul", "xadd", "cmpxchg"}
_LOGIC = {"and", "or", "xor", "test"}
_SHIFT = {"shl", "shr", "sal", "sar", "rol", "ror", "rcl", "rcr", "shld", "shrd"}
_MOVLIKE = re.compile(r"^(?:v?mov\w*|cvt\w+|vcvt\w+|lddqu|pmov\w+|movabs)$")
_READONLY = {"cmp", "test", "bt", "ucomiss", "ucomisd", "comiss", "comisd", "ptest", "vucomiss", "vucomisd"}


@dataclass
class Sem:
    mn: str
    P: list
    reads: list = field(default_factory=list)
    writes: list = field(default_factory=list)
    mem: list = field(default_factory=list)       # (mode R|W|RW|A, Op, tag)
    fr: str = ""
    fw: str = ""
    notes: list = field(default_factory=list)
    stack: str = ""                                # push | pop


def _uniq(xs):
    seen, out = set(), []
    for x in xs:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def sem_of(mn: str, ops: str) -> Sem:
    m = mn.lower()
    parts = [o for o in re.split(r",(?![^\[]*\])", ops) if o.strip()] if ops else []
    P = [parse_op(o) for o in parts]
    S = Sem(m, P)

    def addr_regs(op):
        for r in (op.base, op.index):
            if r and r != "rip":
                S.reads.append(r)

    def rd(op, tag=""):
        if op.kind == "reg":
            S.reads.append(op.text)
        elif op.kind == "mem":
            S.mem.append(("R", op, tag))
            addr_regs(op)

    def wr(op, tag=""):
        if op.kind == "reg":
            S.writes.append(op.text)
        elif op.kind == "mem":
            S.mem.append(("W", op, tag))
            addr_regs(op)

    def rw(op, tag=""):
        if op.kind == "reg":
            S.reads.append(op.text)
            S.writes.append(op.text)
        elif op.kind == "mem":
            S.mem.append(("RW", op, tag))
            addr_regs(op)

    def stk(mode, disp, tag=""):
        S.mem.append((mode, Op("mem", f"[rsp{disp:+#x}]", size=8, base="rsp", disp=disp), tag))

    if m.startswith("nop") or m in ("endbr64", "endbr32", "pause", "int3", "fnop"):
        return S
    if not P and m in ("movs", "movsb", "movsw", "movsd", "movsq", "stos", "stosb", "stosw", "stosd", "stosq"):
        P = []
    if m in ("movs", "movsb", "movsw", "movsq") or (m == "movsd" and ops and "es:" in ops):
        S.reads += ["rsi", "rdi", "rcx"]
        S.writes += ["rsi", "rdi", "rcx"]
        S.mem += [("R", Op("mem", "[rsi]", base="rsi"), "string"), ("W", Op("mem", "[rdi]", base="rdi"), "string")]
        S.notes.append("string copy: rcx units from [rsi] to [rdi]")
        return S
    if m.startswith("stos"):
        S.reads += ["rax", "rdi", "rcx"]
        S.writes += ["rdi", "rcx"]
        S.mem.append(("W", Op("mem", "[rdi]", base="rdi"), "string"))
        S.notes.append("string fill: rcx units at [rdi] = rax (memset-like)")
        return S
    if m.startswith(("cmps", "scas", "lods")):
        S.reads += ["rsi", "rdi", "rcx", "rax"]
        S.writes += ["rsi", "rdi", "rcx"]
        return S

    if m == "lea":
        wr(P[0])
        S.mem.append(("A", P[1], ""))
        addr_regs(P[1])
        o = P[1]
        if o.base and o.index and o.base == o.index and o.scale in (2, 4, 8):
            S.notes.append(f"x*{1 + o.scale} via lea (no memory access)")
        elif o.index and not o.base:
            S.notes.append(f"x*{o.scale}" + (f"+{o.disp:#x}" if o.disp else "") + " via lea")
        elif o.index:
            S.notes.append("address arithmetic: base + index*%d%+#x (no memory access)" % (o.scale, o.disp) if o.disp
                           else "address arithmetic: base + index*%d (no memory access)" % o.scale)
        return S
    if m == "push":
        rd(P[0])
        S.stack = "push"
        S.reads.append("rsp"); S.writes.append("rsp")
        stk("W", -8, "push:" + (P[0].text if P[0].kind == "reg" else ""))
        return S
    if m == "pop":
        wr(P[0])
        S.stack = "pop"
        S.reads.append("rsp"); S.writes.append("rsp")
        stk("R", 0, "pop:" + (P[0].text if P[0].kind == "reg" else ""))
        return S
    if m == "leave":
        S.reads += ["rbp"]; S.writes += ["rsp", "rbp"]
        S.notes.append("mov rsp,rbp ; pop rbp  (tears down the frame)")
        return S
    if m.startswith("call"):
        if P:
            rd(P[0])
            if P[0].kind in ("reg", "mem"):
                S.notes.append("INDIRECT call through " + ("register" if P[0].kind == "reg" else "memory"))
        S.writes += ["rax"]
        S.notes.append("caller-saved regs clobbered")
        return S
    if m.startswith("ret"):
        S.reads += ["rax", "rsp"]; S.writes += ["rsp"]
        return S
    if m == "syscall":
        S.reads += ["rax", "rdi", "rsi", "rdx", "r10", "r8", "r9"]
        S.writes += ["rax", "rcx", "r11"]
        S.notes.append("kernel entry: rax=number, args rdi rsi rdx r10 r8 r9")
        return S
    if m == "int":
        S.notes.append("software interrupt")
        return S
    if m in ("cdq", "cqo", "cdqe", "cwde", "cwd", "cbw"):
        S.reads += {"cdq": ["eax"], "cqo": ["rax"], "cdqe": ["eax"], "cwde": ["ax"]}.get(m, ["ax"])
        S.writes += {"cdq": ["edx"], "cqo": ["rdx"], "cdqe": ["rax"], "cwde": ["eax"]}.get(m, ["ax"])
        S.notes.append("sign-extension")
        return S
    if m == "cpuid":
        S.reads += ["eax", "ecx"]; S.writes += ["eax", "ebx", "ecx", "edx"]
        return S
    if m in ("rdtsc", "rdtscp"):
        S.writes += ["rax", "rdx"]
        return S
    if m in ("mul", "div", "idiv") or (m == "imul" and len(P) == 1):
        rd(P[0])
        S.reads += ["rax"] + (["rdx"] if m != "mul" and m != "imul" else [])
        S.writes += ["rax", "rdx"]
        S.fw = "OF CF" if m in ("mul", "imul") else "(undefined)"
        if m in ("div", "idiv"):
            S.notes.append("divide rdx:rax by operand — #DE if zero")
        return S
    if m == "imul" and len(P) == 3:
        wr(P[0]); rd(P[1]); S.fw = "OF SF ZF AF PF CF"
        return S
    if m.startswith("cmov"):
        S.fr = _COND.get(m[4:], "")
        rw(P[0]); rd(P[1])
        return S
    if m.startswith("set") and m[3:] in _COND:
        S.fr = _COND[m[3:]]
        wr(P[0])
        return S
    if m.startswith("j") and m != "jmp" and m[1:] in _COND:
        S.fr = _COND[m[1:]]
        return S
    if m in ("jmp", "jmpq"):
        if P and P[0].kind in ("reg", "mem"):
            rd(P[0])
            S.notes.append("INDIRECT jump (jump table / computed goto)")
        return S

    if m in ("xchg", "xadd", "cmpxchg"):
        for o in P:
            rw(o)
        if m == "cmpxchg":
            S.reads.append("rax")
    elif m in _READONLY or m.startswith(("bt",)) and m == "bt":
        for o in P:
            rd(o)
    elif m in ("xor", "sub", "pxor", "vpxor", "xorps", "xorpd") and len(P) == 2 and P[0].kind == "reg" \
            and P[1].kind == "reg" and P[0].reg == P[1].reg:
        S.writes.append(P[0].text)
        S.notes.append("zeroing idiom")
    elif _MOVLIKE.match(m) and P:
        wr(P[0])
        for o in P[1:]:
            rd(o)
    elif m.startswith("v") and len(P) >= 3:
        wr(P[0])
        for o in P[1:]:
            rd(o)
    elif P:
        rw(P[0])
        for o in P[1:]:
            rd(o)
    if m in _ARITH:
        S.fw = "OF SF ZF AF PF CF"
    elif m in ("inc", "dec"):
        S.fw = "OF SF ZF AF PF"
    elif m in _LOGIC:
        S.fw = "SF ZF PF (CF=OF=0)"
    elif m in _SHIFT:
        S.fw = "CF ZF SF PF"
    elif m in ("adc", "sbb"):
        S.fr = "CF"
    elif m.startswith(("ucomis", "comis", "vucomis")):
        S.fw = "ZF PF CF"
    elif m == "bt":
        S.fw = "CF"
    if m in ("adc", "sbb", "rcl", "rcr"):
        S.fr = "CF"
    if m == "test" and len(P) == 2 and P[0].kind == "reg" and P[1].kind == "reg" and P[0].reg == P[1].reg:
        S.notes.append("zero/sign test of one register")
    if m == "movsxd" or m.startswith("movsx"):
        S.notes.append("sign-extending load")
    S.reads, S.writes = _uniq(S.reads), _uniq(S.writes)
    return S


# ------------------------------- stack frame ------------------------------- #
def step_state(s, S: Sem):
    """Track rsp / rbp as offsets from the CFA (value of rsp before the call pushed the return address)."""
    rsp, rbp = s
    m, P = S.mn, S.P
    dst = P[0] if P else None
    drsp = dst is not None and dst.kind == "reg" and dst.reg == "rsp"
    drbp = dst is not None and dst.kind == "reg" and dst.reg == "rbp"
    if m == "push":
        rsp = None if rsp is None else rsp - 8
    elif m == "pop":
        rsp = None if rsp is None else rsp + 8
        if drbp:
            rbp = None
    elif m in ("sub", "add") and drsp:
        if len(P) > 1 and P[1].kind == "imm" and rsp is not None:
            rsp += -P[1].val if m == "sub" else P[1].val
        else:
            rsp = None
    elif m == "mov" and drsp:
        rsp = rbp if P[1].kind == "reg" and P[1].reg == "rbp" else None
    elif m == "mov" and drbp:
        rbp = rsp if P[1].kind == "reg" and P[1].reg == "rsp" else None
    elif m == "leave":
        rsp, rbp = (None if rbp is None else rbp + 8), None
    elif m == "lea" and drsp:
        o = P[1]
        b = rbp if o.base == "rbp" else rsp if o.base == "rsp" else None
        rsp = None if b is None or o.index else b + o.disp
    elif drsp:
        rsp = None
    return (rsp, rbp)


def mem_class(op: Op, s, comment: str):
    rsp, rbp = s
    if op.seg in ("fs", "gs"):
        return ("tls", op.disp, op.seg)
    if op.base in ("rsp", "rbp"):
        b = rsp if op.base == "rsp" else rbp
        if b is None:
            return ("stack?", None, bool(op.index))
        return ("stack", b + op.disp, bool(op.index))
    if op.base == "rip":
        m = re.search(r"#\s*([0-9a-f]+)(?:\s*<([^>]+)>)?", comment or "")
        return ("global", int(m.group(1), 16) if m else None, (m.group(2) or "") if m else "")
    if not op.base and not op.index:
        return ("abs", op.disp, "")
    return ("ptr", op.base, op.index)


@dataclass
class Slot:
    off: int
    r: int = 0
    w: int = 0
    size: int = 0
    first: str = ""
    first_idx: int = -1
    addr_taken: bool = False
    addr_idx: int = -1
    indexed: bool = False
    tags: list = field(default_factory=list)
    spill: str = ""


@dataclass
class Finding:
    sev: str
    title: str
    idx: int
    detail: str = ""
    fix: str = ""
    conf: str = "likely"


SEV_ORDER = {"CRIT": 0, "HIGH": 1, "MED": 2, "LOW": 3, "INFO": 4}
SEV_ROLE = {"CRIT": "danger", "HIGH": "err", "MED": "warn", "LOW": "label", "INFO": "dim"}

# name: (severity, title, why, fix, dst-arg index, length-arg index)
DANGER = {
    "gets": ("CRIT", "gets(): unbounded read", "input of any length is copied into the buffer; it can never be made safe",
             "fgets(buf, sizeof buf, stdin)", 0, None),
    "strcpy": ("HIGH", "strcpy(): no destination bound", "copies until NUL regardless of destination size",
               "snprintf / strlcpy / memcpy with a checked length", 0, None),
    "stpcpy": ("HIGH", "stpcpy(): no destination bound", "copies until NUL regardless of destination size", "stpncpy + explicit NUL", 0, None),
    "strcat": ("HIGH", "strcat(): no destination bound", "appends until NUL; caller must prove room", "strncat / snprintf", 0, None),
    "sprintf": ("HIGH", "sprintf(): no destination bound", "formatted output can exceed the buffer", "snprintf(buf, sizeof buf, ...)", 0, None),
    "vsprintf": ("HIGH", "vsprintf(): no destination bound", "formatted output can exceed the buffer", "vsnprintf", 0, None),
    "wcscpy": ("HIGH", "wcscpy(): no destination bound", "copies until NUL", "wcsncpy", 0, None),
    "getwd": ("HIGH", "getwd(): no buffer size", "writes an unbounded path", "getcwd(buf, size)", 0, None),
    "scanf": ("MED", "scanf-family: check %s widths", "an unbounded %s writes past the buffer", "use %Ns with N < sizeof buf", None, None),
    "sscanf": ("MED", "scanf-family: check %s widths", "an unbounded %s writes past the buffer", "use %Ns with N < sizeof buf", None, None),
    "fscanf": ("MED", "scanf-family: check %s widths", "an unbounded %s writes past the buffer", "use %Ns with N < sizeof buf", None, None),
    "system": ("HIGH", "system(): shell execution", "command injection if any part of the string is attacker-influenced",
               "execve with an argv array; never build shell strings", None, None),
    "popen": ("HIGH", "popen(): shell execution", "command injection if any part is attacker-influenced", "fork/execve with pipes", None, None),
    "mktemp": ("MED", "mktemp(): race condition", "name is guessable between check and use", "mkstemp", None, None),
    "tmpnam": ("MED", "tmpnam(): race condition", "name is guessable between check and use", "mkstemp", None, None),
    "tempnam": ("MED", "tempnam(): race condition", "name is guessable between check and use", "mkstemp", None, None),
    "strtok": ("LOW", "strtok(): hidden static state", "not thread-safe, mutates its input", "strtok_r", None, None),
    "rand": ("LOW", "rand(): not cryptographically secure", "predictable output", "getrandom() / arc4random()", None, None),
    "atoi": ("LOW", "atoi(): no error reporting", "overflow and garbage input are silent", "strtol with end-pointer check", None, None),
    "atol": ("LOW", "atol(): no error reporting", "overflow and garbage input are silent", "strtol with end-pointer check", None, None),
    "access": ("LOW", "access(): TOCTOU race", "file can change between check and use", "open then fstat", None, None),
    "alloca": ("MED", "alloca(): attacker-sized stack allocation", "huge sizes jump the guard page", "malloc", None, None),
    "memcpy": ("INFO", "memcpy(): verify length", "length must be <= destination size", "", 0, 2),
    "memmove": ("INFO", "memmove(): verify length", "length must be <= destination size", "", 0, 2),
    "strncpy": ("LOW", "strncpy(): may not NUL-terminate", "truncation leaves no terminator", "strlcpy / snprintf", 0, 2),
    "strncat": ("LOW", "strncat(): length is remaining room, not buffer size", "classic off-by-one", "snprintf", 0, 2),
    "read": ("INFO", "read(): verify length", "length must be <= destination size", "", 1, 2),
    "recv": ("INFO", "recv(): verify length", "length must be <= destination size", "", 1, 2),
    "fgets": ("INFO", "fgets(): verify length", "length must be <= destination size", "", 0, 1),
    "snprintf": ("INFO", "snprintf(): verify length", "length must be <= destination size", "", 0, 1),
}
FMT_ARG = {"printf": 0, "fprintf": 1, "sprintf": 1, "snprintf": 2, "dprintf": 1, "syslog": 1, "vprintf": 0,
           "vfprintf": 1, "vsprintf": 1, "vsnprintf": 2, "err": 1, "warn": 0}
PROTOS = {
    "gets": ("s",), "puts": ("s",), "putchar": ("c",), "printf": ("fmt",), "fprintf": ("stream", "fmt"),
    "sprintf": ("dst", "fmt"), "snprintf": ("dst", "n", "fmt"), "strcpy": ("dst", "src"), "strncpy": ("dst", "src", "n"),
    "strcat": ("dst", "src"), "strncat": ("dst", "src", "n"), "strlen": ("s",), "strcmp": ("a", "b"),
    "strncmp": ("a", "b", "n"), "memcpy": ("dst", "src", "n"), "memmove": ("dst", "src", "n"),
    "memset": ("dst", "c", "n"), "memcmp": ("a", "b", "n"), "read": ("fd", "buf", "n"), "write": ("fd", "buf", "n"),
    "recv": ("fd", "buf", "n", "flags"), "send": ("fd", "buf", "n", "flags"), "fgets": ("buf", "n", "stream"),
    "fread": ("ptr", "size", "nmemb", "stream"), "fwrite": ("ptr", "size", "nmemb", "stream"),
    "scanf": ("fmt",), "sscanf": ("str", "fmt"), "fscanf": ("stream", "fmt"), "malloc": ("size",),
    "calloc": ("n", "size"), "realloc": ("ptr", "size"), "free": ("ptr",), "system": ("cmd",),
    "popen": ("cmd", "mode"), "atoi": ("s",), "open": ("path", "flags", "mode"), "fopen": ("path", "mode"),
    "exit": ("code",), "strdup": ("s",), "getenv": ("name",), "execve": ("path", "argv", "envp"),
    "close": ("fd",), "strchr": ("s", "c"), "strstr": ("hay", "needle"), "socket": ("domain", "type", "proto"),
    "connect": ("fd", "addr", "len"), "bind": ("fd", "addr", "len"), "accept": ("fd", "addr", "len"),
}
SYSCALLS = {0: "read", 1: "write", 2: "open", 3: "close", 9: "mmap", 10: "mprotect", 11: "munmap", 12: "brk",
            39: "getpid", 41: "socket", 42: "connect", 43: "accept", 44: "sendto", 45: "recvfrom", 49: "bind",
            50: "listen", 56: "clone", 57: "fork", 59: "execve", 60: "exit", 62: "kill", 101: "ptrace",
            231: "exit_group", 257: "openat"}


def libc_base(name: str) -> str:
    n = re.sub(r"^__isoc(?:99|23)_", "", name)
    n = re.sub(r"^__", "", n)
    return re.sub(r"_chk$", "", n)


@dataclass
class XRay:
    fn: Func
    sems: list
    pre: list
    slots: dict
    rbp_base: int | None
    findings: list = field(default_factory=list)
    calls: list = field(default_factory=list)       # (idx, name, [(argname, desc)])
    syscalls: list = field(default_factory=list)
    canary: bool = False
    min_rsp: int = -8
    mem_txt: dict = field(default_factory=dict)     # idx -> [str]
    notes: dict = field(default_factory=dict)       # idx -> [str]
    callee_saved: list = field(default_factory=list)

    def name(self, off: int) -> str:
        if off == -8:
            return "ret_addr"
        if off >= 0:
            return f"stack_arg_{off:X}"
        if self.rbp_base is not None:
            if off == self.rbp_base:
                return "saved_rbp"
            d = off - self.rbp_base
            return f"var_{-d:X}" if d < 0 else f"saved_rbp+{d:X}"
        return f"local_{-off:X}"

    def offsets(self) -> list:
        base = {o for o in self.slots if o < 0}
        base.add(-8)
        if self.rbp_base is not None:
            base.add(self.rbp_base)
        return sorted(base)

    def extent(self, off: int) -> int:
        higher = [o for o in self.offsets() if o > off]
        return max((min(higher) if higher else -8) - off, 1)

    def by_idx(self, i: int) -> list:
        return [f for f in self.findings if f.idx == i]


def _desc(xr: XRay, d) -> str:
    if d is None:
        return "?"
    k = d[0]
    if k == "imm":
        return hex(d[1]) if abs(d[1]) > 9 else str(d[1])
    if k == "rodata":
        return f'&rodata@0x{d[1]:x}' if d[1] is not None else "&global"
    if k == "stackaddr":
        return "&" + xr.name(d[1])
    if k == "slot":
        return xr.name(d[1])
    if k == "global":
        return d[1] or "global"
    if k == "ret":
        return f"ret({d[1]})"
    if k == "arg":
        return f"arg{d[1]}"
    if k in ("ptr", "load") and len(d) > 1:
        t = re.sub(r"^\w+ PTR ", "", d[1])
        return ("*" if k == "load" else "&") + t
    if k == "arith":
        return f"calc({d[1]})"
    return d[1] if len(d) > 1 and isinstance(d[1], str) else k


def xray_analyze(fn: Func) -> XRay:
    ins, n = fn.ins, len(fn.ins)
    norm = [norm_ins(it) for it in ins]
    sems = [sem_of(mn, ops) for mn, ops in norm]
    nb = len(fn.blocks)
    st_in = [None] * nb
    st_in[0] = (-8, None)
    queue = [0]
    while queue:
        b = queue.pop(0)
        s = st_in[b]
        for i in fn.blocks[b].idx:
            s = step_state(s, sems[i])
        for e in fn.blocks[b].succ:
            if st_in[e.dst] is None:
                st_in[e.dst] = s
                queue.append(e.dst)
    pre: list = [None] * n
    for b in fn.blocks:
        s = st_in[b.id] or (None, None)
        for i in b.idx:
            pre[i] = s
            s = step_state(s, sems[i])
    rbp_base = next((p[1] for p in pre if p and p[1] is not None), None)
    xr = XRay(fn, sems, pre, {}, rbp_base)
    xr.min_rsp = min([p[0] for p in pre if p and p[0] is not None] or [-8])

    def slot(off):
        return xr.slots.setdefault(off, Slot(off))

    # ---- pass A: memory traffic -> slots, annotations
    pushes = set()
    for i, S in enumerate(sems):
        it, s = ins[i], pre[i]
        txt = []
        for mode, op, tag in S.mem:
            kind, a, b = mem_class(op, s, it.comment)
            size = op.size or (S.P[0].bits // 8 if S.P and S.P[0].kind == "reg" else 0)
            if kind == "stack" and mode != "A" or kind == "stack" and mode == "A":
                sl = slot(a)
                if mode == "A":
                    if not sl.addr_taken:
                        sl.addr_taken, sl.addr_idx = True, i
                else:
                    if "R" in mode:
                        sl.r += 1
                    if "W" in mode:
                        sl.w += 1
                    sl.first = sl.first or ("R" if mode == "R" else "W")
                    if sl.first_idx < 0:
                        sl.first_idx = i
                    sl.size = max(sl.size, size)
                if b:
                    sl.indexed = True
                if tag.startswith("push:"):
                    sl.tags.append("saved " + tag[5:])
                    pushes.add(canon(tag[5:]))
                if mode == "W" and S.P and len(S.P) > 1 and S.P[1].kind == "reg" and S.P[1].reg in ARGREGS \
                        and not sl.spill and sl.first_idx == i:
                    sl.spill = S.P[1].text
                nm = xr.name(a) + ("[idx]" if b else "")
                txt.append(f"{mode}{size or ''} {nm}" if mode != "A" else f"addr {nm}")
            elif kind == "tls":
                txt.append(f"{mode}{size or ''} {a and 'fs:' + hex(a) or 'fs:0'}" + (" (stack canary)" if a == 0x28 else ""))
                if a == 0x28:
                    xr.canary = True
                    xr.notes.setdefault(i, []).append("stack-protector canary load")
            elif kind == "global":
                nm = f"<{b}>" if b else (f"@0x{a:x}" if a is not None else "[rip+…]")
                txt.append(f"addr {nm}" if mode == "A" else f"{mode}{size or ''} {nm}")
            elif kind == "ptr" and mode != "A":
                txt.append(f"{mode}{size or ''} *{op.text.split('PTR')[-1].strip()}")
            elif kind == "stack?":
                txt.append(f"{mode}{size or ''} {op.text}")
        xr.mem_txt[i] = txt
        for note in S.notes:
            xr.notes.setdefault(i, []).append(note)
        for w in S.writes:
            c = canon(w)
            if c in CALLEE_SAVED and c not in xr.callee_saved:
                xr.callee_saved.append(c)
    ret_slot = slot(-8)
    ret_slot.tags.append("return address")
    if rbp_base is not None and "saved rbp" not in slot(rbp_base).tags:
        slot(rbp_base).tags.append("saved rbp")
    # canary slot = stack slot written right after an fs:0x28 load
    for i, S in enumerate(sems):
        if any(op.seg == "fs" and op.disp == 0x28 for _, op, _t in S.mem) and S.writes:
            reg = canon(S.writes[0])
            for j in range(i + 1, min(i + 4, n)):
                for mode, op, _t in sems[j].mem:
                    if mode == "W" and sems[j].P and len(sems[j].P) > 1 and sems[j].P[1].kind == "reg" \
                            and sems[j].P[1].reg == reg:
                        kind, a, _b = mem_class(op, pre[j], ins[j].comment)
                        if kind == "stack":
                            slot(a).tags.append("canary")
                            break

    # ---- pass B: def-use, calls, audit
    findings = xr.findings

    def add(sev, title, i, detail="", fix="", conf="likely"):
        findings.append(Finding(sev, title, i, detail, fix, conf))

    freed: dict = {}
    reported_uninit: set = set()
    for b in fn.blocks:
        defs: dict = {}
        if b.id == 0:
            defs = {r: ("arg", k) for k, r in enumerate(ARGREGS)}
        for pos, i in enumerate(b.idx):
            mn, ops = norm[i]
            S, s, it = sems[i], pre[i], ins[i]
            m, P = S.mn, S.P

            # writes over return address / saved rbp
            for mode, op, tag in S.mem:
                kind, a, _x = mem_class(op, s, it.comment)
                if kind == "stack" and "W" in mode and not tag.startswith("push:"):
                    if a == -8 or (rbp_base is not None and a == rbp_base and S.stack != "push"):
                        add("CRIT", "write over " + ("return address" if a == -8 else "saved rbp"), i,
                            f"explicit store to {xr.name(a)}: control-flow hijack primitive", conf="certain")
                if kind == "stack" and a is not None and a < -8:
                    sl = xr.slots.get(a)
                    if sl and mode == "R" and sl.first == "R" and sl.first_idx == i and not sl.addr_taken \
                            and not tag.startswith("pop:") and a not in reported_uninit \
                            and (rbp_base is None or a < rbp_base):
                        reported_uninit.add(a)
                        add("MED", f"{xr.name(a)} read before any write", i,
                            "uninitialised stack variable (or written only through a pointer)", conf="heuristic")
                if kind == "stack" and a in freed and mode == "W":
                    freed.pop(a, None)
                elif kind == "stack" and a in freed and "R" in mode and i > freed[a][0]:
                    add("MED", f"use of {xr.name(a)} after free()", i,
                        f"pointer was freed at 0x{ins[freed[a][0]].addr}", "set the pointer to NULL after free", "heuristic")
                    freed.pop(a, None)

            if m == "div" or m == "idiv":
                recent = [norm[j][0].lower() for j in range(max(0, i - 8), i)]
                if not any(x in ("test", "cmp") for x in recent) and P and P[0].kind != "imm":
                    add("LOW", "division without a visible zero check", i,
                        "no cmp/test in the preceding 8 instructions: possible #DE crash", conf="heuristic")
            if S.notes and any("INDIRECT" in x for x in S.notes):
                add("LOW" if m.startswith("call") else "INFO", "indirect " + ("call" if m.startswith("call") else "jump"), i,
                    "target comes from data (function pointer / vtable / jump table): integrity of that data decides control flow",
                    conf="certain")
            if m == "syscall":
                d = defs.get("rax")
                num = d[1] if d and d[0] == "imm" else None
                nm = SYSCALLS.get(num, f"#{num}" if num is not None else "?")
                xr.syscalls.append((i, nm, num))
                xr.notes.setdefault(i, []).append(f"syscall {nm}")
                if nm == "execve":
                    add("HIGH", "raw execve syscall", i, "spawns a new program image", conf="certain")
                elif nm == "mprotect":
                    add("MED", "mprotect syscall", i, "check whether PROT_EXEC is requested", conf="heuristic")
                elif nm == "ptrace":
                    add("INFO", "ptrace syscall", i, "debugger detection or process control", conf="certain")
            if m == "int" and P and P[0].kind == "imm" and P[0].val == 0x80:
                add("INFO", "int 0x80 legacy syscall", i, "32-bit syscall ABI from 64-bit code is unusual", conf="certain")
            if m == "rep" or (it.mnem.lower() in _PREFIX and it.mnem.lower().startswith("rep") and m.startswith(("movs", "stos"))):
                if "rcx" not in defs or defs["rcx"][0] != "imm":
                    add("LOW", "rep string op with variable count", i,
                        "length comes from rcx; confirm it is bounded by the destination size", conf="heuristic")

            if m.startswith("call"):
                name = call_name(ops or "")
                base = libc_base(name)
                proto = PROTOS.get(base) or PROTOS.get(name, ())
                args = []
                for k, r in enumerate(ARGREGS[:len(proto) if proto else 3]):
                    if r in defs:
                        args.append((proto[k] if k < len(proto) else f"a{k}", _desc(xr, defs[r])))
                    elif proto:
                        args.append((proto[k], "?"))
                xr.calls.append((i, name, args))
                dsp = DANGER.get(base)
                getarg = lambda k: defs.get(ARGREGS[k]) if k is not None and k < 6 else None
                if dsp:
                    sev, title, why, fix, dst, ln = dsp
                    d_dst, d_len = getarg(dst), getarg(ln)
                    detail = why
                    if d_dst and d_dst[0] == "stackaddr":
                        off = d_dst[1]
                        room, to_ret = xr.extent(off), -8 - off
                        detail += f"; target {xr.name(off)} is ~{room} B, {to_ret} B below ret_addr"
                        if ln is not None:
                            if d_len and d_len[0] == "imm":
                                if d_len[1] > room:
                                    sev = "CRIT"
                                    title = f"{base}(): {d_len[1]} B into ~{room} B buffer"
                                    detail += f"; length {d_len[1]} exceeds estimated size {room}"
                                else:
                                    sev, detail = "INFO", detail + f"; constant length {d_len[1]} fits"
                            elif sev == "INFO":
                                sev = "MED"
                                title = f"{base}(): variable length into stack buffer"
                                detail += "; length is not a compile-time constant"
                        elif sev in ("HIGH", "CRIT"):
                            detail += " (overflow reaches the return address)"
                    if name.endswith("_chk") and sev != "INFO":
                        sev, title = "INFO", title.split(":")[0] + " (fortified _chk variant)"
                        detail = "compiler-checked: aborts on overflow instead of corrupting memory"
                    add(sev, title, i, detail, fix, "likely" if d_dst else "heuristic")
                fa = FMT_ARG.get(base)
                if fa is not None:
                    d = getarg(fa)
                    if d and d[0] in ("stackaddr", "slot", "ptr", "load", "arith", "ret", "arg") and not (d[0] == "arg" and False):
                        add("HIGH", f"{base}(): non-constant format string", i,
                            f"format argument is {_desc(xr, d)}, not a literal: attacker %n/%s = read/write primitive",
                            f'{base}("%s", ...)', "likely")
                if base in ("malloc", "calloc", "realloc"):
                    d = getarg(0 if base != "realloc" else 1)
                    if d and d[0] == "arith" and d[1] in ("imul", "mul", "shl", "add"):
                        add("MED", f"{base}(): size computed by {d[1]}", i,
                            "arithmetic on the size may wrap around: undersized allocation then heap overflow",
                            "use calloc(n, size) or a checked multiply", "heuristic")
                if base == "free":
                    d = getarg(0)
                    if d and d[0] == "slot":
                        if d[1] in freed:
                            add("HIGH", f"double free of {xr.name(d[1])}", i,
                                f"already freed at 0x{ins[freed[d[1]][0]].addr}", "NULL the pointer after free", "likely")
                        freed[d[1]] = (i,)
                for r in CALLER_SAVED:
                    defs.pop(r, None)
                defs["rax"] = ("ret", base or name)
                continue

            # ---- def tracking
            dst = P[0] if P else None
            if dst is not None and dst.kind == "reg":
                c = dst.reg
                if "zeroing idiom" in S.notes:
                    defs[c] = ("imm", 0)
                elif m in ("mov", "movabs", "movzx", "movsx", "movsxd") and len(P) == 2:
                    src = P[1]
                    if src.kind == "imm":
                        defs[c] = ("imm", src.val)
                    elif src.kind == "reg":
                        if src.reg in defs:
                            defs[c] = defs[src.reg]
                        else:
                            defs.pop(c, None)
                    elif src.kind == "mem":
                        kind, a, bb = mem_class(src, s, it.comment)
                        defs[c] = ("slot", a) if kind == "stack" and not bb else ("global", bb) if kind == "global" else ("load", src.text)
                    else:
                        defs.pop(c, None)
                elif m == "lea":
                    kind, a, bb = mem_class(P[1], s, it.comment)
                    if kind == "stack":
                        defs[c] = ("stackaddr", a)
                    elif kind == "global":
                        defs[c] = ("rodata", a, bb)
                    else:
                        defs[c] = ("ptr", P[1].text)
                elif m in ("add", "sub", "imul", "mul", "shl", "sal", "or", "and", "xor", "inc", "dec"):
                    defs[c] = ("arith", m)
                elif S.writes:
                    defs.pop(c, None)
                for w in S.writes[1:]:
                    defs.pop(canon(w), None)
            elif m not in ("cdqe", "cwde", "cdq", "cqo"):
                for w in S.writes:
                    defs.pop(canon(w), None)

    # ---- function-level findings
    bufs = [sl for sl in xr.slots.values() if sl.off < -8 and (sl.addr_taken or sl.indexed)
            and not any(t in ("canary", "saved rbp") or t.startswith("saved") for t in sl.tags)]
    if bufs and not xr.canary:
        names = ", ".join(xr.name(sl.off) for sl in bufs[:4])
        add("MED", "no stack protector", 0,
            f"address-taken locals ({names}) can be overflowed up to ret_addr with nothing checking it",
            "build with -fstack-protector-strong", "likely")
    elif xr.canary:
        add("INFO", "stack canary present", 0, "fs:0x28 is checked before return", conf="certain")
    for r in xr.callee_saved:
        if r not in pushes and not any(S.mn == "mov" and S.P and S.P[0].kind == "mem" and len(S.P) > 1
                                       and S.P[1].kind == "reg" and S.P[1].reg == r for S in sems):
            add("LOW", f"callee-saved {r} modified without being saved", 0,
                "caller's value is lost (ABI violation) unless this is a non-C entry point", conf="heuristic")
    findings.sort(key=lambda f: (SEV_ORDER[f.sev], f.idx))
    return xr


def effect_segments(xr: XRay, i: int) -> list:
    """[(text, role)] describing everything instruction i does."""
    S, segs = xr.sems[i], []
    if S.reads:
        segs.append(("R ", "dim")); segs.append((" ".join(S.reads), "math"))
    if S.writes:
        if segs:
            segs.append(("  ", "dim"))
        segs.append(("W ", "dim")); segs.append((" ".join(S.writes), "pink"))
    for t in xr.mem_txt.get(i, []):
        if segs:
            segs.append((" │ ", "dim"))
        segs.append(("MEM ", "dim")); segs.append((t, "cyan"))
    if S.fw:
        segs.append((" │ ", "dim")); segs.append(("flags ", "dim")); segs.append((S.fw, "warn"))
    if S.fr:
        segs.append((" │ ", "dim")); segs.append(("reads ", "dim")); segs.append((S.fr, "warn"))
    pre = xr.pre[i]
    if pre and pre[0] is not None and S.mn in ("push", "pop", "sub", "add", "call", "leave") \
            and (S.stack or (S.P and S.P[0].kind == "reg" and S.P[0].reg == "rsp") or S.mn == "leave"):
        after = step_state(pre, S)[0]
        if after is not None:
            segs.append((" │ ", "dim")); segs.append(("rsp ", "dim")); segs.append((f"cfa{after:+#x}", "stack"))
    for note in xr.notes.get(i, []):
        segs.append((" │ ", "dim")); segs.append(("⟡ " + note, "src"))
    return segs


# --------------------------------------------------------------------------- #
#  X-ray rendering                                                            #
# --------------------------------------------------------------------------- #
def jump_gutter(fn: Func, p: Painter, max_cols: int = 6):
    spans = []
    for blk in fn.blocks:
        last = blk.idx[-1]
        for e in blk.succ:
            if e.kind in ("jump", "taken"):
                t = fn.blocks[e.dst].idx[0]
                spans.append((last, t, t <= last))
    spans.sort(key=lambda s: abs(s[0] - s[1]))
    cols: list[list] = []
    placed = []
    for s in spans:
        lo, hi = min(s[0], s[1]), max(s[0], s[1])
        for k, c in enumerate(cols):
            if all(hi < a or lo > b for a, b in c):
                c.append((lo, hi))
                placed.append((s, k))
                break
        else:
            cols.append([(lo, hi)])
            placed.append((s, len(cols) - 1))
    ncol = min(len(cols), max_cols)
    rows = []
    for i in range(len(fn.ins)):
        cells, end, targ = {}, " ", False
        for (src, dst, back), k in placed:
            if k >= ncol:
                continue
            lo, hi, col = min(src, dst), max(src, dst), ncol - 1 - k
            role = "stack" if back else "flow"
            if i in (src, dst):
                corner = "╭" if i == lo else "╰"
                for c in range(col, ncol):
                    ch = corner if c == col else "─"
                    old = cells.get(c)
                    cells[c] = ("┼" if old and old[0] == "│" and ch == "─" else ch, role)
                if i == dst:
                    targ = True
                end = "►" if targ else "─"
            elif lo < i < hi and col not in cells:
                cells[col] = ("│", role)
        row = "".join(p(*cells[c]) if c in cells else " " for c in range(ncol))
        rows.append(row + (p(end, "accent", True) if end != " " else " "))
    return rows, ncol + 1


def _eff_line(xr: XRay, i: int, p: Painter) -> str:
    return "".join(p(t, r) for t, r in effect_segments(xr, i))


def xray_function(fn: Func, xr: XRay, p: Painter, src_lines: list[str], show_src: bool) -> list[str]:
    rail = p("║ ", "pink")
    out: list[str] = []
    ins = fn.ins
    nsz = sum((len(i.raw) + 1) // 3 for i in ins)
    loops = sum(1 for b in fn.blocks if b.header)
    counts = {s: sum(1 for f in xr.findings if f.sev == s) for s in SEV_ORDER}
    calls = {}
    for _, nm, _a in xr.calls:
        calls[nm] = calls.get(nm, 0) + 1
    head = (f"ƒ {fn.dname}  @ 0x{fn.addr}   {nsz} B · {len(ins)} ins · {len(fn.blocks)} blocks · {loops} loops")
    out.append(rail + p(head, "accent", True))
    frame = (f"stack: {-xr.min_rsp} B deep · {'rbp frame' if xr.rbp_base is not None else 'frameless (rsp-based)'} · "
             f"canary {'✔' if xr.canary else '✘'}" + (f" · clobbers {' '.join(xr.callee_saved)}" if xr.callee_saved else ""))
    out.append(rail + p(frame, "label"))
    out.append(rail + p("calls: ", "dim") + p(" ".join(f"{k}×{v}" if v > 1 else k for k, v in calls.items()) or "none", "sym")
               + p("   syscalls: ", "dim") + p(" ".join(s[1] for s in xr.syscalls) or "none", "flow"))
    out.append(rail + p("audit: ", "dim") + "  ".join(
        p(f"{counts[s]} {s}", SEV_ROLE[s] if counts[s] else "dim", bool(counts[s]) and s in ("CRIT", "HIGH"))
        for s in SEV_ORDER if s != "INFO") + p(f"  ({counts['INFO']} info)", "dim"))

    # ---------------- frame map
    out += [rail, rail + p("┌─ STACK FRAME  ", "pink") + p("(offsets from CFA = rsp before the call pushed the return address)", "dim")]
    offs = sorted(xr.slots, reverse=True)
    printed_cfa = False
    for off in offs:
        if off < 0 and not printed_cfa:
            out.append(rail + p("│ ", "pink") + p("cfa+0x0  ", "dim") + p("──────── CFA ────────", "dim"))
            printed_cfa = True
        sl = xr.slots[off]
        buf = off < -8 and (sl.addr_taken or sl.indexed) and not any(t == "canary" or t.startswith("saved") for t in sl.tags)
        size = xr.extent(off) if buf else (sl.size or 8)
        tags = list(sl.tags) + (["BUFFER"] if buf else []) + ([f"← {sl.spill}"] if sl.spill else [])
        role = "danger" if buf else "stack" if off in (-8,) or sl.tags else "label"
        out.append(rail + p("│ ", "pink") + p(f"cfa{off:+#x}".ljust(9), "dim") + p("├─ ", "pink")
                   + p(xr.name(off).ljust(16), role, buf) + p(f"{'~' if buf else ''}{size} B".ljust(7), "imm")
                   + p((f"R{sl.r} W{sl.w}" if (sl.r or sl.w) else "via ptr" if (sl.addr_taken or sl.indexed) else "").ljust(8), "dim") + p(", ".join(tags), "src"))
        if buf:
            out.append(rail + p("│ ", "pink") + " " * 9 + p("│  ▲ ", "pink")
                       + p(f"writes run upward: {-8 - off} B from the start of this buffer to ret_addr", "warn"))
    if not printed_cfa:
        out.append(rail + p("│ ", "pink") + p("cfa+0x0  ──────── CFA ────────", "dim"))
    out.append(rail + p("└─ ", "pink") + p(f"lowest rsp: cfa{xr.min_rsp:+#x}   ▼ lower addresses", "dim"))

    # ---------------- disassembly
    gut, gw = jump_gutter(fn, p)
    aw = max(len(i.addr) for i in ins)
    bw = min(23, max(len(i.raw) for i in ins))
    out += [rail, rail + p("┌─ DEEP DISASSEMBLY  ", "pink")
            + p("R=reads W=writes MEM=memory access, stack offsets named, ► jump targets, ⟡ idioms", "dim")]
    leaders = {b.idx[0]: b for b in fn.blocks}
    last_src = None
    pad = " " * (gw + 1 + aw + 2 + bw + 2)
    for i, it in enumerate(ins):
        if i in leaders:
            b = leaders[i]
            tags = []
            if b.header:
                tags.append(f"loop header ↻ depth {b.depth}")
            elif b.depth:
                tags.append(f"in loop depth {b.depth}")
            if b.pred:
                tags.append("from " + ",".join(f"B{e.src}{'↺' if e.back else ''}" for e in b.pred))
            if b.exit:
                tags.append("exit")
            out.append(rail + p("├┈┈ ", "pink") + p(f"B{b.id}", "accent", True) + p(" " + " · ".join(tags) + " ┈┈┈", "dim"))
            last_src = None
        if show_src and it.src and it.src != last_src and 0 < it.src <= len(src_lines):
            out.append(rail + " " * gw + p(" ▍", "accent") + p(f"{it.src:>4} │ ", "srcnum") + p(src_lines[it.src - 1].strip(), "src"))
            last_src = it.src
        mn, ops = norm_ins(it)
        cat = classify(it.mnem, "x86")
        raw = it.raw if len(it.raw) <= bw else it.raw[:bw - 1] + "…"
        line = (f"{rail}{gut[i]} {p(it.addr.rjust(aw), 'label')}  {p(raw.ljust(bw), 'bytes')}  "
                f"{p(it.mnem, cat, cat in ('flow', 'danger'))}{' ' * max(1, 7 - len(it.mnem))}{highlight_ops(it.ops_d or it.ops, p)}")
        if it.comment:
            line += "  " + p(it.comment, "comment")
        out.append(line.rstrip())
        eff = _eff_line(xr, i, p)
        if eff:
            out.append(rail + pad + p("╰ ", "dim") + eff)
        for f in xr.by_idx(i):
            if f.sev == "INFO" and i == 0:
                continue
            out.append(rail + pad + p("⚑ ", SEV_ROLE[f.sev], True) + p(f.sev.ljust(5), SEV_ROLE[f.sev], True) + p(f.title, SEV_ROLE[f.sev]))
    out.append(rail + p("└─", "pink"))

    # ---------------- calls
    if xr.calls:
        out += [rail, rail + p("┌─ CALLS  ", "pink") + p("SysV: rdi rsi rdx rcx r8 r9, resolved from the nearest definition in the block", "dim")]
        for i, nm, args in xr.calls:
            sev = min((f.sev for f in xr.by_idx(i)), key=lambda s: SEV_ORDER[s], default=None)
            tag = p(f"[{sev}] ", SEV_ROLE[sev], True) if sev and sev != "INFO" else ""
            a = p(", ", "dim").join(p(k + "=", "dim") + p(v, "imm") for k, v in args)
            out.append(rail + p("│ ", "pink") + p("0x" + ins[i].addr, "label") + "  " + tag + p(nm, "sym", True) + p("(", "dim") + a + p(")", "dim"))
        out.append(rail + p("└─", "pink"))

    # ---------------- findings
    real = [f for f in xr.findings if not (f.sev == "INFO" and f.title.startswith("stack canary"))] or xr.findings
    out += [rail, rail + p("┌─ THREAT REPORT", "pink")]
    if not real:
        out.append(rail + p("│ ", "pink") + p("nothing flagged by the heuristics (that is not a proof of safety)", "ok"))
    for f in real:
        loc = f"0x{ins[f.idx].addr}"
        out.append(rail + p("│ ", "pink") + p(f.sev.center(6), SEV_ROLE[f.sev], True) + " "
                   + p(f.title, SEV_ROLE[f.sev], True) + p(f"  @ {loc}  [{f.conf}]", "dim"))
        if f.detail:
            out.append(rail + p("│        ", "pink") + p(f.detail, "label"))
        if f.fix:
            out.append(rail + p("│        ", "pink") + p("fix ▸ ", "ok") + p(f.fix, "dim"))
    out.append(rail + p("└─", "pink"))
    return out


def render_xray(funcs: list[Func], p: Painter, src_lines: list[str], show_src: bool):
    d = dom()
    title = f" {d['jp'] + '  ·  ' if d['jp'] else ''}{d['en']}  ·  X-RAY "
    bar = p("╔═╡", "pink") + p(title, "accent", True) + p("╞" + "═" * max(8, 70 - dw(title)), "pink")
    out = ["", bar]
    results = []
    for fn in funcs:
        build_cfg(fn)
        xr = xray_analyze(fn)
        results.append((fn, xr))
        out += xray_function(fn, xr, p, src_lines, show_src)
        out.append(p("╚" + "═" * 78, "pink"))
        out.append("")
    return out, results


# --------------------------------------------------------------------------- #
#  Animated control-flow graph                                                #
# --------------------------------------------------------------------------- #
DIRBIT = {(0, -1): 1, (1, 0): 2, (0, 1): 4, (-1, 0): 8}
LINECH = {1: "│", 4: "│", 5: "│", 2: "─", 8: "─", 10: "─", 6: "╭", 12: "╮", 3: "╰", 9: "╯",
          7: "├", 13: "┤", 14: "┬", 11: "┴", 15: "┼"}
HGAP = 4


def _route(points):
    cells = [points[0]]
    for (x0, y0), (x1, y1) in zip(points, points[1:]):
        dx, dy = (x1 > x0) - (x1 < x0), (y1 > y0) - (y1 < y0)
        x, y = x0, y0
        while (x, y) != (x1, y1):
            x, y = x + dx, y + dy
            cells.append((x, y))
    return cells


def _ascii1(ch: str) -> str:
    return ch if dw(ch) == 1 and ch.isprintable() else "?"


def _ins_cells(mn: str, ops: str, width: int):
    cells = [(c, classify(mn, "x86"), True) for c in mn.ljust(6)[:max(6, len(mn))]] + [(" ", "dim", False)]
    pos = 0
    for m in _OPERAND.finditer(ops):
        for c in ops[pos:m.start()]:
            cells.append((c, "dim", False))
        for c in m.group():
            cells.append((c, _ROLE[m.lastgroup], False))
        pos = m.end()
    for c in ops[pos:]:
        cells.append((c, "dim", False))
    cells = [(_ascii1(c), r, b) for c, r, b in cells]
    if len(cells) > width:
        cells = cells[:width - 1] + [("…", "dim", False)]
    return cells


class Graph:
    """Layered layout + orthogonal edge routing on a character canvas."""

    def __init__(self, fn: Func, term_w: int, src_lines: list[str], tags: dict, max_rows: int = 7):
        self.fn, self.E, self.B = fn, fn.edges, fn.blocks
        self.tags = tags
        B, E = self.B, self.E
        keys = sorted({b.layer for b in B})
        remap = {k: i for i, k in enumerate(keys)}
        for b in B:
            b.layer = remap[b.layer]
        L = len(keys)
        layers = [[] for _ in range(L)]
        for b in B:
            layers[b.layer].append(b.id)
        pos = {b: i for lay in layers for i, b in enumerate(lay)}
        fp = {b.id: [e.src for e in b.pred if not e.back and B[e.src].layer < b.layer] for b in B}
        fs = {b.id: [e.dst for e in b.succ if not e.back and B[e.dst].layer > b.layer] for b in B}
        for _ in range(4):
            for k in range(1, L):
                layers[k].sort(key=lambda b: sum(pos[x] for x in fp[b]) / len(fp[b]) if fp[b] else pos[b])
                pos.update({b: i for i, b in enumerate(layers[k])})
            for k in range(L - 2, -1, -1):
                layers[k].sort(key=lambda b: sum(pos[x] for x in fs[b]) / len(fs[b]) if fs[b] else pos[b])
                pos.update({b: i for i, b in enumerate(layers[k])})
        self.layers = layers
        israil = lambda e: e.back or B[e.dst].layer != B[e.src].layer + 1
        rails = [e for e in E if israil(e)]
        maxn = max(len(x) for x in layers)
        avail = term_w - 2 * len(rails) - 10
        W = max(26, min(44, (avail - (maxn - 1) * HGAP) // maxn))
        self.W = W

        # ---- boxes
        self.rows, self.bh = {}, {}
        for b in B:
            rows = self._box(b, W, src_lines, tags.get(b.id, {}), max_rows)
            self.rows[b.id], self.bh[b.id] = rows, len(rows)
        # ---- lanes / gaps / y
        lanes = [[] for _ in range(L + 1)]
        for e in E:
            s, t = B[e.src].layer, B[e.dst].layer
            if israil(e):
                lanes[s + 1].append((e.id, "x"))
                lanes[t].append((e.id, "e"))
            else:
                lanes[s + 1].append((e.id, "a"))
        gap_h = [max(2, len(x) + 1) for x in lanes]
        y, gap_y, layer_y = 0, [], []
        for k in range(L):
            gap_y.append(y)
            y += gap_h[k]
            layer_y.append(y)
            y += max(self.bh[b] for b in layers[k])
        gap_y.append(y)
        y += gap_h[L]
        self.ch = y
        # ---- x
        area = maxn * W + (maxn - 1) * HGAP
        self.bx, self.by = {}, {}
        for k, lay in enumerate(layers):
            tot = len(lay) * W + (len(lay) - 1) * HGAP
            x0 = 2 + (area - tot) // 2
            for i, b in enumerate(lay):
                self.bx[b], self.by[b] = x0 + i * (W + HGAP), layer_y[k]
        box_right = 2 + area
        self.cw = box_right + 2 + 2 * len(rails) + 3
        cx = {b: self.bx[b] + W // 2 for b in self.bx}
        # ---- exits / entries
        outs = {b.id: sorted(b.succ, key=lambda e: (israil(e), cx[e.dst])) for b in B}
        ins_ = {b.id: sorted(b.pred, key=lambda e: (israil(e), cx[e.src])) for b in B}
        spread = lambda x0, k, j: x0 + 2 + ((j + 1) * (W - 4)) // (k + 1)
        sx = {e.id: spread(self.bx[b.id], len(outs[b.id]), j) for b in B for j, e in enumerate(outs[b.id])}
        tx = {e.id: spread(self.bx[b.id], len(ins_[b.id]), j) for b in B for j, e in enumerate(ins_[b.id])}
        rail_x = {}
        for i, e in enumerate(sorted(rails, key=lambda e: (abs(B[e.dst].layer - B[e.src].layer), e.id))):
            rail_x[e.id] = box_right + 2 + 2 * i
        lane_row = lambda g, key: gap_y[g] + lanes[g].index(key)
        # ---- box cells
        self.box: dict = {}
        self.slot: dict = {}
        self.brole: dict = {}
        for b in B:
            t = tags.get(b.id, {})
            self.brole[b.id] = ("danger" if t.get("crit") else "accent" if b.id == 0 else "pink" if b.exit
                                else "stack" if b.header else "cyan")
            for j, row in enumerate(self.rows[b.id]):
                for i, (ch, kind, role, bold) in enumerate(row):
                    self.box[(self.bx[b.id] + i, self.by[b.id] + j)] = (ch, kind, role, bold, b.id)
            self.slot[b.id] = (self.bx[b.id] + W - 8, self.by[b.id])
        # ---- edges
        self.ec: dict = {}
        for e in E:
            s, t = e.src, e.dst
            ls, lt = B[s].layer, B[t].layer
            ey = self.by[s] + self.bh[s]
            ty = self.by[t]
            if israil(e):
                l1, l2 = lane_row(ls + 1, (e.id, "x")), lane_row(lt, (e.id, "e"))
                pts = [(sx[e.id], ey), (sx[e.id], l1), (rail_x[e.id], l1), (rail_x[e.id], l2), (tx[e.id], l2), (tx[e.id], ty - 1)]
            else:
                ln = lane_row(ls + 1, (e.id, "a"))
                pts = [(sx[e.id], ey), (sx[e.id], ln), (tx[e.id], ln), (tx[e.id], ty - 1)]
            cells = _route(pts)
            e.path = cells
            jx, jy = sx[e.id], ey - 1
            if (jx, jy) in self.box:
                old = self.box[(jx, jy)]
                self.box[(jx, jy)] = ("┳", old[1], old[2], old[3], old[4])
            for k, (x, y2) in enumerate(cells):
                ent = self.ec.setdefault((x, y2), [0, [], None])
                if k == 0:
                    ent[0] |= 1
                if k < len(cells) - 1:
                    nx, ny = cells[k + 1]
                    ent[0] |= DIRBIT[(nx - x, ny - y2)]
                if k > 0:
                    px, py = cells[k - 1]
                    ent[0] |= DIRBIT[(px - x, py - y2)]
                if e.id not in ent[1]:
                    ent[1].append(e.id)
                if k == len(cells) - 1:
                    ent[2] = "▼"

    def _box(self, b: Block, W: int, src_lines, tag: dict, max_rows: int):
        fn, cw = self.fn, W - 4
        its = [fn.ins[i] for i in b.idx]
        body = []
        srcln = next((i.src for i in its if i.src), None)
        if srcln and 0 < srcln <= len(src_lines):
            text = f"{srcln:>3}│ {src_lines[srcln - 1].strip()}"
            body.append([(_ascii1(c), "src", False) for c in text][:cw - 1] + ([("…", "dim", False)] if len(text) > cw - 1 else []))
        avail = max_rows - len(body)
        sel = its if len(its) <= avail else its[:avail - 2] + [None] + [its[-1]]
        for it in sel:
            if it is None:
                body.append([(c, "dim", False) for c in f"⋮ +{len(its) - (avail - 1)} more"])
                continue
            mn, ops = norm_ins(it)
            k = branch_kind(mn, ops)
            if k in ("call", "noret"):
                ops = call_name(ops)
            elif k in ("jmp", "cond") and it is its[-1]:
                tgt = next((e for e in b.succ if e.kind in ("jump", "taken")), None)
                if tgt is not None:
                    ops = f"→ B{tgt.dst}"
                elif b.tail:
                    ops = b.tail + " (tail call)"
                elif b.indirect:
                    ops = ops + "  ⇢ ?"
            body.append(_ins_cells(mn, ops, cw))
        mk = ("▶" if b.id == 0 else "") + ("■" if b.exit else "") + ("↻" if b.header else "")
        title = f" B{b.id}{(' ' + mk) if mk else ''} {b.label if len(b.label) <= 14 else b.label[:13] + '…'} "
        n = tag.get("n", 0)
        if n:
            title += f"◆{n} "
        title = "".join(_ascii1(c) if c != "◆" and c not in "▶■↻→" else c for c in title)[:W - 12]
        top = [("┏", "bd", "", True), ("━", "bd", "", True)] + [(c, "ti", "", True) for c in title]
        top += [("━", "bd", "", True)] * (W - len(top) - 1) + [("┓", "bd", "", True)]
        rows = [top]
        for cells in body:
            row = [("┃", "bd", "", True), (" ", "pad", "", False)]
            row += [(c, "tx", r, bd) for c, r, bd in cells]
            row += [(" ", "pad", "", False)] * (W - 2 - len(row))
            row += [(" ", "pad", "", False), ("┃", "bd", "", True)][:W - len(row)]
            rows.append(row)
        rows.append([("┗", "bd", "", True)] + [("━", "bd", "", True)] * (W - 2) + [("┛", "bd", "", True)])
        return rows


@dataclass
class State:
    active: int | None = None
    visits: dict = field(default_factory=dict)
    ecount: dict = field(default_factory=dict)
    pulses: list = field(default_factory=list)
    tick: int = 0
    lit: bool = False


def draw_graph(G: Graph, fr: Frame, ox: int, oy: int, vw: int, vh: int, vx: int, vy: int, st: State, twinkle: bool = True):
    cells = fr.cells
    dim = scale(PALETTE["dim"], 0.55)
    tint = scale(PALETTE["accent"], 0.15)
    for sy in range(vh):
        y = vy + sy
        if not 0 <= y < G.ch or not 0 <= oy + sy < fr.h:
            continue
        row = cells[oy + sy]
        for sx in range(vw):
            x = vx + sx
            if not 0 <= x < G.cw or not 0 <= ox + sx < fr.w:
                continue
            b = G.box.get((x, y))
            if b is not None:
                ch, kind, role, bold, bid = b
                act = bid == st.active
                seen = st.lit or st.visits.get(bid, 0) > 0
                if kind == "tx":
                    base, f = PALETTE[role], (1.0 if act else 0.95 if seen else 0.6)
                elif kind == "ti":
                    base, f = PALETTE[G.brole[bid]], 1.0
                else:
                    base, f = PALETTE[G.brole[bid]], (1.0 if act else 0.9 if seen else 0.5)
                if act:
                    base = mix(base, (255, 255, 255), 0.45)
                row[ox + sx] = (ch, (scale(base, f), bold or act, tint if act else None))
                continue
            e = G.ec.get((x, y))
            if e is not None:
                mask, eids, arrow = e
                best_f, best_e, hot = -1.0, None, False
                for eid in eids:
                    c = st.ecount.get(eid, 0)
                    act = any(p_[0] == eid for p_ in st.pulses)
                    f = 1.0 if act else 0.95 if st.lit else (0.55 + min(c, 6) * 0.07 if c else 0.3)
                    if f > best_f:
                        best_f, best_e, hot = f, eid, act
                role = G.E[best_e].role
                base = mix(PALETTE[role], (255, 255, 255), 0.35) if hot else PALETTE[role]
                row[ox + sx] = (arrow or LINECH.get(mask, "┼"), (scale(base, best_f), hot, None))
                continue
            if twinkle and not st.lit and ((x * 73856093) ^ (y * 19349663) ^ ((st.tick // 6) * 83492791)) % 197 == 0:
                row[ox + sx] = ("·", (dim, False, None))
    for eid, pos in st.pulses:
        path = G.E[eid].path
        for k, (ch, f) in enumerate((("◉", 1.0), ("●", 0.75), ("•", 0.5))):
            idx = int(pos) - k
            if 0 <= idx < len(path):
                x, y = path[idx]
                sx_, sy_ = x - vx + ox, y - vy + oy
                if ox <= sx_ < ox + vw and oy <= sy_ < oy + vh and 0 <= sy_ < fr.h and 0 <= sx_ < fr.w:
                    cells[sy_][sx_] = (ch, (mix(scale(PALETTE[G.E[eid].role], f), (255, 255, 255), 0.5 * f), True, None))
    for bid, n in st.visits.items():
        if n:
            x, y = G.slot[bid]
            lab = f"×{n}".rjust(5)
            for i, c in enumerate(lab):
                sx_, sy_ = x + i - vx + ox, y - vy + oy
                if c == " ":
                    continue
                if ox <= sx_ < ox + vw and oy <= sy_ < oy + vh and 0 <= sy_ < fr.h and 0 <= sx_ < fr.w:
                    cells[sy_][sx_] = (c, (mix(PALETTE["accent"], (255, 255, 255), 0.3), True, None))


@dataclass
class Visit:
    bid: int
    eid: int | None
    steps: list = field(default_factory=list)       # dicts: addr asm raw chg note ext
    note: str = ""


def _static_step(fn: Func, xr: XRay | None, i: int) -> dict:
    it = fn.ins[i]
    mn, ops = norm_ins(it)
    note = "".join(t for t, _r in effect_segments(xr, i)) if xr else ""
    return dict(addr=it.addr, asm=f"{mn} {ops}".strip(), raw=it.raw, chg=None, note=note, ext=False)


def sim_visits(fn: Func, xr: XRay | None, limit: int = 60) -> list[Visit]:
    """Coverage walk: always take the least-travelled edge until every reachable edge has been lit."""
    reach, stack = set(), [0]
    while stack:
        b = stack.pop()
        if b in reach:
            continue
        reach.add(b)
        stack += [e.dst for e in fn.blocks[b].succ]
    need = {e.id for e in fn.edges if e.src in reach}
    count: dict = {}
    mk = lambda bid, eid, note="": Visit(bid, eid, [_static_step(fn, xr, i) for i in fn.blocks[bid].idx], note)
    visits = [mk(0, None, "entry")]
    while len(visits) < limit:
        b = fn.blocks[visits[-1].bid]
        if not b.succ:
            if need <= set(count):
                break
            visits.append(mk(0, None, "↻ next path"))
            continue
        e = min(b.succ, key=lambda e: (count.get(e.id, 0), e.back, e.kind != "taken"))
        count[e.id] = count.get(e.id, 0) + 1
        visits.append(mk(e.dst, e.id))
    return visits


def trace_visits(fn: Func, events: list[dict], bias: int = 0) -> list[Visit]:
    visits: list[Visit] = []
    cur, last_idx = None, -1
    for ev in (e for e in events if e["t"] == "step"):
        pc = ev["pc"] - bias
        idx = fn.amap.get(pc)
        step = dict(addr=f"{pc:x}", asm=ev["asm"].strip(), raw=ev["raw"], chg=ev["chg"],
                    note=("stepped over " + (ev.get("sym") or "call")) if ev.get("skipped") else "", ext=idx is None)
        if idx is None:
            if visits:
                visits[-1].steps.append(step)
            continue
        b = fn.block_of[idx]
        if cur is None or b != cur or idx <= last_idx:
            eid = next((e.id for e in fn.blocks[cur].succ if e.dst == b), None) if cur is not None else None
            visits.append(Visit(b, eid))
            cur = b
        visits[-1].steps.append(step)
        last_idx = idx
    return visits


def _hud_step(fr: Frame, x: int, y: int, w: int, step: dict | None, dim: bool = False) -> None:
    if not step:
        return
    mn, _, ops = step["asm"].partition(" ")
    f = 0.55 if dim else 1.0
    cat = classify(mn, "x86")
    parts = [(("▸ " if not dim else "  "), rstyle("pink", f, True)),
             (("0x" + step["addr"]).ljust(10), rstyle("label", f)), ((step["raw"] or "")[:17].ljust(18), rstyle("bytes", f)),
             (mn.ljust(7), rstyle(cat, f, True)), (ops, rstyle("imm", f))]
    x = fr.segs(x, y, parts)
    if step.get("chg") and not dim:
        for name, (old, new) in step["chg"].items():
            a, b2 = (old, new) if name == "eflags" else (hex(old), hex(new))
            x = fr.segs(x + 2, y, [(name + " ", rstyle("reg")), (a, rstyle("dim")), (" ➜ ", rstyle("pink")), (b2, rstyle("ok", 1.0, True))])
            if x > w - 20:
                break
    elif step.get("note") and not dim:
        fr.put(x + 2, y, "⟨ " + step["note"][:max(0, w - x - 6)] + " ⟩", rstyle("dim", 1.3))


def graph_title(fn: Func, G: Graph, extra: str = "") -> list:
    d = dom()
    loops = sum(1 for b in fn.blocks if b.header)
    return [(f" {d['mark']} ", rstyle("pink", 1.0, True)), ((d["jp"] + " · " if d["jp"] else "") + d["en"] + " ", rstyle("accent", 1.0, True)),
            ("─ ", rstyle("dim")), (f"ƒ {fn.dname}  ", rstyle("label", 1.0, True)),
            (f"{len(fn.blocks)} blocks · {len(fn.edges)} edges · {loops} loops {extra}", rstyle("dim", 1.3))]


def legend(fr: Frame, x: int, y: int) -> None:
    fr.segs(x, y, [(" ━ fall ", rstyle("cyan")), ("━ taken ", rstyle("flow")), ("━ jump ", rstyle("ok")),
                   ("━ loop back-edge ", rstyle("stack")), ("◉ signal ", rstyle("imm", 1.0, True)),
                   ("▶ entry ", rstyle("accent")), ("■ exit ", rstyle("pink")), ("↻ loop head ", rstyle("stack")),
                   ("◆n findings", rstyle("danger"))])


def play_graph(scr: Screen, G: Graph, fn: Func, visits: list[Visit], mode: str) -> None:
    w, h = scr.size()
    hud_h = 6
    gh = max(6, h - hud_h - 2)
    st = State()
    vx = vy = 0.0
    hist: list[int] = []
    prev_steps: list = []
    budget = int(24 * 22)
    used = 0
    d = dom()

    def follow(bid):
        nonlocal vx, vy
        if bid is None:
            return
        tcy = G.by[bid] + G.bh[bid] / 2
        tcx = G.bx[bid] + G.W / 2
        tvy = max(0, min(max(0, G.ch - gh), tcy - gh / 2))
        tvx = max(0, min(max(0, G.cw - w), tcx - w / 2))
        vx += (tvx - vx) * 0.28
        vy += (tvy - vy) * 0.28

    def compose(visit, step, msg=""):
        fr = Frame(w, h)
        fr.segs(0, 0, graph_title(fn, G, f"· {mode}"))
        draw_graph(G, fr, 0, 1, w, gh, int(round(vx)), int(round(vy)), st)
        legend(fr, 0, gh + 1)
        y0 = gh + 2
        fr.put(0, y0, "═══╡ INSTRUCTION STREAM ╞" + "═" * max(0, w - 27), rstyle("pink"))
        if visit is not None:
            for k, ps in enumerate(prev_steps[-2:]):
                _hud_step(fr, 1, y0 + 1 + k, w, ps, True)
            _hud_step(fr, 1, y0 + 3, w, step)
            blk = fn.blocks[visit.bid]
            info = (f"B{blk.id}  {blk.label}  ·  loop depth {blk.depth}  ·  visits {st.visits.get(blk.id, 0)}  ·  path "
                    + "→".join(f"B{b}" for b in hist[-9:]))
            fr.put(1, y0 + 4, info[:w - 2], rstyle("dim", 1.4))
        if msg:
            fr.put(max(0, w - len(msg) - 2), y0 + 4, msg, rstyle("warn", 1.0, True))
        return fr

    def tick(visit=None, step=None, msg=""):
        st.tick += 1
        scr.show(compose(visit, step, msg))

    last = None
    try:
        for vi, v in enumerate(visits):
            if used > budget:
                break
            if v.eid is not None:
                path = G.E[v.eid].path
                pos = 0.0
                while pos < len(path) + 3:
                    st.pulses = [(v.eid, pos)]
                    follow(v.bid if pos > len(path) * 0.5 else (last.bid if last else v.bid))
                    tick(last, last.steps[-1] if last and last.steps else None)
                    pos += 2.4
                    used += 1
                st.pulses = []
                st.ecount[v.eid] = st.ecount.get(v.eid, 0) + 1
            st.active = v.bid
            st.visits[v.bid] = st.visits.get(v.bid, 0) + 1
            hist.append(v.bid)
            n = len(v.steps)
            per = 2 if len(visits) < 25 else 1
            frames = max(3, min(n * per, 16))
            for k in range(frames):
                si = min(n - 1, int(k * n / frames)) if n else 0
                follow(v.bid)
                tick(v, v.steps[si] if v.steps else None, v.note)
                if k and si and v.steps and si < n:
                    prev_steps.append(v.steps[si - 1])
                used += 1
            last = v
        st.active, st.lit = None, True
        for _ in range(14):
            tick(None, None)
    except (KeyboardInterrupt, BrokenPipeError):
        pass


def graph_static(G: Graph, fn: Func, color: bool, stats: str) -> list[str]:
    st = State(lit=True)
    fr = Frame(G.cw + 2, G.ch + 4)
    fr.segs(0, 0, graph_title(fn, G))
    draw_graph(G, fr, 1, 2, G.cw, G.ch, 0, 0, st, twinkle=False)
    legend(fr, 0, G.ch + 2)
    if stats:
        fr.put(1, G.ch + 3, stats, rstyle("dim", 1.4))
    return fr.lines(color)


# --------------------------------------------------------------------------- #
#  --graph / --xray drivers                                                   #
# --------------------------------------------------------------------------- #
def _pie_bias(exe: Path | None, events: list[dict]) -> int:
    """Load bias of a PIE binary: the gdb pcs are runtime addresses, objdump's are file-relative."""
    if exe is None:
        return 0
    try:
        with exe.open("rb") as fh:
            head = fh.read(18)
        if head[:4] != b"\x7fELF" or int.from_bytes(head[16:18], "little") != 3:
            return 0
    except OSError:
        return 0
    start = next((e for e in events if e["t"] == "start"), None)
    for ln in (start or {}).get("maps", []):
        parts = ln.split(None, 5)
        if len(parts) >= 6 and parts[2] == "00000000" and parts[5].endswith(exe.name):
            return int(parts[0].split("-")[0], 16)
    return 0


def _can_animate(args) -> bool:
    return (sys.stderr.isatty() and not args.no_anim and not args.output
            and not os.environ.get("ASMX_NO_ANIM"))


def graph_cli(args, err: Painter, p_out: Painter, items: list[Item], text: str, lang: str, info: str,
              exe: Path | None = None, events: list[dict] | None = None, prog_out: str = "") -> int:
    funcs = split_functions(items)
    if not funcs:
        raise AsmxError("no code found to graph", hint="functions may be optimised away: try -O0")
    fn, cands = pick_function(funcs, args.func)
    build_cfg(fn)
    src_lines = text.splitlines() if lang != "binary" and not args.no_source else []

    xr = None
    if IS_X86 and fn.ins[0].addr:
        try:
            xr = xray_analyze(fn)
        except Exception:                     # the graph must never die because the audit tripped
            xr = None
    tags: dict = {}
    if xr:
        for f in xr.findings:
            if f.sev == "INFO":
                continue
            t = tags.setdefault(fn.block_of[f.idx], {"n": 0, "crit": False})
            t["n"] += 1
            t["crit"] = t["crit"] or f.sev in ("CRIT", "HIGH")

    cols = shutil.get_terminal_size((110, 30)).columns if (sys.stderr.isatty() or sys.stdout.isatty()) else 120
    G = Graph(fn, max(60, cols - 1), src_lines, tags)

    if events is not None:
        visits = trace_visits(fn, events, _pie_bias(exe, events))
        if not visits:
            raise AsmxError(f"the trace never executed code inside {fn.dname}",
                            hint="pick the traced function with -f, e.g.  --graph --trace -f main")
        mode = f"live trace · {sum(len(v.steps) for v in visits)} instructions"
    else:
        visits = sim_visits(fn, xr)
        mode = "static flow simulation"

    if _can_animate(args):
        try:
            with Screen(sys.stderr, args.speed) as scr:
                play_graph(scr, G, fn, visits, mode)
        except (KeyboardInterrupt, OSError):
            pass

    loops = sum(1 for b in fn.blocks if b.header)
    stats = (f"{len(fn.ins)} instructions · {len(fn.blocks)} blocks · {len(fn.edges)} edges · {loops} loops · "
             f"max loop depth {max((b.depth for b in fn.blocks), default=0)}")
    if xr:
        worst = sorted({f.sev for f in xr.findings if f.sev != 'INFO'}, key=lambda s: SEV_ORDER[s])
        stats += f" · audit: {', '.join(worst) if worst else 'clean'}"
    emit(graph_static(G, fn, p_out.enabled, stats), args.output)
    if not args.quiet:
        if len(cands) > 1:
            print(err(f"  other matching functions: {', '.join(f.dname for f in cands[1:6])}  (choose with -f)", "dim"),
                  file=sys.stderr)
        if events is not None and prog_out.strip():
            print(err("  program output:", "dim") + "\n" + err(prog_out.rstrip(), "dim"), file=sys.stderr)
        if info:
            print("  " + err(info, "dim"), file=sys.stderr)
    return 0


def xray_cli(args, err: Painter, p_out: Painter, items: list[Item], text: str, lang: str, info: str) -> int:
    funcs = split_functions(items)
    if args.func:
        chosen = [f for f in funcs if args.func in f.name or args.func in f.dname]
        if not chosen:
            mine = [f for f in funcs if any(i.src for i in f.ins)] or funcs
            raise AsmxError(f"no function matching '{args.func}'", hint="available: " + ", ".join(f.dname for f in mine[:12]))
    else:
        chosen = [f for f in funcs if any(i.src for i in f.ins)] or [f for f in funcs if f.name == "main"] \
                 or [f for f in funcs if not f.name.startswith(("_", "."))][:4] or funcs[:3]
    chosen = chosen[:8]
    src_lines = text.splitlines() if lang != "binary" and not args.no_source else []
    lines, results = render_xray(chosen, p_out, src_lines, bool(src_lines))
    emit(lines, args.output)
    if not args.quiet:
        sev = {s: 0 for s in SEV_ORDER}
        for _fn, xr in results:
            for f in xr.findings:
                sev[f.sev] += 1
        parts = [f"{err(str(v), SEV_ROLE[k], True)} {err(k, 'dim')}" for k, v in sev.items() if v and k != "INFO"]
        print("\n  " + err(" ▸ ", "pink").join(parts or [err("no findings", "ok")]), file=sys.stderr)
        print("  " + err(info or "objdump", "dim"), file=sys.stderr)
    return 0


# --------------------------------------------------------------------------- #
#  CLI                                                                        #
# --------------------------------------------------------------------------- #
EPILOG = """\
examples:
  asmx prog.c                       C -> Intel asm at -O1, source-annotated
  asmx prog.c -O3 -f hot_loop       one function, fully optimised
  asmx prog.cpp --att               C++ in AT&T syntax (symbols demangled)
  asmx prog.c --sweep               instruction count across -O0..-Os
  asmx ./a.out -f main              disassemble a compiled binary (ELF/PE/Mach-O)
  asmx prog.py                      CPython bytecode
  asmx prog.c --deep -f main        real executable: addresses + machine-code bytes
  asmx prog.c --trace -f main       run in gdb, step instructions, show register changes
  asmx ./a.out --bytes -f main      binary with machine-code bytes
  echo 'int f(int x){return x*9;}' | asmx - --lang c -O2
  asmx prog.c --flags="-m32 -DDEBUG=1"

v2 - graph, x-ray, domains:
  asmx prog.c --graph -f main       animated control-flow graph (signal pulses, loops)
  asmx prog.c --graph --trace       the graph replays the REAL execution path (needs gdb)
  asmx prog.c --xray -f main        deepest view: effects, stack frame map, audit
  asmx ./a.out --xray -f parse      x-ray a compiled binary (x86-64)
  asmx prog.c --graph --domain gojo       Unlimited Void theme + intro
  asmx prog.c --xray  --domain sukuna     Malevolent Shrine theme + intro
"""


def parse_args(argv):
    ap = argparse.ArgumentParser(
        prog="asmx", description="source code -> annotated, highlighted assembly",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=EPILOG)
    ap.add_argument("file", help="source file, compiled binary, or '-' for stdin")
    ap.add_argument("-O", dest="opt", default="1", choices=OPT_LEVELS, metavar="LEVEL",
                    help="optimisation level: 0 1 2 3 s z g fast (default: 1)")
    ap.add_argument("-f", "--func", metavar="NAME", help="show only functions whose name contains NAME")
    ap.add_argument("--lang", choices=("c", "c++", "rust", "python"), help="force language (needed for stdin)")
    ap.add_argument("--att", action="store_true", help="AT&T syntax instead of Intel (x86)")
    ap.add_argument("--raw", action="store_true", help="keep every directive, label and section")
    ap.add_argument("--no-source", action="store_true", help="hide interleaved source lines")
    ap.add_argument("--flags", default="", metavar="'...'", help='extra compiler flags, use --flags="-m32 -DX"')
    ap.add_argument("--cc", metavar="PATH", help="compiler to use instead of auto-detect")
    ap.add_argument("--deep", action="store_true",
                    help="build a real executable: true addresses, machine-code bytes, source map (C/C++)")
    ap.add_argument("--bytes", action="store_true", help="show machine-code bytes (implied by --deep)")
    ap.add_argument("--trace", action="store_true",
                    help="run under gdb and single-step: registers, stack, memory map (C/C++/binary)")
    ap.add_argument("--steps", type=int, default=150, metavar="N", help="instructions to trace (default 150)")
    ap.add_argument("--args", default="", metavar="'...'", help="arguments passed to the traced program")
    ap.add_argument("--graph", action="store_true",
                    help="animated sci-fi control-flow graph (with --trace: replays the real path)")
    ap.add_argument("--xray", action="store_true",
                    help="deepest low-level view: effects, stack frame, call args, vulnerability audit (x86-64)")
    ap.add_argument("--omni", action="store_true",
                    help="whole-program/whole-run engine: real ptrace recording, syscalls, heap, taint, "
                         "symbolic constraints, DWARF structs, call graph -> animated graph+timeline")
    ap.add_argument("--omni-html", metavar="FILE", help="--omni: write the animated graph/timeline UI here")
    ap.add_argument("--omni-json", metavar="FILE", help="--omni: write the raw typed graph+events as JSON")
    ap.add_argument("--omni-dot", metavar="FILE", help="--omni: write the call/data graph as Graphviz DOT")
    ap.add_argument("--omni-input", metavar="BYTES", help="--omni: literal stdin for the recorded run (\\n, \\x41 escapes)")
    ap.add_argument("--omni-stdin-file", metavar="FILE", help="--omni: file of bytes piped to stdin for the recorded run")
    ap.add_argument("--omni-diff-against", metavar="FILE", help="--omni: build/run a second target and report where it diverges")
    ap.add_argument("--omni-max-steps", type=int, default=400000, help="--omni: instruction budget (default 400000)")
    ap.add_argument("--domain", choices=tuple(DOMAINS), default="cyber",
                    help="visual theme: cyber matrix gojo sukuna (gojo/sukuna play a domain-expansion intro)")
    ap.add_argument("--no-anim", action="store_true", help="skip intro/animation, print static frames only")
    ap.add_argument("--speed", type=float, default=1.0, metavar="X", help="animation speed multiplier (default 1.0)")
    ap.add_argument("--sweep", action="store_true", help="compare instruction counts across -O levels")
    ap.add_argument("-o", "--output", metavar="FILE", help="write plain (uncoloured) output to FILE")
    ap.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    ap.add_argument("-q", "--quiet", action="store_true", help="no banner or stats on stderr")
    ap.add_argument("--timeout", type=int, default=30, metavar="SEC", help="tool timeout (default 30)")
    ap.add_argument("--version", action="version", version=f"asmx {__version__}")
    return ap.parse_args(argv)


def sniff_binary(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            head = fh.read(4)
    except OSError:
        return False
    return head.startswith((b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"))


def build(args, lang, path, text, workdir, opt) -> tuple[list[Item], str, str]:
    """Return (items, tool-info string, compiler warnings)."""
    if lang == "python":
        return python_items(text, path.name if path else "<stdin>"), f"CPython {platform.python_version()}", ""
    tool = find_tool(lang, args.cc)
    src = ensure_source(lang, path, text, workdir)
    flags = parse_flags(args.flags)
    asm, warnings = compile_to_asm(lang, src, opt, flags, args.att, tool, args.timeout, workdir)
    items = parse_asm(asm, src.name, args.raw)
    info = f"{tool_version(tool) or Path(tool).name}  ·  -O{opt}  ·  {'AT&T' if args.att else 'Intel' if IS_X86 else 'native'}"
    return items, info, warnings


def run_cli(args, err: Painter) -> int:
    if args.omni:
        omni_argv = [args.file, "-O", args.opt]
        if args.cc: omni_argv += ["--cc", args.cc]
        if args.flags: omni_argv += ["--flags", args.flags]
        if args.args: omni_argv += ["--args", args.args]
        if args.omni_input is not None: omni_argv += ["--input", args.omni_input]
        if args.omni_stdin_file: omni_argv += ["--stdin-file", args.omni_stdin_file]
        if args.omni_diff_against: omni_argv += ["--diff-against", args.omni_diff_against]
        omni_argv += ["--max-steps", str(args.omni_max_steps), "--timeout", str(args.timeout)]
        if args.omni_html: omni_argv += ["--html", args.omni_html]
        if args.omni_json: omni_argv += ["--json", args.omni_json]
        if args.omni_dot: omni_argv += ["--dot", args.omni_dot]
        if args.output: omni_argv += ["-o", args.output]
        if args.quiet: omni_argv += ["--quiet"]
        return omni_main(omni_argv)
    path: Path | None = None
    text = ""
    if args.file == "-":
        if not args.lang:
            raise AsmxError("reading stdin needs --lang", EXIT_USAGE, hint="e.g.  asmx - --lang c < file.c")
        data = sys.stdin.buffer.read(MAX_SOURCE_BYTES + 1)
        if len(data) > MAX_SOURCE_BYTES:
            raise AsmxError("input too large (limit 5 MB)", EXIT_USAGE)
        text, lang = data.decode("utf-8", "replace"), args.lang
    else:
        path = Path(args.file).resolve()   # compilers run with cwd=src.parent: never pass a relative path
        if not path.is_file():
            raise AsmxError(f"no such file: {path}", EXIT_USAGE)
        if sniff_binary(path):
            lang = "binary"
        else:
            lang = args.lang or EXT_LANG.get(path.suffix.lower())
            if not lang:
                raise AsmxError(f"cannot guess language of {path.name}", EXIT_USAGE,
                                hint="use --lang c|c++|rust|python")
            if path.stat().st_size > MAX_SOURCE_BYTES:
                raise AsmxError("source too large (limit 5 MB)", EXIT_USAGE)
            text = path.read_text(errors="replace")

    p_out = Painter(False if args.output else {"always": True, "never": False}.get(
        args.color, sys.stdout.isatty() and "NO_COLOR" not in os.environ))

    if (args.graph or args.xray) and lang == "python":
        raise AsmxError("--graph/--xray work on native code (c, c++, rust, binaries)", EXIT_USAGE,
                        hint="for Python use plain `asmx prog.py` (CPython bytecode)")
    if args.xray and not IS_X86:
        raise AsmxError("--xray decodes x86-64 semantics; this host is not x86", EXIT_USAGE)
    if args.graph or args.xray:
        args.att = False      # the semantic engine reads Intel syntax
    if args.xray:
        args.deep = True      # x-ray needs a real executable: addresses, bytes, DWARF lines

    maybe_intro(args, err)
    if not args.quiet and err.enabled:
        print_banner(err)
    if args.sweep and lang in ("binary", "python"):
        raise AsmxError("--sweep needs a compiled language (c, c++, rust)", EXIT_USAGE)

    with tempfile.TemporaryDirectory(prefix="asmx-") as tmp:
        workdir = Path(tmp)
        if args.sweep:
            rows = []
            for level in ("0", "1", "2", "3", "s"):
                items, _, _ = build(args, lang, path, text, workdir, level)
                items = select(items, args.func, args.raw)
                rows.append((level, compute_stats(items)["instructions"]))
            peak = max(n for _, n in rows) or 1
            lines = [p_out(f"  instruction count by optimisation level"
                           f"{' · ' + args.func if args.func else ''}", "dim")]
            for level, n in rows:
                bar = "█" * (max(1, round(36 * n / peak)) if n else 0)
                lines.append(f"  {p_out(('-O' + level).ljust(4), 'accent', bold=True)} "
                             f"{p_out.gradient(bar)} {p_out(str(n), 'imm', bold=True)}")
            emit(lines, args.output)
            return 0

        exe, src_name, info, warnings = None, None, "", ""
        graph_only = args.graph and not (args.trace or args.xray or args.deep)
        if lang == "binary":
            exe = path
        elif args.deep or args.trace or args.xray or args.graph:
            if lang not in ("c", "c++"):
                if not graph_only:
                    raise AsmxError("--deep/--trace/--xray support C and C++ sources", EXIT_USAGE,
                                    hint="for Rust/Go: build a binary yourself and pass it:  asmx ./target/debug/app --xray")
            else:
                try:
                    tool = find_tool(lang, args.cc)
                    src = ensure_source(lang, path, text, workdir)
                    exe = compile_to_exe(lang, src, args.opt, parse_flags(args.flags), tool, args.timeout, workdir)
                    src_name = src.name
                    info = f"{tool_version(tool) or Path(tool).name}  ·  -O{args.opt}  ·  -g -no-pie"
                except AsmxError:
                    if not graph_only:   # a plain --graph can fall back to assembly output
                        raise
                    exe = None

        if args.trace:
            if not 1 <= args.steps <= 5000:
                raise AsmxError("--steps must be between 1 and 5000", EXIT_USAGE)
            func = args.func or "main"
            if not args.quiet:
                print(err("  ▸ running the target under gdb (it really executes)", "warn"), file=sys.stderr)
            events, prog_out = trace_binary(exe, func, args.steps, parse_flags(args.args), args.timeout, workdir)
            if args.graph:
                items = disassemble_binary(exe, False, args.timeout, src_name)
                demangle(items)
                return graph_cli(args, err, p_out, items, text, lang, info, exe=exe, events=events,
                                 prog_out=prog_out)
            emit(render_trace(events, p_out, text.splitlines(), src_name, prog_out, func), args.output)
            if not args.quiet:
                steps = [e for e in events if e["t"] == "step"]
                changed = {k for e in steps for k in e["chg"]}
                skipped = sum(1 for e in steps if e.get("skipped"))
                print(f"\n  {err(str(len(steps)), 'accent', True)} {err('instructions', 'dim')}"
                      f" {err(' ▸ ', 'pink')}{err(str(len(changed)), 'accent', True)} {err('registers modified', 'dim')}"
                      f" {err(' ▸ ', 'pink')}{err(str(skipped), 'accent', True)} {err('external calls skipped', 'dim')}",
                      file=sys.stderr)
                print("  " + err(info or "objdump/gdb", "dim"), file=sys.stderr)
            return 0

        if exe is not None:
            items = disassemble_binary(exe, args.att, args.timeout, src_name)
            info = info or "objdump"
        else:
            items, info, warnings = build(args, lang, path, text, workdir, args.opt)

    if lang != "python":
        demangle(items)
    if args.graph or args.xray:
        if exe is not None or lang == "binary":
            pass
        if args.xray:
            return xray_cli(args, err, p_out, items, text, lang, info)
        return graph_cli(args, err, p_out, items, text, lang, info)
    if args.deep and not args.func:
        items = keep_user_functions(items)
    items = select(items, args.func, args.raw)
    if args.func and not any(i.kind == "ins" for i in items):
        raise AsmxError(f"no function matching '{args.func}'", hint="drop -f to list everything, or check -O "
                        "(the function may have been optimised out)")
    if not any(i.kind == "ins" for i in items):
        raise AsmxError("no instructions were emitted", hint="functions may be optimised away: try -O0, make them "
                        "non-static (C) / pub (Rust), or call them from main")

    src_lines = text.splitlines() if lang != "binary" else []
    emit(render(items, src_lines, p_out, lang, not args.no_source and bool(src_lines),
                show_bytes=args.bytes or args.deep), args.output)

    if not args.quiet:
        if warnings:
            print(err("  compiler warnings:", "warn") + "\n" + err(warnings, "dim"), file=sys.stderr)
        print_stats(items, err, info + (f"  ·  wrote {args.output}" if args.output else ""), lang)
    return 0


def emit(lines: list[str], output: str | None) -> None:
    text = "\n".join(lines) + "\n"
    if output:
        Path(output).write_text(text)
    else:
        sys.stdout.write(text)


def main(argv=None) -> int:
    args = parse_args(argv)
    apply_domain(args.domain)
    err = Painter(args.color == "always" or (args.color == "auto" and sys.stderr.isatty()))
    try:
        return run_cli(args, err)
    except AsmxError as exc:
        print(f"\n{err('✖ ' + str(exc), 'err', bold=True)}", file=sys.stderr)
        if exc.detail:
            print(err(exc.detail, "dim"), file=sys.stderr)
        if exc.hint:
            print(f"  {err('▸', 'accent')} {exc.hint}", file=sys.stderr)
        return exc.code
    except BrokenPipeError:  # e.g. `asmx x.c | head`
        sys.stderr.close()
        return 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())