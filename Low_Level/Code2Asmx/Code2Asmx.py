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

__version__ = "2.0.0"

EXIT_FAIL, EXIT_USAGE, EXIT_MISSING = 1, 2, 3
MAX_SOURCE_BYTES = 5 * 1024 * 1024
OPT_LEVELS = ("0", "1", "2", "3", "s", "z", "g", "fast")
EXT_LANG = {".c": "c", ".cc": "c++", ".cpp": "c++", ".cxx": "c++", ".rs": "rust", ".py": "python"}
TOOLS = {"c": ("gcc", "clang", "cc"), "c++": ("g++", "clang++", "c++"), "rust": ("rustc",)}
IS_X86 = platform.machine().lower() in ("x86_64", "amd64", "i386", "i686")


class AsmxError(Exception):
    def __init__(self, message, code=EXIT_FAIL, detail="", hint=""):
        super().__init__(message)
        self.code, self.detail, self.hint = code, detail, hint


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