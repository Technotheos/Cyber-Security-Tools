#!/usr/bin/env python3
"""asmx - source code -> annotated, syntax-highlighted assembly.

Pure standard library. Wraps the compilers / binutils already on your machine
(gcc, clang, g++, rustc, objdump, c++filt) and adds source mapping, noise
filtering, demangling, highlighting and stats on top.
"""
from __future__ import annotations

import argparse
import dis
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

__version__ = "1.0.0"

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
        path = Path(args.file)
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
        if lang == "binary":
            exe = path
        elif args.deep or args.trace:
            if lang not in ("c", "c++"):
                raise AsmxError("--deep/--trace support C and C++ sources", EXIT_USAGE,
                                hint="for Rust/Go: build a binary yourself and pass it:  asmx ./target/debug/app --trace")
            tool = find_tool(lang, args.cc)
            src = ensure_source(lang, path, text, workdir)
            exe = compile_to_exe(lang, src, args.opt, parse_flags(args.flags), tool, args.timeout, workdir)
            src_name = src.name
            info = f"{tool_version(tool) or Path(tool).name}  ·  -O{args.opt}  ·  -g -no-pie"

        if args.trace:
            if not 1 <= args.steps <= 5000:
                raise AsmxError("--steps must be between 1 and 5000", EXIT_USAGE)
            func = args.func or "main"
            if not args.quiet:
                print(err("  ▸ running the target under gdb (it really executes)", "warn"), file=sys.stderr)
            events, prog_out = trace_binary(exe, func, args.steps, parse_flags(args.args), args.timeout, workdir)
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
