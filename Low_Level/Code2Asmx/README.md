# --Code2Asmx-- #

Source code to annotated assembly, from the terminal. It wraps gcc/clang, objdump and gdb
and adds source mapping, noise filtering, demangling, highlighting and a dynamic tracer.

- Disassemble C, C++, Rust (best-effort), Python bytecode and compiled binaries
- `--deep`: real addresses, machine-code bytes, source-to-instruction mapping
- `--trace`: runs the target under gdb and single-steps it, logging register and flag
  changes, a stack dump and the memory map (x86-64)
- `--sweep`: compare instruction counts across `-O0` to `-Os`
- Pure Python standard library, no pip installs

> **Warning:** `--trace` really executes the target. Only trace code you trust, and only
> analyse software you are authorised to test.

## Requirements
Python 3.8+, plus `gcc`/`g++`, `binutils` (objdump) and `gdb` for the modes that need them.

## To use it just run : python3 Code2Asmx.py 'file_path' 'a flag'


# Example: Tracing a C++ Network Program Implementation

Below is a trace visualization from executing a low-level network binary, demonstrating real-time inspection of CPU instruction paths, active stack registers, and memory mappings.

```text
technotheos@HP-EliteBook-840-G8-PC:~/CodeToAssembly\$ python3 Code2Asmx.py ../Tests/test.cpp --trace

  ▄▀█ █▀ █▀▄▀█ ▀▄▀
  █▀█ ▄█ █░▀░█ █░█
  source ⟶ assembly  //  v1.0.0

  ▸ running the target under gdb (it really executes)

━━ REGISTERS  ·  breakpoint at main ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  rax     0x00007ffff7a19de8  ‹anon›
  rbx     0x0000000000000000  
  rcx     0x0000000000403df0  ‹target.bin›
  rdx     0x00007fffffffdc18  ‹[stack]›
  rsi     0x00007fffffffdc08  ‹[stack]›
  rdi     0x0000000000000001  
  rbp     0x00007fffffffdb80  ‹[stack]›
  rsp     0x00007fffffffdad8  ‹[stack]›
  r8      0x00007ffff7a12680  ‹libc.so.6›
  r9      0x00007ffff7a13fa0  ‹libc.so.6›
  r10     0x0000000000012010  
  r11     0x00007ffff7a12ac0  ‹libc.so.6›
  r12     0x00007fffffffdc08  ‹[stack]›
  r13     0x0000000000000001  
  r14     0x00007ffff7ffd000  ‹ld-linux-x86-64.so.2›
  r15     0x0000000000403df0  ‹target.bin›
  rip     0x0000000000401280  ‹target.bin›
  eflags  [ PF ZF IF ]

━━ STACK  ·  16 qwords from rsp ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  0x7fffffffdad8  rsp+0x00  0x00007ffff782a601  ‹libc.so.6›
  0x7fffffffdae0  rsp+0x08  0x0000000000000000
  0x7fffffffdae8  rsp+0x10  0x00007fffffffdc08  ‹[stack]›
  0x7fffffffdaf0  rsp+0x18  0x0000000100000008
  0x7fffffffdaf8  rsp+0x20  0x0000000000401280  ‹target.bin›
  0x7fffffffdb00  rsp+0x28  0x0000000000000000
  0x7fffffffdb08  rsp+0x30  0x0000000000000009
  0x7fffffffdb10  rsp+0x38  0x0000000000000000
  0x7fffffffdb18  rsp+0x40  0xb727e83b0f4adde6
  0x7fffffffdb20  rsp+0x48  0x00007fffffffdc08  ‹[stack]›
  0x7fffffffdb28  rsp+0x50  0x0000000000000001
  0x7fffffffdb30  rsp+0x58  0x00007ffff7ffd000  ‹ld-linux-x86-64.so.2›
  0x7fffffffdb38  rsp+0x60  0x0000000000403df0  ‹target.bin›
  0x7fffffffdb40  rsp+0x68  0xb727e83b0d8adde6
  0x7fffffffdb48  rsp+0x70  0xb727f8c1f320dde6
  0x7fffffffdb50  rsp+0x78  0x00007fff00000000

━━ MEMORY MAP ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  0x000000400000-0x000000401000  r--p  target.bin
  0x000000401000-0x000000402000  r-xp  target.bin
  0x000000402000-0x000000403000  r--p  target.bin
  0x000000403000-0x000000404000  r--p  target.bin
  0x000000404000-0x000000405000  rw-p  target.bin
  0x000000405000-0x000000438000  rw-p  [heap]
  0x7ffff7800000-0x7ffff7828000  r--p  libc.so.6
  0x7ffff7828000-0x7ffff79c0000  r-xp  libc.so.6
  0x7ffff79c0000-0x7ffff7a0e000  r--p  libc.so.6
  0x7ffff7a0e000-0x7ffff7a12000  r--p  libc.so.6
  0x7ffff7a12000-0x7ffff7a14000  rw-p  libc.so.6
  0x7ffff7a14000-0x7ffff7a21000  rw-p  anon
  0x7ffff7ada000-0x7ffff7aec000  r--p  libm.so.6
  0x7ffff7aec000-0x7ffff7b8c000  r-xp  libm.so.6
  0x7ffff7b8c000-0x7ffff7bfe000  r--p  libm.so.6
  0x7ffff7bfe000-0x7ffff7bff000  r--p  libm.so.6
  0x7ffff7bff000-0x7ffff7c00000  rw-p  libm.so.6
  0x7ffff7c00000-0x7ffff7ca3000  r--p  libstdc++.so.6.0.35
  … 23 more

━━ EXECUTION  ·  150 instructions ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ▍  27 │ int main() {
  0000  0x401280  41 55                    push    r13                         ‹ rsp 0x7fffffffdad8 ➜ 0x7fffffffdad0 ›
  0001  0x401282  41 54                    push    r12                         ‹ rsp 0x7fffffffdad0 ➜ 0x7fffffffdac8 ›
  0002  0x401284  55                       push    rbp                         ‹ rsp 0x7fffffffdac8 ➜ 0x7fffffffdac0 ›
  0003  0x401285  53                       push    rbx                         ‹ rsp 0x7fffffffdac0 ➜ 0x7fffffffdab8 ›
  0004  0x401286  48 81 ec 48 04 00 00     sub     rsp, 0x448                  ‹ rsp 0x7fffffffdab8 ➜ 0x7fffffffd670  eflags [ PF ZF IF ] ➜ [ IF ] ›
  0005  0x40128d  64 48 8b 04 25 28 00 0…  mov     rax, QWORD PTR fs:0x28      ‹ rax 0x7ffff7a19de8 ➜ 0x6bc6215305c85b00 ›
  0006  0x401296  48 89 84 24 38 04 00 00  mov     QWORD PTR [rsp+0x438], rax
  0007  0x40129e  31 c0                    xor     eax, eax                    ‹ rax 0x6bc6215305c85b00 ➜ 0x0  eflags [ IF ] ➜ [ PF ZF IF ] ›
  ▍  28 │ int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  0008  0x4012a0  ba 00 00 00 00           mov     edx, 0x0                    ‹ rdx 0x7fffffffdc18 ➜ 0x0 ›
  0009  0x4012a5  be 01 00 00 00           mov     esi, 0x1                    ‹ rsi 0x7fffffffdc08 ➜ 0x1 ›
  0010  0x4012aa  bf 02 00 00 00           mov     edi, 0x2                    ‹ rdi 0x1 ➜ 0x2 ›
  0011  0x4012af  e8 9c fd ff ff           call    0x401050 <socket@plt>       ‹ rax 0x0 ➜ 0x3  rcx 0x403df0 ➜ 0x7ffff793945b  r10 0x12010 ➜ 0x0  r11 0x7ffff7a12ac0 ➜ 0x202  eflags [ PF ZF IF ] ➜ [ CF IF ] ›
          ⤷ stepped over a call into code without debug info
  ▍  29 │ if (server_fd < 0) {
  0012  0x4012b4  85 c0                    test    eax, eax                    ‹ eflags [ CF IF ] ➜ [ PF IF ] ›
  0013  0x4012b6  0f 88 b8 00 00 00        js      0x401374 <main()+244>
  0014  0x4012bc  41 89 c4                 mov     r12d, eax                   ‹ r12 0x7fffffffdc08 ➜ 0x3 ›
  ▍  35 │ int opt = 1;
  0015  0x4012bf  c7 44 24 08 01 00 00 00  mov     DWORD PTR [rsp+0x8], 0x1
  ▍  36 │ if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
  0016  0x4012c7  48 8d 4c 24 08           lea     rcx, [rsp+0x8]              ‹ rcx 0x7ffff793945b ➜ 0x7fffffffd678 ›
  0017  0x4012cc  41 b8 04 00 00 00        mov     r8d, 0x4                    ‹ r8 0x7ffff7a12680 ➜ 0x4 ›
  0018  0x4012d2  ba 02 00 00 00           mov     edx, 0x2                    ‹ rdx 0x0 ➜ 0x2 ›
  0019  0x4012d7  be 01 00 00 00           mov     esi, 0x1
  0020  0x4012dc  89 c7                    mov     edi, eax                    ‹ rdi 0x2 ➜ 0x3 ›
  0021  0x4012de  e8 3d fe ff ff           call    0x401120 <setsockopt@plt>   ‹ rax 0x3 ➜ 0x0  rcx 0x7fffffffd678 ➜ 0x7ffff79392ce  r10 0x0 ➜ 0x7fffffffd678  eflags [ PF IF ] ➜ [ CF PF IF ] ›
          ⤷ stepped over a call into code without debug info
  0022  0x4012e3  85 c0                    test    eax, eax                    ‹ eflags [ CF PF IF ] ➜ [ PF ZF IF ] ›
  0023  0x4012e5  0f 88 b4 00 00 00        js      0x40139f <main()+287>
  ▍  42 │ sockaddr_in address{};
  0024  0x4012eb  48 c7 44 24 14 00 00 0…  mov     QWORD PTR [rsp+0x14], 0x0
  0025  0x4012f4  c7 44 24 1c 00 00 00 00  mov     DWORD PTR [rsp+0x1c], 0x0
  ▍  43 │ address.sin_family = AF_INET;
  0026  0x4012fc  66 c7 44 24 10 02 00     mov     WORD PTR [rsp+0x10], 0x2
  ▍  45 │ address.sin_port = htons(PORT);
  0027  0x401303  66 c7 44 24 12 1f 90     mov     WORD PTR [rsp+0x12], 0x901f
  ▍  47 │ if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
```
