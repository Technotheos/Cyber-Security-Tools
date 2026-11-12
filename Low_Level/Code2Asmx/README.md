# --Code2Asmx-- #

Source code to annotated assembly, from the terminal. It wraps gcc/clang, objdump and gdb
and adds source mapping, noise filtering, demangling, highlighting and a dynamic tracer.

- Disassemble C, C++, Rust (best-effort), Python bytecode and compiled binaries
- `--deep`: real addresses, machine-code bytes, source-to-instruction mapping
- `--trace`: runs the target under gdb and single-steps it, logging register and flag
  changes, a stack dump and the memory map (x86-64)
- `--sweep`: compare instruction counts across `-O0` to `-Os`
- Pure Python standard library, no pip installs

well now we have a beautiful graph representation, it looks so appealing. 
## you can run :

**python3 Code2Asmx.py Tests/test.cpp --graph -f main -O0 --domain gojo**

**python3 Code2Asmx.py Tests/test.cpp --graph --trace -f main -O0 --steps 600**

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

**```python3 asmx.py Tests/test.cpp --graph --trace -f main -O0 --steps 600``` command execution example :**

**I don't think it will look better here, so make sure to run it and see it with your eyes, it is really magnificent and gorgeous to look at.**

# technotheos@HP-EliteBook-840-G8-PC:~$ python3 asmx.py Tests/test.cpp --graph --trace -f main -O0 --steps 600

```
  ▄▀█ █▀ █▀▄▀█ ▀▄▀
  █▀█ ▄█ █░▀░█ █░█
  source ⟶ assembly  //  v2.0.0

  ▸ running the target under gdb (it really executes)
 ◢◤ NEURAL LINK ─ ƒ main  27 blocks · 38 edges · 2 loops                                                                                           
                                                                                                                                                   
                                                                                                                                                   
                                                                                                                                                   
                                                ┏━ B0 ▶ main ━━━━━━━━━━━━┓                                                                         
                                                ┃  27│ int main() {      ┃                                                                         
                                                ┃ push   rbp             ┃                                                                         
                                                ┃ mov    rbp, rsp        ┃                                                                         
                                                ┃ sub    rsp, 0x450      ┃                                                                         
                                                ┃ mov    rax, QWORD PTR… ┃                                                                         
                                                ┃ ⋮ +8 more              ┃                                                                         
                                                ┃ jns    → B2            ┃                                                                         
                                                ┗━━━━━━━━┳━━━━━━┳━━━━━━━━┛                                                                         
                                              ╭──────────╯      │                                                                                  
                                              │                 ╰───────────╮                                                                      
                                              ▼                             ▼                                                                      
                                 ┏━ B2 0x4012ef ━━━━━━━━━━┓    ┏━ B1 0x4012db ━━━━━━━━━━┓                                                          
                                 ┃  35│ int opt = 1;      ┃    ┃  30│ perror("socket f… ┃                                                          
                                 ┃ mov    DWORD PTR [rbp… ┃    ┃ mov    edi, 0x40202a   ┃                                                          
                                 ┃ lea    rdx, [rbp-0x45… ┃    ┃ call   perror          ┃                                                          
                                 ┃ mov    eax, DWORD PTR… ┃    ┃ mov    eax, 0x1        ┃                                                          
                                 ┃ mov    r8d, 0x4        ┃    ┃ jmp    → B24           ┃                                                          
                                 ┃ ⋮ +7 more              ┃    ┗━━━━━━━━━━━━┳━━━━━━━━━━━┛                                                          
                                 ┃ je     → B4            ┃                 │                                                                      
                                 ┗━━━━━━━━┳━━━━━━┳━━━━━━━━┛                 │                                                                      
                                          │      │                          ╰────────────────────────────────────────────────────────────────╮     
                                          ╰───╮  │                                                                                           │     
                                              │  ╰──────────────────────────╮                                                                │     
                                              ▼                             ▼                                                                │     
                                 ┏━ B4 0x401348 ━━━━━━━━━━┓    ┏━ B3 0x401327 ━━━━━━━━━━┓                                                    │     
                                 ┃  42│ sockaddr_in addr… ┃    ┃  37│ perror("setsocko… ┃                                                    │     
                                 ┃ mov    QWORD PTR [rbp… ┃    ┃ mov    edi, 0x402038   ┃                                                    │     
                                 ┃ mov    QWORD PTR [rbp… ┃    ┃ call   perror          ┃                                                    │     
                                 ┃ mov    WORD PTR [rbp-… ┃    ┃ mov    eax, DWORD PTR… ┃                                                    │     
                                 ┃ mov    DWORD PTR [rbp… ┃    ┃ mov    edi, eax        ┃                                                    │     
                                 ┃ ⋮ +11 more             ┃    ┃ ⋮ +2 more              ┃                                                    │     
                                 ┃ je     → B6            ┃    ┃ jmp    → B24           ┃                                                    │     
                                 ┗━━━━━━━━┳━━━━━━┳━━━━━━━━┛    ┗━━━━━━━━━━━━┳━━━━━━━━━━━┛                                                    │     
                                          │      │                          ╰──────────────────────────────────────────────────────────────╮ │     
                                          ╰───╮  │                                                                                         │ │     
                                              │  ╰──────────────────────────╮                                                              │ │     
                                              ▼                             ▼                                                              │ │     
                                 ┏━ B6 0x4013c6 ━━━━━━━━━━┓    ┏━ B5 0x4013a5 ━━━━━━━━━━┓                                                  │ │     
                                 ┃  53│ if (listen(serve… ┃    ┃  48│ perror("bind fai… ┃                                                  │ │     
                                 ┃ mov    eax, DWORD PTR… ┃    ┃ mov    edi, 0x40204a   ┃                                                  │ │     
                                 ┃ mov    esi, 0x1000     ┃    ┃ call   perror          ┃                                                  │ │     
                                 ┃ mov    edi, eax        ┃    ┃ mov    eax, DWORD PTR… ┃                                                  │ │     
                                 ┃ call   listen          ┃    ┃ mov    edi, eax        ┃                                                  │ │     
                                 ┃ ⋮ +2 more              ┃    ┃ ⋮ +2 more              ┃                                                  │ │     
                                 ┃ je     → B8            ┃    ┃ jmp    → B24           ┃                                                  │ │     
                                 ┗━━━━━━━━┳━━━━━━┳━━━━━━━━┛    ┗━━━━━━━━━━━━┳━━━━━━━━━━━┛                                                  │ │     
                                          │      │                          ╰──────────────────────────────────────────────────────────╮   │ │     
                                          ╰───╮  │                                                                                     │   │ │     
                                              │  ╰──────────────────────────╮                                                          │   │ │     
                                              ▼                             ▼                                                          │   │ │     
                                 ┏━ B8 0x401400 ━━━━━━━━━━┓    ┏━ B7 0x4013df ━━━━━━━━━━┓                                              │   │ │     
                                 ┃  59│ make_non_blockin… ┃    ┃  54│ perror("listen f… ┃                                              │   │ │     
                                 ┃ mov    eax, DWORD PTR… ┃    ┃ mov    edi, 0x402056   ┃                                              │   │ │     
                                 ┃ mov    edi, eax        ┃    ┃ call   perror          ┃                                              │   │ │     
                                 ┃ call   make_non_block… ┃    ┃ mov    eax, DWORD PTR… ┃                                              │   │ │     
                                 ┃ mov    esi, 0x402064   ┃    ┃ mov    edi, eax        ┃                                              │   │ │     
                                 ┃ ⋮ +7 more              ┃    ┃ ⋮ +2 more              ┃                                              │   │ │     
                                 ┃ call   std::basic_ost… ┃    ┃ jmp    → B24           ┃                                              │   │ │     
                                 ┗━━━━━━━━━━━━┳━━━━━━━━━━━┛    ┗━━━━━━━━━━━━┳━━━━━━━━━━━┛                                              │   │ │     
                                              │                             ╰────────────────────────────────────────────────────────╮ │   │ │     
                                              ╰────────╮                                                                             │ │   │ │     
                                                       │     ╭───────────────────────────────────────────────────────────────────╮   │ │   │ │     
                                                       │     │    ╭──────────────────────────────────────────────────────────────┼───┼─┼─╮ │ │     
                                                       ▼     ▼    ▼                                                              │   │ │ │ │ │     
                                                ┏━ B9 ↻ 0x401436━━━━━━━━━┓                                                       │   │ │ │ │ │     
                                                ┃  63│ sockaddr_in clie… ┃                                                       │   │ │ │ │ │     
                                                ┃ mov    QWORD PTR [rbp… ┃                                                       │   │ │ │ │ │     
                                                ┃ mov    QWORD PTR [rbp… ┃                                                       │   │ │ │ │ │     
                                                ┃ mov    DWORD PTR [rbp… ┃                                                       │   │ │ │ │ │     
                                                ┃ lea    rdx, [rbp-0x44… ┃                                                       │   │ │ │ │ │     
                                                ┃ ⋮ +7 more              ┃                                                       │   │ │ │ │ │     
                                                ┃ jns    → B14           ┃                                                       │   │ │ │ │ │     
                                                ┗━━━━━━━━┳━━━━━━┳━━━━━━━━┛                                                       │   │ │ │ │ │     
                                                         │      ╰───────────╮                                                    │   │ │ │ │ │     
                                              ╭──────────╯                  │                                                    │   │ │ │ │ │     
                                              ▼                             ▼                                                    │   │ │ │ │ │     
                                 ┏━ B10 0x401483 ━━━━━━━━━┓    ┏━ B14 0x4014c8 ━━━━━━━━━┓                                        │   │ │ │ │ │     
                                 ┃  68│ if (errno == EWO… ┃    ┃  78│ make_non_blockin… ┃                                        │   │ │ │ │ │     
                                 ┃ call   __errno_locati… ┃    ┃ mov    eax, DWORD PTR… ┃                                        │   │ │ │ │ │     
                                 ┃ mov    eax, DWORD PTR… ┃    ┃ mov    edi, eax        ┃                                        │   │ │ │ │ │     
                                 ┃ cmp    eax, 0xb        ┃    ┃ call   make_non_block… ┃                                        │   │ │ │ │ │     
                                 ┃ je     → B12           ┃    ┃ mov    esi, 0x402091   ┃                                        │   │ │ │ │ │     
                                 ┗━━━━━━━━┳━━━━━━┳━━━━━━━━┛    ┃ mov    edi, 0x4040c0   ┃                                        │   │ │ │ │ │     
                                          │      │             ┃ call   std::basic_ost… ┃                                        │   │ │ │ │ │     
                                          │      │             ┗━━━━━━━━━━━━┳━━━━━━━━━━━┛                                        │   │ │ │ │ │     
                                          │      ╰──────────────────────────┼────────────────────────────────────────────╮       │   │ │ │ │ │     
                                          ╰───╮                             │                                            │       │   │ │ │ │ │     
                                              │                         ╭───╯                                            │       │   │ │ │ │ │     
                                              │                         │      ╭─────────────────────────────────────────┼─────╮ │   │ │ │ │ │     
                                              ▼                         ▼      ▼                                         │     │ │   │ │ │ │ │     
                                 ┏━ B11 0x40148f ━━━━━━━━━┓    ┏━ B15 ↻ 0x4014e━━━━━━━━━┓                                │     │ │   │ │ │ │ │     
                                 ┃  68│ if (errno == EWO… ┃    ┃  83│ ssize_t bytes_re… ┃                                │     │ │   │ │ │ │ │     
                                 ┃ call   __errno_locati… ┃    ┃ lea    rsi, [rbp-0x41… ┃                                │     │ │   │ │ │ │ │     
                                 ┃ mov    eax, DWORD PTR… ┃    ┃ mov    eax, DWORD PTR… ┃                                │     │ │   │ │ │ │ │     
                                 ┃ cmp    eax, 0xb        ┃    ┃ mov    ecx, 0x0        ┃                                │     │ │   │ │ │ │ │     
                                 ┃ jne    → B13           ┃    ┃ mov    edx, 0x400      ┃                                │     │ │   │ │ │ │ │     
                                 ┗━━━━━━━━┳━━━━━━┳━━━━━━━━┛    ┃ ⋮ +4 more              ┃                                │     │ │   │ │ │ │ │     
                                          │      │             ┃ jns    → B19           ┃                                │     │ │   │ │ │ │ │     
                                          │      │             ┗━━━━━━━━┳━━━━━━┳━━━━━━━━┛                                │     │ │   │ │ │ │ │     
                   ╭──────────────────────┼──────┼──────────────────────┼──────┼─────────────────────────────────────────╯     │ │   │ │ │ │ │     
                   │                      │      ╰──────────────────────┼──────┼──────────────────────────╮                    │ │   │ │ │ │ │     
            ╭──────┼──────────────────────╯                             │      │                          │                    │ │   │ │ │ │ │     
            │      │                                                    │   ╭──╯                          │                    │ │   │ │ │ │ │     
            │      │                          ╭─────────────────────────╯   │                             │                    │ │   │ │ │ │ │     
            ▼      ▼                          ▼                             ▼                             ▼                    │ │   │ │ │ │ │     
   ┏━ B12 0x40149b ━━━━━━━━━┓    ┏━ B16 0x401513 ━━━━━━━━━┓    ┏━ B19 0x401537 ━━━━━━━━━┓    ┏━ B13 0x4014a7 ━━━━━━━━━┓        │ │   │ │ │ │ │     
   ┃  70│ usleep(100000); … ┃    ┃  85│ if (errno == EWO… ┃    ┃  92│ } else if (bytes… ┃    ┃  73│ perror("accept f… ┃        │ │   │ │ │ │ │     
   ┃ mov    edi, 0x186a0    ┃    ┃ call   __errno_locati… ┃    ┃ cmp    QWORD PTR [rbp… ┃    ┃ mov    edi, 0x402083   ┃        │ │   │ │ │ │ │     
   ┃ call   usleep          ┃    ┃ mov    eax, DWORD PTR… ┃    ┃ jne    → B21           ┃    ┃ call   perror          ┃        │ │   │ │ │ │ │     
   ┃ jmp    → B9            ┃    ┃ cmp    eax, 0xb        ┃    ┗━━━━━━━━┳━━━━━━┳━━━━━━━━┛    ┃ mov    eax, DWORD PTR… ┃        │ │   │ │ │ │ │     
   ┗━━━━━━━━━━━━┳━━━━━━━━━━━┛    ┃ je     → B23           ┃             │      │             ┃ mov    edi, eax        ┃        │ │   │ │ │ │ │     
                │                ┗━━━━━━━━┳━━━━━━┳━━━━━━━━┛             │      │             ┃ ⋮ +2 more              ┃        │ │   │ │ │ │ │     
                │                         │      │                      │      │             ┃ jmp    → B24           ┃        │ │   │ │ │ │ │     
                │                         │      │                      │      │             ┗━━━━━━━━━━━━┳━━━━━━━━━━━┛        │ │   │ │ │ │ │     
                │                         │      │                      ├──────┼──────────────────────────┼────────────────────┼─┼───┼─┼─┼─┼─╯     
                │                         │      │                      │   ╭──┼──────────────────────────┼────────────────────┼─┼───┼─┼─┼─╯       
                │                         │      │                      │   │  ├──────────────────────────┼────────────────────┼─┼───┼─╯ │         
                │                         │      │                      │   │  │   ╭──────────────────────┼────────────────────┼─┼───╯   │         
                ╰─────────────────────────┼──────┼──────────────────────┼───┼──┼───┼──────────────────────┼────────────────────┼─╯       │         
                                          │      │                  ╭───┼───┼──┼───┼──────────────────────╯                    │         │         
                                          │      ╰──────────────────┼───┼───┼──┼───┼───────────────────────────────────────────┼───╮     │         
                                          ╰───╮                     │   │   │  │   │                                           │   │     │         
                                              │                     │   │   │  ├───┼──────────────────────╮                    │   │     │         
                ╭─────────────────────────────┼─────────────────────┼───┤   │  │   │                      │                    │   │     │         
                ▼                             ▼                     ▼   ▼   ▼  ▼   ▼                      ▼                    │   │     │         
   ┏━ B20 0x401541 ━━━━━━━━━┓    ┏━ B17 0x40151f ━━━━━━━━━┓    ┏━ B24 0x4015a3 ━━━━━━━━━┓    ┏━ B21 0x401552 ━━━━━━━━━┓        │   │     │         
   ┃  94│ std::cout << "Cl… ┃    ┃  85│ if (errno == EWO… ┃    ┃ 111│ }                 ┃    ┃  99│ ssize_t bytes_se… ┃        │   │     │         
   ┃ mov    esi, 0x4020b3   ┃    ┃ call   __errno_locati… ┃    ┃ mov    rdx, QWORD PTR… ┃    ┃ mov    rdx, QWORD PTR… ┃        │   │     │         
   ┃ mov    edi, 0x4040c0   ┃    ┃ mov    eax, DWORD PTR… ┃    ┃ sub    rdx, QWORD PTR… ┃    ┃ lea    rsi, [rbp-0x41… ┃        │   │     │         
   ┃ call   std::basic_ost… ┃    ┃ cmp    eax, 0xb        ┃    ┃ je     → B26           ┃    ┃ mov    eax, DWORD PTR… ┃        │   │     │         
   ┃ jmp    → B23           ┃    ┃ je     → B23           ┃    ┗━━━━━━━━┳━━━━━━┳━━━━━━━━┛    ┃ mov    ecx, 0x0        ┃        │   │     │         
   ┗━━━━━━━━━━━━┳━━━━━━━━━━━┛    ┗━━━━━━━━┳━━━━━━┳━━━━━━━━┛             │      │             ┃ ⋮ +4 more              ┃        │   │     │         
                │                         │      │                      │      │             ┃ jns    → B15           ┃        │   │     │         
                │                         │      │                      │      │             ┗━━━━━━━━┳━━━━━━┳━━━━━━━━┛        │   │     │         
                │                         │      ╰──────────────────────┼──────┼──────────────────────┼──────┼─────────────╮   │   │     │         
                │                         ╰───╮                         │      │                      │      │             │   │   │     │         
                ╰─────────────────────────────┼─────────────────────────┼──────┼──────────────────────┼──────┼─────────────┼─╮ │   │     │         
                                              │                         │      │                      │      ╰─────────────┼─┼─╯   │     │         
                                              │                         │   ╭──┼──────────────────────╯                    │ │     │     │         
                                              │                         │   │  ╰──────────────────────────╮                │ │     │     │         
                ╭─────────────────────────────┼─────────────────────────╯   │                             │                │ │     │     │         
                ▼                             ▼                             ▼                             ▼                │ │     │     │         
   ┏━ B25 ■ 0x4015b━━━━━━━━━┓    ┏━ B18 0x40152b ━━━━━━━━━┓    ┏━ B22 0x401587 ━━━━━━━━━┓    ┏━ B26 ■ 0x4015b━━━━━━━━━┓    │ │     │     │         
   ┃ 111│ }                 ┃    ┃  89│ perror("recv err… ┃    ┃ 101│ perror("send err… ┃    ┃ 111│ }                 ┃    │ │     │     │         
   ┃ call   __stack_chk_fa… ┃    ┃ mov    edi, 0x4020a8   ┃    ┃ mov    edi, 0x4020c9   ┃    ┃ leave                  ┃    │ │     │     │         
   ┗━━━━━━━━━━━━━━━━━━━━━━━━┛    ┃ call   perror          ┃    ┃ call   perror          ┃    ┃ ret                    ┃    │ │     │     │         
                                 ┃ jmp    → B23           ┃    ┗━━━━━━━━━━━━┳━━━━━━━━━━━┛    ┗━━━━━━━━━━━━━━━━━━━━━━━━┛    │ │     │     │         
                                 ┗━━━━━━━━━━━━┳━━━━━━━━━━━┛                 │                                              │ │     │     │         
                                              │                 ╭───────────┼──────────────────────────────────────────────┼─┼─────╯     │         
                                              │                 │   ╭───────┼──────────────────────────────────────────────╯ │           │         
                                              ╰──────╮          │   │       │                                                │           │         
                                                     │       ╭──┼───┼───────┼────────────────────────────────────────────────╯           │         
                                                     │   ╭───┼──┼───┼───────╯                                                            │         
                                                     ▼   ▼   ▼  ▼   ▼                                                                    │         
                                                ┏━ B23 0x401591 ━━━━━━━━━┓                                                               │         
                                                ┃ 106│ close(client_fd)… ┃                                                               │         
                                                ┃ mov    eax, DWORD PTR… ┃                                                               │         
                                                ┃ mov    edi, eax        ┃                                                               │         
                                                ┃ call   close           ┃                                                               │         
                                                ┃ jmp    → B9            ┃                                                               │         
                                                ┗━━━━━━━━━━━━┳━━━━━━━━━━━┛                                                               │         
                                                             ╰───────────────────────────────────────────────────────────────────────────╯         
                                                                                                                                                   
 ━ fall ━ taken ━ jump ━ loop back-edge ◉ signal ▶ entry ■ exit ↻ loop head ◆n findings                                                            
 168 instructions · 27 blocks · 38 edges · 2 loops · max loop depth 2 · audit: clean                                                               
  g++ (Ubuntu 15.2.0-16ubuntu1) 15.2.0  ·  -O0  ·  -g -no-pie
  ```