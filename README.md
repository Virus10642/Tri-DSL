Tri: A Domain-Specific Language for Trinary-Themed x86 Assembly


Tri is a compact, single-file ANSI C compiler designed to transform a high-level DSL into raw x86 machine code. Blending real-mode tape memory manipulation, scoped borrowing (inspired by Rust), and Pythonic syntax, Tri emits precise binaries from a minimalist source format with hardened error handling and tight memory safety.


---


Language Philosophy


Tri is built around three pillars:


- Safety  
  Structured borrow semantics, bounds-checked buffers, and immediate-range validation eliminate silent failures and undefined behavior.


- Simplicity  
  A readable DSL with familiar function-call syntax compiles directly into assembler primitives without macro layers or runtime dependencies.


- Minimal Footprint  
  Just one C file (~400 LOC) compiles down to ~6 KB (with -Os -s + strip + UPX). No external libraries required.


---


Language Concepts


| Concept        | Description                                                |
| -------------- | ---------------------------------------------------------- |
| Tape Memory    | A flat byte array starting at 0x500:0x0000 accessed via SI |
| Head Pointer   | SI register — tracks current cell on the tape             |
| Borrowing      | Scoped exclusive or shared access to tape (let &mut, let &) |
| Scopes         | Braces { … } isolate borrow frames and reset on exit    |


---


Syntax Overview


- Line-oriented: one statement per line (max 80 characters)  
- Case-insensitive: db, DB, Db() all parsed identically  
- Comments: any line starting with ; is ignored  
- Blank lines: skipped automatically  
- Labels: must end in : and be unique  


---


Borrowing & Scopes


`asm
{              ; Begin borrow scope
  let &mut     ; Exclusive mutable borrow
  tape_start() ; Move SI to tape base
  load()       ; Read [SI] into AL
}
{              ; New scope
  let &        ; Shared borrow — multiple allowed
  head += 1
  store()
}
`


- let &mut disallowed if any borrow is active in scope  
- let & disallowed if a mutable borrow is active  
- Unmatched {} or multiple conflicting borrows trigger compile-time errors  
- All borrow state is reset when leaving a scope


---


Built-In Primitives


| DSL Statement   | Emits            | Description                     |
| --------------- | ---------------- | -------------------------------- |
| tape_start()  | ORG + MOV SI     | Set SI = 0x500                |
| load()        | DB 0x8A, 0x04  | MOV AL, [SI]                  |
| store()       | DB 0x88, 0x04  | MOV [SI], AL                  |
| head += N     | DB 0x83,0xC6,N | ADD SI, imm8 (0 ≤ N ≤ 255)   |


Immediate values are strictly checked to ensure safe range.


---


Python-Style DSL Directives


Tri supports ergonomic function-like syntax:


| DSL Call           | Translates To        | Example                        |
| ------------------ | -------------------- | ------------------------------ |
| db(0x90, 0x90)   | DB 0x90, 0x90      | Insert NOPs                    |
| fill(16, 0x00)   | FILL 16 0x00       | Zero pad                       |
| org(0x7C00)      | ORG 0x7C00         | Set base address               |
| int(0x10)        | INT 0x10           | BIOS call                      |
| jmp(label)       | JMP label          | Relative jump                  |
| call(label)      | CALL label         | Relative call                  |
| ljmp(seg, off)   | LJMP off:seg       | Far jump (EA opcode)           |


Syntax is flexible and forgiving: optional whitespace, mixed case, and clean auto-conversion.


---


; === Fold and power ===
.macro FOLD(n)           fold_mode(n)
.macro GATE(u,op)        power_gate(u,op)

; === BIST ===
.macro BIST(id)          bist_start(id) ; followed by a poll loop in tape

; === SMT weight ===
.macro WEIGHT(t,w)       smt_weight(t,w)

; === Mem-move ===
; args: sCap,dCap,size,srcStr,dstStr,flags,mask
.macro MME(s,d,sz,ss,ds,fl,msk)
  mme(s,d,sz,ss,ds,fl,msk)
.endm

; === Patch ===
.macro PATCH_BEGIN(bank,flags)  patch_bank(bank,flags)
.macro PATCH_COMMIT(crc)        patch_commit(crc)

; === Perf ===
.macro PMC(op,evt,slot)         perf_sample(op,evt,slot)

; === Link ===
.macro LINKCFG(ch,mode,flags)   link_config(ch,mode,flags)


---


Labels & Control Flow


`asm
start:               ; Label definition
  load()
  call(continue)


continue:
  store()
  jmp(start)
`


- All labels must be globally unique  
- Relative offsets for CALL, JMP are calculated precisely  
- Duplicate or missing labels halt compilation with source diagnostics


---


Error Diagnostics


Errors are contextual and precise:


`txt
Error at source line 7: borrow conflict
    let &mut
`


`txt
Error at source line 11: immediate out of range
    head += 512
`


- Out-of-range values, malformed numerics, unbalanced scopes, unknown tokens, and bad label usage are all caught  
- Each error includes:
  - Source line number  
  - Offending line text  
  - Description of failure  


---


Compilation Stages


1. DSL Parsing (pass1):  
   - Reads and transforms source lines  
   - Tracks scope/borrowing  
   - Builds intermediate assembly (asm1[])


2. Label Resolution (passA):  
   - Copies into lines2[]  
   - Records label addresses  
   - Precomputes PC offsets


3. Binary Emission (passB):  
   - Generates out.bin byte-by-byte  
   - Resolves jumps and calls  
   - Frees all dynamic memory  


Each line retains mapping between DSL source → intermediate ASM → final binary.


---


 Example Program: BIOS Hello Loop


`asm
org(0x7C00)


{ let &mut
  tape_start()
  head += 0
  db(0x41)       ; 'A'
  fill(9, 0x41)
}


loop:
  load()
  int(0x10)      ; BIOS: print AL
  jmp(loop)
`


Compile with:


`bash
./tri hello.tasm
`


Output: out.bin (bootable segment starting at 0x7C00)


---


FAQ


Q: Can I use negative numbers like head += -1?  
No. All immediates must be unsigned bytes (0 to 255). Negative values will cause a parse error.


Q: Can I mix assembler and DSL primitives in one scope?  
Yes — db(), int(), labels, and built-ins coexist naturally.


Q: Is label resolution forward and backward compatible?  
Yes. Labels are collected in pass A; all references are patched in pass B.


Q: Are nested scopes supported?  
Yes — up to 16 levels deep. Each scope resets its own borrow frame.


---


Building Tri


Requirements:
- GCC or Clang with C99
- Optional: make, upx


Compile manually:


`bash
gcc -std=c99 -Os -s tri.c -o tri
strip tri
upx --best tri
`


Or use:


`bash
make
`


---


Contributing


This version of Tri marks the foundation for future expansion. PRs are welcome for:


- New built-in DSL primitives  
- Enhancements to syntax or diagnostics  
- Documentation or example programs  
- Integration with loaders, VMs, or boot frameworks


Please maintain clean ANSI C, document new features, and include sample .tasm files.
