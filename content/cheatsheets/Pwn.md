---
title: Pwn cheatsheet
date: 2025-02-04
author: Flavien
draft: false
tags:
  - CTF
  - Pwn
  - Cheatsheet
categories:
  - Pwn
  - Cheatsheet
description: All resources and information useful for Pwn challenges
summary: All resources and information useful for Pwn challenges
---
## `GDB`
Many different useful commands to know to work with `GDB`:
- `start`: start the program with a breakpoint at `main` or `start`
- `ni`: next instruction
- `si`: step instruction
- `x/[%d][ixdsb]{Address}`: display value at memory address
- `b {address}`sets breakpoint at the address
- `run`: runs the binary, stops at breakpoint
- `disassemble {disas}`: disassemble the current function
- `set {address} = {val}`: sets value at the address 
- `heap bins`: shows current heap
- `stack`: shows current stack

## `PWNTOOLS`
Python library with simple socket/process control, has many features:
- `shellcode`
- Address lookup
- Easy `GBD`interaction
- ...
Can also use the `cyclic`utility of `pwntools` to find out the size of the buffer we're trying to overflow:

```bash
cyclic 100 # gives 100 random character
cyclic -l iaaa # finds the index of this sequence
```

### Example
To overflow a buffer of 48 characters, we can use the following `exploit.py` file:

```python
from pwn import *

p = process('./a.out')

gdb.attach(p)
p.sendLine('a'*48 + p32(0xcafebabe))

p.interactive()
```

## Buffer overflows
Either `Stack`based or `Heap`based --> occurs from miscalculations and can cause too much data to be read in.
--> We can check what security are enabled on a binary with:

```bash
checksec mc
[*] '/home/test/minio-binaries/mc'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```


## Resources
- [`pwnable.tw`](https://pwnable.tw/)
- [`pwnable.kr`](http://pwnable.kr/)
- [`Temple of pwn`](https://www.youtube.com/watch?v=TqGMVRV2l9s&list=PLiCcguURxSpbD9M0ha-Mvs-vLYt-VKlWt)
- 
