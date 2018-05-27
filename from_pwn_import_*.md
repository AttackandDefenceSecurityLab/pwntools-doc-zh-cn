from pwn import *

您会发现使用pwntools最普遍的方式是

    >>> from pwn import *

这将导入成千上万有用的东西至全局名称空间，简化您的生活。以下是绝大部分导入对象和例程的简要列表，按重要性和使用频率进行了粗略的排列。

- pwnlib.context
  - pwnlib.context.context
  - 负责便捷地配置pwntools的大部分设置项
  - 当执行漏洞遇到异常时，设置context.log_level='debug'
  - 具有作用域限制，因此您可以通过Context.local()来禁用代码段的日志记录
- remote,listen,ssh,process
  - pwnlib.tubes
  - 将CTF参赛者所用的常用功能进行了超级方便的封装
  - 连接至任何地方，任何设备，并且会按照你设想的方式运作
  - 日常任务的助手，如recvline,recvuntil,clean等
  - 通过.interactive()与应用进行直接地交互
- p32和u32
  - pwnlib.util.packing
  - 一个有用的功能，struct.pack让您不再需要死记硬背>是有符号比较还是无符号的，同时摒弃了丑陋的[0]索引
  - 通过设置signed和endian来达同样的功能（也可以通过设置context完成，一劳永逸）
  - 为常见的位宽进行了预声明（u8,u64等），并且pwnlib.util.packing.pack()让您可以自定义位宽
- log
  - pwnlib.log
  - 让您的输出更加清晰明了！
- cyclic和cyclic_func
  - pwnlib.util.cyclic
  - 用于生成字符串的实用程序，以便于您找到给定子字串的偏移量（通常为4字节的倍数）。这对于缓冲区直接溢出非常有用。相比于直接显示的0x41414141，您可以通过0x61616171更好地了解您通过从缓冲区偏移64字节来控制EIP
- asm和disasm
  - pwnlib.asm
  - 快速地将汇编转换成字节码，反之亦然，无需担心混淆的问题
  - 支持任何一个您已安装相应构建工具的CPU架构
  - 从ppa:pwntools/binutils获取预构建的超过20个不同目标架构的二进制文件
- shellcraft
  - pwnlib.shellcraft
  - 准备就绪的shellcode库
  - 使用asm(shellcraft.sh())来获取一个shell
  - 可重用的shellcode片段模版
- ELF
  - pwnlib.elf
  - ELF二进制文件操作工具，包括符号查找、虚拟内存至文件偏移的辅助，以及修改及保存二进制文件至本地的能力
- DynELF
  - pwnlib.dynelf
  - 通过一个给定的指向任意已加载模块的指针，动态解析函数表并返回任何导致数据泄露的函数
- ROP
  - pwnlib.rop
  - 使用DSL自动生成ROP而不是原始地址来执行您想执行的操作
- gdb.debug和gdb.attach
  - pwnlib.gdb
  - 在GDB环境下启动一个二进制文件，并弹出一个新的终端与其交互。自动设置断点，并更快地对进行漏洞的迭代
  - 或者通过给定的一个PID，pwnlib.tubes对象，甚至是一个连接到程序的套接字来连接到正在运行的进程
- args
  - 一个字典，包含所有大写的命令行参数以提供快速访问的功能
  - 通过python foo.py REMOTE=1和args['remote'] == '1'来执行
  - 还可以控制日志的详细度和终端的灵活性
    - NOTERM
    - SILENT
    - DEBUG
- radoms,rol,ror,xor,bits
  - pwnlib.util.fiddling
  - 用于从给定的字母表生成随机数据的有用工具，或者简化那些被0xffffffff混淆，或者需要用ord()和chr()来进行转换的数学运算
- net
  - pwnlib.net
  - 查询网络接口的例程
- proc
  - pwnlib.util.proc
  - 查询进程的例程
- pause
  - 新版getch
- safeeval
  - pwnlib.util.safeeval
  - 安全地执行python代码，不需担心额外的影响

以下模块“行如其名”，但在全局名称空间依然十分重要

- hexdump
- read和write
- enhex和unhex
- more
- group
- align和align_down
- urlencode和urldecode
- which
- wget

另外，以下模块已自动为您包含。您可以随心所欲调用。

- os
- sys
- time
- requests
- re
- radom
