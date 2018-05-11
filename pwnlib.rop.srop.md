## `pwnlib.rop.srop` — Sigreturn Oriented Programmin

Sigreturn ROP（SROP）

Sigreturn 是一个用于从ESP指向的内存中恢复整个寄存器上下文的syscall（系统调用）。

我们可以在ROP过程中利用这一点去控制那些不便于被gadgets控制的寄存器。主要的注意事项是所有寄存器都需被设置，包括ESP和EIP（或其等效项）。这就意味着，在使用sigreturn帧后，为了使程序可以继续得到执行，我们就必须得相应地设置好堆栈指针。

i386 示例：

让我们使用SROP仅打印出一条信息试试。

```
>>> message = "Hello, World\\n"
```

首先我们创建好示例二进制文件，它的作用只是从栈上读取一些数据，并调用`sigreturn`系统调用。我们还提供了一个值为`int 0x80`的gadget，并在其之后添加一个`exit(0)`。

```
>>> context.clear(arch='i386')
>>> assembly =  'read:'      + shellcraft.read(constants.STDIN_FILENO, 'esp', 1024)
>>> assembly += 'sigreturn:' + shellcraft.sigreturn()
>>> assembly += 'int3:'      + shellcraft.trap()
>>> assembly += 'syscall: '  + shellcraft.syscall()
>>> assembly += 'exit: '     + 'xor ebx, ebx; mov eax, 1; int 0x80;'
>>> assembly += 'message: '  + ('.asciz "%s"' % message)
>>> binary = ELF.from_assembly(assembly)
```

让我们构造好我们的栈帧，让其去调用`write`系统调用，并将message中的内容转储到标准输出流中。

```
>>> frame = SigreturnFrame(kernel='amd64')
>>> frame.eax = constants.SYS_write
>>> frame.ebx = constants.STDOUT_FILENO
>>> frame.ecx = binary.symbols['message']
>>> frame.edx = len(message)
>>> frame.esp = 0xdeadbeef
>>> frame.eip = binary.symbols['syscall']
```

让我们开始执行这个进程，向其发送数据，然后检查message中的内容。

```
>>> p = process(binary.path)
>>> p.send(str(frame))
>>> p.recvline()
'Hello, World\n'
>>> p.poll(block=True)
0
```

amd64示例：

```
>>> context.clear()
>>> context.arch = "amd64"
>>> assembly =  'read:'      + shellcraft.read(constants.STDIN_FILENO, 'rsp', 1024)
>>> assembly += 'sigreturn:' + shellcraft.sigreturn()
>>> assembly += 'int3:'      + shellcraft.trap()
>>> assembly += 'syscall: '  + shellcraft.syscall()
>>> assembly += 'exit: '     + 'xor rdi, rdi; mov rax, 60; syscall;'
>>> assembly += 'message: '  + ('.asciz "%s"' % message)
>>> binary = ELF.from_assembly(assembly)
>>> frame = SigreturnFrame()
>>> frame.rax = constants.SYS_write
>>> frame.rdi = constants.STDOUT_FILENO
>>> frame.rsi = binary.symbols['message']
>>> frame.rdx = len(message)
>>> frame.rsp = 0xdeadbeef
>>> frame.rip = binary.symbols['syscall']
>>> p = process(binary.path)
>>> p.send(str(frame))
>>> p.recvline()
'Hello, World\n'
>>> p.poll(block=True)
0
```

arm 示例：

```
>>> context.clear()
>>> context.arch = "arm"
>>> assembly =  'read:'      + shellcraft.read(constants.STDIN_FILENO, 'sp', 1024)
>>> assembly += 'sigreturn:' + shellcraft.sigreturn()
>>> assembly += 'int3:'      + shellcraft.trap()
>>> assembly += 'syscall: '  + shellcraft.syscall()
>>> assembly += 'exit: '     + 'eor r0, r0; mov r7, 0x1; swi #0;'
>>> assembly += 'message: '  + ('.asciz "%s"' % message)
>>> binary = ELF.from_assembly(assembly)
>>> frame = SigreturnFrame()
>>> frame.r7 = constants.SYS_write
>>> frame.r0 = constants.STDOUT_FILENO
>>> frame.r1 = binary.symbols['message']
>>> frame.r2 = len(message)
>>> frame.sp = 0xdead0000
>>> frame.pc = binary.symbols['syscall']
>>> p = process(binary.path)
>>> p.send(str(frame))
>>> p.recvline()
'Hello, World\n'
>>> p.wait_for_close()
>>> p.poll(block=True)
0
```

Mips 示例：

```
>>> context.clear()
>>> context.arch = "mips"
>>> context.endian = "big"
>>> assembly =  'read:'      + shellcraft.read(constants.STDIN_FILENO, '$sp', 1024)
>>> assembly += 'sigreturn:' + shellcraft.sigreturn()
>>> assembly += 'syscall: '  + shellcraft.syscall()
>>> assembly += 'exit: '     + shellcraft.exit(0)
>>> assembly += 'message: '  + ('.asciz "%s"' % message)
>>> binary = ELF.from_assembly(assembly)
>>> frame = SigreturnFrame()
>>> frame.v0 = constants.SYS_write
>>> frame.a0 = constants.STDOUT_FILENO
>>> frame.a1 = binary.symbols['message']
>>> frame.a2 = len(message)
>>> frame.sp = 0xdead0000
>>> frame.pc = binary.symbols['syscall']
>>> p = process(binary.path)
>>> p.send(str(frame))
>>> p.recvline()
'Hello, World\n'
>>> p.poll(block=True)
0
```

> *class*  **pwnlib.rop.srop.SigreturnFrame**(*a, **kw)[[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/rop/srop.py)

制作一个带值的sigreturn帧，这些值将被加载进寄存器中。

**Parameters：**

**arch** ([*str*](https://docs.python.org/2.7/library/functions.html#str)) – 架构。目前支持`i386` 和`amd64`。

**Examples**

制作一个在amd64上调用mprotect系统调用（mprotect函数可用于修改一段指定内存区域的保护属性）的SigreturnFrame。

```
>>> context.clear(arch='amd64')
>>> s = SigreturnFrame()
>>> unpack_many(str(s))
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 51, 0, 0, 0, 0, 0, 0, 0]
>>> assert len(s) == 248
>>> s.rax = 0xa
>>> s.rdi = 0x00601000
>>> s.rsi = 0x1000
>>> s.rdx = 0x7
>>> assert len(str(s)) == 248
>>> unpack_many(str(s))
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6295552, 4096, 0, 0, 7, 10, 0, 0, 0, 0, 51, 0, 0, 0, 0, 0, 0, 0]
```

制作一个在i386上调用mprotect系统调用的SigreturnFrame。

```
>>> context.clear(arch='i386')
>>> s = SigreturnFrame(kernel='i386')
>>> unpack_many(str(s))
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 115, 0, 0, 123, 0]
>>> assert len(s) == 80
>>> s.eax = 125
>>> s.ebx = 0x00601000
>>> s.ecx = 0x1000
>>> s.edx = 0x7
>>> assert len(str(s)) == 80
>>> unpack_many(str(s))
[0, 0, 0, 0, 0, 0, 0, 0, 6295552, 7, 4096, 125, 0, 0, 0, 115, 0, 0, 123, 0]
```

制作一个在ARM上调用mprotect系统调用的SigreturnFrame。

```
>>> s = SigreturnFrame(arch='arm')
>>> unpack_many(str(s))
[0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1073741840, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1447448577, 288]
>>> s.r0 = 125
>>> s.r1 = 0x00601000
>>> s.r2 = 0x1000
>>> s.r3 = 0x7
>>> assert len(str(s)) == 240
>>> unpack_many(str(s))
[0, 0, 0, 0, 0, 6, 0, 0, 125, 6295552, 4096, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1073741840, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1447448577, 288]
```

制作一个在MIPS上调用mprotect系统调用的SigreturnFrame。

```
>>> context.clear()
>>> context.endian = "big"
>>> s = SigreturnFrame(arch='mips')
>>> unpack_many(str(s))
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
>>> s.v0 = 0x101d
>>> s.a0 = 0x00601000
>>> s.a1 = 0x1000
>>> s.a2 = 0x7
>>> assert len(str(s)) == 296
>>> unpack_many(str(s))
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4125, 0, 0, 0, 6295552, 0, 4096, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
```

制作一个在MIPSel上调用mprotect系统调用的SigreturnFrame。

```
>>> context.clear()
>>> context.endian = "little"
>>> s = SigreturnFrame(arch='mips')
>>> unpack_many(str(s))
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
>>> s.v0 = 0x101d
>>> s.a0 = 0x00601000
>>> s.a1 = 0x1000
>>> s.a2 = 0x7
>>> assert len(str(s)) == 292
>>> unpack_many(str(s))
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4125, 0, 0, 0, 6295552, 0, 4096, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
```

制作一个在Aarch64上调用mprotect系统调用的SigreturnFrame。

```
>>> context.clear()
>>> context.endian = "little"
>>> s = SigreturnFrame(arch='aarch64')
>>> unpack_many(str(s))
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1179680769, 528]
>>> s.x8 = 0xe2
>>> s.x0 = 0x4000
>>> s.x1 = 0x1000
>>> s.x2 = 0x7
>>> assert len(str(s)) == 600
>>> unpack_many(str(s))
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16384, 0, 4096, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 226, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1179680769, 528]
```

> set_regvalue(*reg*, *val*)[[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/rop/srop.py#L455-459)

将一个特定的`reg`的值设定为`val`。
