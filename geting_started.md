# 入门
让我们通过几个例子来让您对pwntools进行最初的接触。在编写漏洞时，pwntools通常遵循“厨房水槽”方法。

```python
>>> from pwn import *
```

这将大量功能导入到全局名称空间中。您现在可以对单一功能进行组装，拆卸，打包，解包和其他更多操作。使用`from pwn import *`来导入所有的功能。


# 创建链接
您需要通过与目标二进制文件进行交互以执行漏洞，对吗？pwntools的`pwnlib.tubes`模块将这个复杂的过程简化了。
该模块暴露了一个用于与进程、套接字、串行端口和其他途径进行通讯的标准接口，以及一些用于常见任务的辅助模块。例如，通过`pwnlib.tubes.remote`模块进行远程连接

```python
>>> conn = remote('ftp.ubuntu.org',21)
>>> conn.recvline() 
'220 ...'
>>> conn.send('USER anonymous\r\n')
>>> conn.recvuntil(' ', drop=True)
'331'
>>> conn.recvline()
'Please specify the password.\r\n'
>>> conn.close()
```

启动监听模块亦十分简单

```python
>>> l = listen()
>>> r = remote('localhost', l.lport)
>>> c = l.wait_for_connection()
>>> r.send('hello')
>>> c.recv()
'hello'
```

`pwnlib.tubes.process`模块简化了与进程交互的过程

```python
>>> sh = process('/bin/sh')
>>> sh.sendline('sleep 3; echo hello world;')
>>> sh.recvline(timeout=1)
''
>>> sh.recvline(timeout=5)
'hello world\n'
>>> sh.close()
```

您不仅可以通过编写既定指令的方式与进程交互，还可以与进程进行实时交互

```python
>>> sh.interactive() 
$ whoami
user
```

当您需要通过SSH进入一个沙盒时，甚至还有一个SSH模块，你可以利用`pwnlib.tubes.ssh`执行本地/提权攻击时。您可以快速执行程序并获取输出，或者生成一个进程，并像类似过程管道的方式与其交互。

```python
>>> shell = ssh('bandit0', 'bandit.labs.overthewire.org', password='bandit0', port=2220)
>>> shell['whoami']
'bandit0'
>>> shell.download_file('/etc/motd')
>>> sh = shell.run('sh')
>>> sh.sendline('sleep 3; echo hello world;') 
>>> sh.recvline(timeout=1)
''
>>> sh.recvline(timeout=5)
'hello world\n'
>>> shell.close()
```

# 封装整型
漏洞编写者的一个日常任务是将整型从通常形式转换成字节序列。通常人们使用内置的模块来完成此过程。
pwntools使用`pwnlib.util.pacing`模块简化了转换过程。不再需要记住更多的模块解包代码，使用该模块来简化你的代码

```python
>>> import struct
>>> p32(0xdeadbeef) == struct.pack('I', 0xdeadbeef)
True
>>> leet = '37130000'.decode('hex')
>>> u32('abcd') == struct.unpack('I', 'abcd')[0]
True
```

这种打包/解包的操作为多种常见位宽进行了定义

```python
>>> u8('A') == 0x41
True
```

# 设置目标处理器架构和系统
可以为目标指令指定所需体系结构参数。

```python
>>> asm('nop')
'\x90'
>>> asm('nop', arch='arm')
'\x00\xf0 \xe3'
```

不过，这项操作可以通过设置全局的`context`一次性解决。目标操作系统、位宽和大小端都可以在此进行设置。

```python 
>>> context.arch      = 'i386'
>>> context.os        = 'linux'
>>> context.endian    = 'little'
>>> context.word_size = 32
```

另外，您可以使用简写来一次设置所有值。

```python
>>> asm('nop')
'\x90'
>>> context(arch='arm', os='linux', endian='big', word_size=32)
>>> asm('nop')
'\xe3 \xf0\x00'
```

# 日志设置项
您可以通过设置`context`的值来控制pwntools的日志记录。例如，设置

```python
>>> context.log_level = 'debug'
```

将导致所有通过`tube`发送/接收的数据输出到屏幕上

# 汇编和反汇编
再也不需要从互联网上运行一些已经组装好的shellcode了！`pwnlib.asm`模块意义非凡。

```python
>>> asm('mov eax, 0').encode('hex')
'b800000000'
```

反汇编亦如此简单

```python 
>>> print disasm('6a0258cd80ebf9'.decode('hex'))
   0:   6a 02                   push   0x2
   2:   58                      pop    eax
   3:   cd 80                   int    0x80
   5:   eb f9                   jmp    0x0
```

不过，大部分时间你并不需要编写自己的shellcode！pwntools包含了`pwnlib.shellcraft`模块，可以用来加载有效省时的shellcode.
假设我们想在`setreuid(getuid(),getuid())`后添加输出文件描述的的操作，然后反弹一个shell！

```python
>>> asm(shellcraft.setreuid() + shellcraft.dupsh(4)).encode('hex') 
'6a3158cd80...'
```

# 杂项工具
感谢`pwnlib.util.fiddling`，我们不再需要编写十六进制编码了。
使用`pwnlib.cyclic`模块来在缓冲区中找到导致崩溃的偏移量

```python
>>> print cyclic(20)
aaaabaaacaaadaaaeaaa
>>> # Assume EIP = 0x62616166 ('faab' which is pack(0x62616166))  at crash time
>>> print cyclic_find('faab')
120
```

# ELF文件操作
抛弃硬编码的东西吧!使用`pwnlib.elf`来与它们进行实时的交互

```python 
>>> e = ELF('/bin/cat')
>>> print hex(e.address) 
0x400000
>>> print hex(e.symbols['write']) 
0x401680
>>> print hex(e.got['write']) 
0x60b070
>>> print hex(e.plt['write']) 
0x401680
```

你甚至可以更改文件并保存

```python
>>> e = ELF('/bin/cat')
>>> e.read(e.address, 4)
'\x7fELF'
>>> e.asm(e.address, 'ret')
>>> e.save('/tmp/quiet-cat')
>>> disasm(file('/tmp/quiet-cat','rb').read(1))
'   0:   c3                      ret'
```





