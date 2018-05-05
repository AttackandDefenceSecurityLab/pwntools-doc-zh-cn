## `pwnlib.asm` - 汇编函数

用于汇编和反汇编代码的实用工具。

###架构选择

使用`pwnlib.context`选择架构，字节顺序和字长。

任何可以指定给`context`的参数也可以指定为`asm()`或`disasm()`的关键字参数。

###汇编

想要汇编代码，只需要在代码上调用`asm()`进行汇编。
```
>>> asm('mov eax, 0')
'\xb8\x00\x00\x00\x00'
```

此外，你可以使用`pwnlib.constants`模块中定义的常量。

```
>>> asm('mov eax, SYS_execve')
'\xb8\x0b\x00\x00\x00'
```

最后，`asm()`可用于汇编在`shellcraft`模块中由`pwntools`提供的shellcode。

```
>>> asm(shellcraft.nop())
'\x90'
```

###反汇编

想要反汇编代码，只需要在字节上调用`disasm()`进行反汇编。

```
>>> disasm('\xb8\x0b\x00\x00\x00')
'   0:   b8 0b 00 00 00          mov    eax,0xb'
```


>**pwnlib.asm.asm**(_code,vma = 0,extract = True,shared = False, ..._) → str   [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/asm.py#L1388-1395)


在给定的shellcode上运行`cpp()`，然后将其汇编成字节。

想要查看其支持哪些架构或操作系统，可以查阅`pwnlib.contex`。

汇编shellcode需要为目标架构安装GNU汇编器。查看[安装Binutils](https://docs.pwntools.com/en/stable/install/binutils.html)获取更多信息。

**Parameters**:

- **shellcode**(_str_) \- 进行汇编的代码
- **vma**(_int_) \- 汇编起始的虚拟内存地址
- **extract**(_bool_) \- 从汇编文件中提取原始的汇编字节。如果是`False`,则将该路径返回到嵌入式汇编的ELF文件。
- **shared**(_bool_) \- 创建共享对象
- **kwargs**(_dict_) \- `context`的任何属性都可以设置，例如`arch='arm'`

**Examples**

```
>>> asm("mov eax, SYS_select", arch = 'i386', os = 'freebsd')
'\xb8]\x00\x00\x00'
>>> asm("mov eax, SYS_select", arch = 'amd64', os = 'linux')
'\xb8\x17\x00\x00\x00'
>>> asm("mov rax, SYS_select", arch = 'amd64', os = 'linux')
'H\xc7\xc0\x17\x00\x00\x00'
>>> asm("mov r0, #SYS_select", arch = 'arm', os = 'linux', bits=32)
'R\x00\xa0\xe3'
```


>**pwnlib.asm.cpp**(_shellcode, ..._) → str   [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/asm.py#L1388-1395)

在给定的shellcode上运行CPP。

输出结果总是只包含一个换行符。

**Parameters**: **shellcode**(_str_) - Shellcode预处理

**Kwargs**:任何可以在`context`中设置的参数/属性

**Examples**

```
>>> cpp("mov al, SYS_setresuid", arch = "i386", os = "linux")
'mov al, 164\n'
>>> cpp("weee SYS_setresuid", arch = "arm", os = "linux")
'weee (0+164)\n'
>>> cpp("SYS_setresuid", arch = "thumb", os = "linux")
'(0+164)\n'
>>> cpp("SYS_setresuid", os = "freebsd")
'311\n'
```


>**pwnlib.asm.disasm**(_data, ..._) → str   [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/asm.py#L1388-1395)

将字节串反汇编为可读的汇编语言。

想要查看其支持哪些架构，可以查阅`pwnlib.contex`。

为了支持这所有的架构，我们将GNU中的objcopy和objdump集成到pwntools中。

**Parameters**:
- **data**(_str_) - 字节串反汇编
- **vma**(_int_) - 传递给objdump的–adjust-vma参数
- **byte**(_bool_) - 在反汇编中所包含的十六进制打印字节
- **offset**(_bool_) - 在反汇编中所包含的虚拟内存地址

**Kwargs**:任何可以在`context`中设置的参数/属性

**Examples**

```
>>> print disasm('b85d000000'.decode('hex'), arch = 'i386')
   0:   b8 5d 00 00 00          mov    eax,0x5d
>>> print disasm('b85d000000'.decode('hex'), arch = 'i386', byte = 0)
   0:   mov    eax,0x5d
>>> print disasm('b85d000000'.decode('hex'), arch = 'i386', byte = 0, offset = 0)
mov    eax,0x5d
>>> print disasm('b817000000'.decode('hex'), arch = 'amd64')
   0:   b8 17 00 00 00          mov    eax,0x17
>>> print disasm('48c7c017000000'.decode('hex'), arch = 'amd64')
   0:   48 c7 c0 17 00 00 00    mov    rax,0x17
>>> print disasm('04001fe552009000'.decode('hex'), arch = 'arm')
   0:   e51f0004        ldr     r0, [pc, #-4]   ; 0x4
   4:   00900052        addseq  r0, r0, r2, asr r0
>>> print disasm('4ff00500'.decode('hex'), arch = 'thumb', bits=32)
   0:   f04f 0005       mov.w   r0, #5
```


>**pwnlib.asm.make\_elf**(_data, vma=None, strip=True, extract=True, shared=False, \*\*kwargs_) → str   [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/asm.py#L1388-1395)

用指定的二进制数据构建一个ELF文件作为其可执行代码。

**Parameters**:
- **data**(_str_) - 汇编代码
- **vma**(_int_) - ELF文件的加载地址
- **strip**(_bool_) - 删除生成的ELF文件。仅当`extract=False`的情况下。(默认情况：`True`)
- **extract**(_bool_) - 从ELF文件中提取汇编代码。如果为`False`，则返回ELF文件的路径。(默认情况：`True`)
- **shared**(_bool_) - 创建一个可通过`dlopen`或者`LD_PRELOAD`加载的动态共享对象(DSO, i.e. a `.so`)。 

**Examples**

此示例仅仅进行了系统调用创建一个i386 ELF文件(‘/bin/sh’,…)。

```
>>> context.clear(arch='i386')
>>> bin_sh = '6a68682f2f2f73682f62696e89e331c96a0b5899cd80'.decode('hex')
>>> filename = make_elf(bin_sh, extract=False)
>>> p = process(filename)
>>> p.sendline('echo Hello; exit')
>>> p.recvline()
'Hello\n'
```



>**pwnlib.asm.make\_elf\_from\_assembly**(_assembly, vma=None, extract=None, shared=False, strip=False, \*\*kwargs_) → str   [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/asm.py#L1388-1395)

用指定的汇编代码构建一个ELF文件作为其可执行代码。

其与`make_elf()`不同，因为所有的ELF符号都被储存下来，如标签和局部变量。如果非常注重文件的大小，请使用`make_elf()`。另外，其与`make_elf（）`中提取的默认值也是不同的。
- **Note**
    这个实际上是`asm()`的封装。设置`extract=False`,`vma=0x10000000`,并将结果文件标记为可执行文件(`chmod +x`)。
    
- **Note**   
    使用arch=thumb创建的ELF文件会预先准备一个切换到Thumb模式的ARM存根。

**Parameters**:
- **assembly**(_str_) - 汇编代码以构建成ELF 
- **vma**(_int_) - 加载二进制地址(默认情况：`0x10000000`,或者如果`shared=True`则为`0`)
- **extract**(_bool_) - 从文件中提取完整的ELF数据(默认情况：`False`)
- **shared**(_bool_) - 创建一个共享库(默认情况：`False`)
- **kwargs**(_dict_) - 传递给`asm()`的参数。

**Returns**:ELF的汇编路径(extract=False)，或者ELF的汇编数据。

**Example**

此示例显示如何创建共享库，并通过`LD_PRELOAD`加载它。
```
>>> context.clear()
>>> context.arch = 'amd64'
>>> sc = 'push rbp; mov rbp, rsp;'
>>> sc += shellcraft.echo('Hello\n')
>>> sc += 'mov rsp, rbp; pop rbp; ret'
>>> solib = make_elf_from_assembly(sc, shared=1)
>>> subprocess.check_output(['echo', 'World'], env={'LD_PRELOAD': solib})
'Hello\nWorld\n'
```

虽然文件大小是不同的，但`make_elf()`可以与其完成同样的事情。

```
>>> file_a = make_elf(asm('nop'), extract=True)
>>> file_b = make_elf_from_assembly('nop', extract=True)
>>> file_a[:4] == file_b[:4]
True
>>> len(file_a) < 0x200
True
>>> len(file_b) > 0x1000
True
```

###内部函数

这些函数包含在内以便进行测试运行。

正常情况下不需要这些函数。


>**pwnlib.asm.dpkg\_search\_for\_binutils**(_arch, util_) → str   [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/asm.py#L71-102)

使用dpkg搜索任何可用的汇编器。

**Returns**: 推荐的软件包名称列表。

```
>>> pwnlib.asm.dpkg_search_for_binutils('aarch64', 'as')
['binutils-aarch64-linux-gnu']
```


>**pwnlib.asm.print_binutils_instructions**(_util, context_) → str   [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/asm.py#L104-138)

如果找不到可用的binutils程序，通知用户轻松获取它的方式。

**Doctest**:

```
>>> context.clear(arch = 'amd64')
>>> pwnlib.asm.print_binutils_instructions('as', context)
Traceback (most recent call last):
...
PwnlibException: Could not find 'as' installed for ContextType(arch = 'amd64', bits = 64, endian = 'little')
Try installing binutils for this architecture:
$ sudo apt-get install binutils
```