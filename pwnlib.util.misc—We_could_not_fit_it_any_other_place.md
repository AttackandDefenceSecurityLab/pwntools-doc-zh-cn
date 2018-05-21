# pwnlib.util.misc — We could not fit it any other place

### `pwnlib.util.misc.align(`*`alignment, x`*`) → int` [source](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/misc.py#L17-26)

计算`x`到最多为`alignmet`的倍数。

#### 例

```shell
>>> [align(5, n) for n in range(15)]
[0, 5, 5, 5, 5, 5, 10, 10, 10, 10, 10, 15, 15, 15, 15]
```

### `pwnlib.util.misc.align_down(`*`alignment, x`*`) → int` [source](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/misc.py#L29-39)

计算`x`到最接近`alignmet`的倍数。

#### 例

```shell
>>> [align_down(5, n) for n in range(15)]
[0, 0, 0, 0, 0, 5, 5, 5, 5, 5, 10, 10, 10, 10, 10]
```

### `wnlib.util.misc.binary_ip(`*`host`*`) → str` [source](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/misc.py#L42-51)

解析主机并返回四字节字符串的格式的IP。

#### 例

```shell
>>> binary_ip("127.0.0.1")
'\x7f\x00\x00\x01'
```

### `pwnlib.util.misc.dealarm_shell(`*`tube`*`) [source](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/misc.py#L305-320)

给出一个shell形式的`tube`，对其发出警告。

### `pwnlib.util.misc.mkdir_p(`*`path`*`)` [source](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/misc.py#L294-303)

模拟`mkdir -p`的行为。

### `pwnlib.util.misc.parse_ldd_output(`*`output`*`)` [source](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/misc.py#L263-292)

解析"ldd"运行的输出为二进制。返回指定二进制文件所需要的每个库的{path:address}字典。

参数:	output (*str*) – 用于解析的输出。

#### 例

```shell
>>> sorted(parse_ldd_output('''
...     linux-vdso.so.1 =>  (0x00007fffbf5fe000)
...     libtinfo.so.5 => /lib/x86_64-linux-gnu/libtinfo.so.5 (0x00007fe28117f000)
...     libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007fe280f7b000)
...     libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fe280bb4000)
...     /lib64/ld-linux-x86-64.so.2 (0x00007fe2813dd000)
... ''').keys())
['/lib/x86_64-linux-gnu/libc.so.6', '/lib/x86_64-linux-gnu/libdl.so.2', '/lib/x86_64-linux-gnu/libtinfo.so.5', '/lib64/ld-linux-x86-64.so.2']
```

### `pwnlib.util.misc.read(`*`path, count=-1, skip=0`*`) → str` [source](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/misc.py#L104-117)

打开文件并返回内容。

#### 例s

```shell
>>> read('/proc/self/exe')[:4]
'\x7fELF'
```

### `pwnlib.util.misc.register_sizes(`*`regs, in_sizes`*`)` [source](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/misc.py#L322-366)

根据寄存器大小和关系创建字典。

给定关于重叠寄存器的名称（如：[‘eax’,’ax’,’al’,’ah’]）的list和输入大小的list 的一个list，会返回以下内容：

* all_regs : 所有有效寄存器的list。
* sizes[reg] : `reg`的字节大小。
* bigger[reg] : 大于`reg`的所有重叠寄存器的list。
* smaller[reg]: 小于`reg`的所有重叠寄存器的list。

使用i386/AMD64模式的shellcode, 如：mov-shellcode.

#### 例

```shell
>>> regs = [['eax', 'ax', 'al', 'ah'],['ebx', 'bx', 'bl', 'bh'],
... ['ecx', 'cx', 'cl', 'ch'],
... ['edx', 'dx', 'dl', 'dh'],
... ['edi', 'di'],
... ['esi', 'si'],
... ['ebp', 'bp'],
... ['esp', 'sp'],
... ]
>>> all_regs, sizes, bigger, smaller = register_sizes(regs, [32, 16, 8, 8])
>>> all_regs
['eax', 'ax', 'al', 'ah', 'ebx', 'bx', 'bl', 'bh', 'ecx', 'cx', 'cl', 'ch', 'edx', 'dx', 'dl', 'dh', 'edi', 'di', 'esi', 'si', 'ebp', 'bp', 'esp', 'sp']
>>> sizes
{'ch': 8, 'cl': 8, 'ah': 8, 'edi': 32, 'al': 8, 'cx': 16, 'ebp': 32, 'ax': 16, 'edx': 32, 'ebx': 32, 'esp': 32, 'esi': 32, 'dl': 8, 'dh': 8, 'di': 16, 'bl': 8, 'bh': 8, 'eax': 32, 'bp': 16, 'dx': 16, 'bx': 16, 'ecx': 32, 'sp': 16, 'si': 16}
>>> bigger
{'ch': ['ecx', 'cx', 'ch'], 'cl': ['ecx', 'cx', 'cl'], 'ah': ['eax', 'ax', 'ah'], 'edi': ['edi'], 'al': ['eax', 'ax', 'al'], 'cx': ['ecx', 'cx'], 'ebp': ['ebp'], 'ax': ['eax', 'ax'], 'edx': ['edx'], 'ebx': ['ebx'], 'esp': ['esp'], 'esi': ['esi'], 'dl': ['edx', 'dx', 'dl'], 'dh': ['edx', 'dx', 'dh'], 'di': ['edi', 'di'], 'bl': ['ebx', 'bx', 'bl'], 'bh': ['ebx', 'bx', 'bh'], 'eax': ['eax'], 'bp': ['ebp', 'bp'], 'dx': ['edx', 'dx'], 'bx': ['ebx', 'bx'], 'ecx': ['ecx'], 'sp': ['esp', 'sp'], 'si': ['esi', 'si']}
>>> smaller
{'ch': [], 'cl': [], 'ah': [], 'edi': ['di'], 'al': [], 'cx': ['cl', 'ch'], 'ebp': ['bp'], 'ax': ['al', 'ah'], 'edx': ['dx', 'dl', 'dh'], 'ebx': ['bx', 'bl', 'bh'], 'esp': ['sp'], 'esi': ['si'], 'dl': [], 'dh': [], 'di': [], 'bl': [], 'bh': [], 'eax': ['ax', 'al', 'ah'], 'bp': [], 'dx': ['dl', 'dh'], 'bx': ['bl', 'bh'], 'ecx': ['cx', 'cl', 'ch'], 'sp': [], 'si': []}
```

### `pwnlib.util.misc.run_in_new_terminal(`*`command, terminal = None`*`) → None` [source](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/misc.py#L179-261)

在新终端中运行命令。

当`terminal`未设置:
* 如果设置了`context.terminal`，它将会被使用。如果它是iterable，那么`context.terminal[1:]`为默认参数。 
* 如果`$PATH`中存在`pwntools-terminal`命令，那么它将会被使用。
* 如果设置了`$TERM_PROGRAM`，那么它将会被使用。
* 如果检测到X11（通过`$DISPLAY`环境变量的存在）， `x-terminal-emulator`将会被使用。
* 如果检测到tmux（通过`$TMUX`环境变量的存在），一个新的窗格会被打开。
* 如果检测到GNU窗口（通过`$STY`环境变量的存在），一个新的窗口会被打开。

参数:	
* command (*str*) – 运行的命令
* terminal (*str*) – 使用的终端
* args (*list*) – 传输到终端的参数。

#### 注意：stdin, stdout, stderr通过`/dev/null`打开指令

返回:	新的终端进程的PID。

### `pwnlib.util.misc.size(`*`n, abbrev = 'B', si = False`*`) → str` [source](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/misc.py#L54-94)

将字节流长度转换为可读形式。

参数:	
* n (*int,iterable*) – 转换为可读形式的长度，或可以调用`len()`的对象。
* abbrev (*str*) – 字符串附加大小，默认为`'B'`。

#### 例

```shell
>>> size(451)
'451B'
>>> size(1000)
'1000B'
>>> size(1024)
'1.00KB'
>>> size(1024, ' bytes')
'1.00K bytes'
>>> size(1024, si = True)
'1.02KB'
>>> [size(1024 ** n) for n in range(7)]
['1B', '1.00KB', '1.00MB', '1.00GB', '1.00TB', '1.00PB', '1024.00PB']
>>> size([])
'0B'
>>> size([1,2,3])
'3B'
```

### `pwnlib.util.misc.which(`*`name, flags = os.X_OK, all = False`*`) → str or str set` [source](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/misc.py#L129-177)

作为系统命令`which`工作；查找`$PATH`作为`name`，如果找到则返回完成路径。

如果`all`为`True`，则返回所有找到的位置的集合，否则返回第一个出现的或`None`。

参数:	
* name (*str*) – 查找的文件。
* all (*bool*) – 是否返回`name`找到的所有位置。

返回:	
如果`all`为`True`，则为所有找到的位置的集合，否则返回第一个出现的或`None`。

#### 例

```shell
>>> which('sh')
'/bin/sh'
```

### `pwnlib.util.misc.write(`*`path, data='', create_dir=False, mode='w'`*`)` [source](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/misc.py#L120-127)

创建新文件或截断现有文件为长度0并写入数据。
