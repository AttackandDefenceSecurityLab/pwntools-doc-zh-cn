## `pwnlib.constants` - 轻松访问头文件常量

包含从头文件中提取的常量的模块。

该模块的作用是快速访问来自不同架构和操作系统的常量。

常量被一个简便的类所包装，该类允许访问常量的名称，同时对其执行所有正常的数学运算。

**Example**:

```
>>> str(constants.freebsd.SYS_stat)
'SYS_stat'
>>> int(constants.freebsd.SYS_stat)
188
>>> hex(constants.freebsd.SYS_stat)
'0xbc'
>>> 0 | constants.linux.i386.SYS_stat
106
>>> 0 + constants.linux.amd64.SYS_stat
4
```

子模块`freebsd `包含FreeBSD的所有常量，而Linux的常数已被架构拆分。 

通过设置`pwnlib.context.arch`或`pwnlib.context.os`，其类似于`pwnlib.shellcraft`中发生的方式，用来“提升”子模块的变量。

**Example**:

```
>>> with context.local(os = 'freebsd'):
...     print int(constants.SYS_stat)
188
>>> with context.local(os = 'linux', arch = 'i386'):
...     print int(constants.SYS_stat)
106
>>> with context.local(os = 'linux', arch = 'amd64'):
...     print int(constants.SYS_stat)
4
```

```
>>> with context.local(arch = 'i386', os = 'linux'):
...    print constants.SYS_execve + constants.PROT_WRITE
13
>>> with context.local(arch = 'amd64', os = 'linux'):
...    print constants.SYS_execve + constants.PROT_WRITE
61
>>> with context.local(arch = 'amd64', os = 'linux'):
...    print constants.SYS_execve + constants.PROT_WRITE
61
```


