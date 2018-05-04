## `pwnlib.args` - 魔术命令行参数

Pwntools发行了几个在_from pwn import*_模式下运行的魔术命令行参数和环境变量。


这些参数从命令行中提取并从`sys.argv`中移除。


这些参数能添加到命令行来设置，或者`PWNLIB_`前缀的环境中设置这些参数。


最简单的例子就是启用更详细的调试。只需要设置`DEBUG`。


```
$ PWNLIB_DEBUG=1 python exploit.py
$ python exploit.py DEBUG
```

无论这些参数的名称如何，它们都会被自动提取，并通过作为全局变量`args`发行的`pwnlib.args.args`发行。`pwntools`内部储存的参数不会以这种形式暴露出来。


```
$ python -c 'from pwn import *; print args' A=1 B=Hello HOST=1.2.3.4 DEBUG
defaultdict(<type 'str'>, {'A': '1', 'HOST': '1.2.3.4', 'B': 'Hello'})

```

这对于条件代码极为有用，例如可以用来确定是在本地运行漏洞利用还是连接到远程服务器。未指定的参数会计算为一个空字符串。


```
if args['REMOTE']:
    io = remote('exploitme.com', 4141)
else:
    io = process('./pwnable')
```

参数也可以通过点运算符被直接访问，例如：


```
if args.REMOTE:
    ...
```


任何未被定义的参数都计算为一个空字符串，`''`

下面列出了被广泛认可的“魔术参数”及其作用的完整列表：

 

>**pwnlib.args.DEBUG(_x_)**    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/args.py#L128-131)

将日志记录详细等级设置为`debug`，这样可以显示包括记录由管发送的每个字节等更多信息。



>**pwnlib.args.LOG\_FILE(_x_)**    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/args.py#L118-121)

通过`context.log_file`设置要使用的日志文件，例如
`LOG_FILE=./log.txt`。



>**pwnlib.args.LOG\_LEVEL(_x_)**    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/args.py#L111-116)

通过`context.log_level`设置要使用的日志记录的详细等级，例如`LOG_LEVEL=debug`。


>**pwnlib.args.NOASLR(_v_)**    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/args.py#L148-150)

通过`context.aslr`禁用ASLR。


>**pwnlib.args.NOPTRACE(_v_)**    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/args.py#L152-155)

通过`context.noptrace`禁用像`gdb.attach()`等需要用到`ptrace`工具的语句。


>**pwnlib.args.NOTERM(_v_)**    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/args.py#L133-137)
 
禁用高性能的终端设置和动画。


>**pwnlib.args.RANDOMIZE(_v_)**    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/args.py#L144-146)

通过`context.randomize`启用各部分的随机化。


>**pwnlib.args.SILENT(_x_)**    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/args.py#L123-126)

将日志记录的详细等级设置为使大多数保持静默输出的为`error`


>**pwnlib.args.STDERR(_v_)**    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/args.py#L157-159)

默认情况下将日志记录发送到`stderr`，而不是`stdout`。


>**pwnlib.args.TIMEOUT(_v_)**    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/args.py#L139-142)

通过`context.timeout`设置管操作超时时间（以秒为单位），例如`TIMEOUT=30`。


>**pwnlib.args.asbool(_s_)**    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/args.py#L98-109)

将字符串转换为其布尔值。



>**pwnlib.args.isident(_s_)**    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/args.py#L83-96)

帮助函数检查一个字符串是否是一个有效的标识符，比如在命令行中传入的。 




