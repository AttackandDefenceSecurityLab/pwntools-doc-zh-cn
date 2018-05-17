# pwnlib.tubes.process—Processes

### *`class`* `pwnlib.tubes.process.process(`*`argv=None, shell=False, executable=None, cwd=None, env=None, stdin=-1, stdout=<pwnlib.tubes.process.PTY object>, stderr=-2, close_fds=True, preexec_fn=<function <lambda>>, raw=True, aslr=None, setuid=None, where='local', display=None, alarm=None, *args, **kwargs`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/process.py)

基类:`pwnlib.tubes.tube.tube`

生成一个新的进程，用通信通道封装。

参数:	
* argv (*list*) – 传送给生成的进程的参数。

* shell (*bool*) – 设置为`True`时将`argv`设置为字符串来传递给shell，而不是参数。

* executable (*str*) – 要执行的二进制文件路径，如果为`None`，使用`argv[0]`。不能和`shell`一起使用。

* cwd (*str*) – 工作目录，默认使用当前目录。

* env (*dict*) – 环境变量，默认情况下从Python的环境继承。

* stdin (*int*) – 用于`stdin`的文件或工程的标识符。默认情况下使用通道。 可以使用伪终端而不用将其设置为`PTY`。这会使程序在交互模式下运行（如`python`会显示`>>>`提示符)。如果程序直接从`/dev/tty`读取,则使用伪终端。

* stdout (*int*) – 用于`stdout`的文件或工程的标识符.默认使用伪终端，所以libc的任意stdout缓冲都会被禁用。也可以使用`PIPE`来使用普通通道。

* stderr (*int*) –  用于`stderr`的文件或工程的标识符。 默认情况下使用`STDOUT`。也可以作为`PIPE`来使用特定的通道,即使`pwnlib.tubes.tube.tube`封包将会无法读取数据

* close_fds (*bool*) – 关闭除stdin，stdout和stderr之外的所有文件. 默认使用`True`。

* preexec_fn (*callable*) – 在调用`execve`之前，立刻调用所有可调用的。

* raw (*bool*) – 将生成的伪终端设置为原始模式(即禁用回显字符和控制字符)。默认为`True`，如果没有生成伪终端，则没有作用。

* aslr (*bool*) –
如果设置为`False`，通过`personality`(`setarch -R`)和`setrlimit`(`ulimit -s unlimited`)禁用ASLR。
这会禁用目标进程的ASLR，但是如果执行`setuid`二进制文件，`setarch`的更改会丢失。
默认参数从`context.aslr`中继承。查看`setuid`来得到其他选项和信息。

* setuid (*bool*) –
用于控制目标二进制文件的`setuid`状态并采取相应的行动。
默认该值为`None`，所以没有相应设定。
如果设为`True`,将目标二进制文件看作`setuid`。如果`aslr=False`，这会修改进程上禁用ASLR的机制。当调用为`setuid`二进制文件时，对本地调试有用。
如果设为`False`,阻止`setuid`的位对目标进程的作用。该设置仅在内核为kernels V3.5或更高版本的Linux上提供。

* where (*str*) – 进程运行的位置，用于日志记录。

* display (*list*) – 要显示的参数列表，而不是主要的执行文件名称。

* alarm (int) – 设置SIGALRM警告进程上的超时。

#### 例

```shell
>>> p = process('python2')
>>> p.sendline("print 'Hello world'")
>>> p.sendline("print 'Wow, such data'");
>>> '' == p.recv(timeout=0.01)
True
>>> p.shutdown('send')
>>> p.proc.stdin.closed
True
>>> p.connected('send')
False
>>> p.recvline()
'Hello world\n'
>>> p.recvuntil(',')
'Wow,'
>>> p.recvregex('.*data')
' such data'
>>> p.recv()
'\n'
>>> p.recv() 
Traceback (most recent call last):
...
EOFError
```

```shell
>>> p = process('cat')
>>> d = open('/dev/urandom').read(4096)
>>> p.recv(timeout=0.1)
''
>>> p.write(d)
>>> p.recvrepeat(0.1) == d
True
>>> p.recv(timeout=0.1)
''
>>> p.shutdown('send')
>>> p.wait_for_close()
>>> p.poll()
0
```

```shell
>>> p = process('cat /dev/zero | head -c8', shell=True, stderr=open('/dev/null', 'w+'))
>>> p.recv()
'\x00\x00\x00\x00\x00\x00\x00\x00'
```

```shell
>>> p = process(['python','-c','import os; print os.read(2,1024)'],
...             preexec_fn = lambda: os.dup2(0,2))
>>> p.sendline('hello')
>>> p.recvline()
'hello\n'
```

```shell
>>> stack_smashing = ['python','-c','open("/dev/tty","wb").write("stack smashing detected")']
>>> process(stack_smashing).recvall()
'stack smashing detected'
```

```shell
>>> process(stack_smashing, stdout=PIPE).recvall()
''
```

```shell
>>> getpass = ['python','-c','import getpass; print getpass.getpass("XXX")']
>>> p = process(getpass, stdin=PTY)
>>> p.recv()
'XXX'
>>> p.sendline('hunter2')
>>> p.recvall()
'\nhunter2\n'
```

```shell
>>> process('echo hello 1>&2', shell=True).recvall()
'hello\n'
```

```shell
>>> process('echo hello 1>&2', shell=True, stderr=PIPE).recvall()
''
```

```shell
>>> a = process(['cat', '/proc/self/maps']).recvall()
>>> b = process(['cat', '/proc/self/maps'], aslr=False).recvall()
>>> with context.local(aslr=False):
...    c = process(['cat', '/proc/self/maps']).recvall()
>>> a == b
False
>>> b == c
True
```

```shell
>>> process(['sh','-c','ulimit -s'], aslr=0).recvline()
'unlimited\n'
```

```shell
>>> io = process(['sh','-c','sleep 10; exit 7'], alarm=2)
>>> io.poll(block=True) == -signal.SIGALRM
True
```

```shell
>>> binary = ELF.from_assembly('nop', arch='mips')
>>> p = process(binary.path)
```

>### `communicate(`*`stdin = None`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/process.py#L662-668)

在进程中调用`subprocess.Popem.communicate()`的方法。

>### `kill()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/process.py#L623-628)

中止进程。

>### `leak(`*`address, count=1`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/process.py#L925-955)

在指定地址的进程中泄露内存。

参数:	
* address (*int*) – 泄露内存的地址。
* count (*int*) – 在地址上泄露内存的字节数。


#### 例

```shell
>>> e = ELF('/bin/sh')
>>> p = process(e.path)
```

为了确保没有竞争条件阻止进程建立

```shell
>>> p.sendline('echo hello')
>>> p.recvuntil('hello')
'hello'
```

现在我们可以泄露内存了！

```shell
>>> p.leak(e.address, 4)
'\x7fELF'
```

>### `libs() → dict` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/process.py#L828-865)

返回一个映射到进程加载的每个共享库的路径的字典，其加载在进程地址空间中。

如果进程的`/proc/$PID/maps`无法访问，输出中的的`ldd`将会被单独使用。如果ASLR被启用，可能会导致不准确的结果。

>### `poll(`*`block = False`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/process.py#L630-660)

参数:block(*bool*) - 等待进程退出。

轮询进程的退出代码。 如果进程尚未执行完毕，将返回无，否则返回退出代码。

>### `alarm = ` *`None`* [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/process.py)

进程的超时警告。

>### `argv = ` *`None`* [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/process.py)

参数通过argv传递。

>### `aslr = ` *`None`* [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/process.py)

ASLR是否应该打开。

>### `corefile` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/process.py)

返回进程的核心文件

如果进程处于活动状态，尝试使用GDB建立一个coredump文件。

如果进程已经关闭，则尝试定位内核创建的coredump文件。

>### `cwd` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/process.py)

正在运行进程的目录。

#### 例

```shell
>>> p = process('sh')
>>> p.sendline('cd /tmp; echo AAA')
>>> _ = p.recvuntil('AAA')
>>> p.cwd == '/tmp'
True
>>> p.sendline('cd /proc; echo BBB;')
>>> _ = p.recvuntil('BBB')
>>> p.cwd
'/proc'
```

>### `elf` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/process.py)

为启动该进程的可执行文件返回一个ELF文件。

>### `env = ` *`None`* [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/process.py)

传递环境给envp。

>### `executable =` *`None`* [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/process.py)

可执行文件的完整路径。

>### `libc` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/process.py)

为当前进程的libc返回ELF，如果可能，会自行调整到正确的地址。

>### `proc =` *`None`* [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/process.py)

支持该进程的`subprocess.Popen`对象

>### `program` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/process.py)

`executable`的别称，用于向后兼容。

#### 例

```shell
>>> p = process('true')
>>> p.executable == '/bin/true'
True
>>> p.executable == p.program
True
```

>### `pty =` *`None`* [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/process.py)

用于控制终端的文件标识符。

>### `raw =` *`None`* [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/process.py)

查看正在控制的终端是否运行在原始模式。

>### `stderr` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/process.py)

`self.proc.stderr`的缩写

查看: `process.proc`

>### `stdin` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/process.py)

`self.proc.stdin`的缩写

查看: `process.proc`

>### `stdout` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/process.py)

`self.proc.stdout`的缩写

查看: `process.proc`

