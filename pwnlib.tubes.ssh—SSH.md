# pwnlib.tubes.ssh — SSH

### *`class`* `pwnlib.tubes.ssh.ssh(`*`user, host, port=22, password=None, key=None, keyfile=None, proxy_command=None, proxy_sock=None, level=None, cache=True, ssh_agent=False, *a, **kw`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py)

建立一个新的SSH链接。

参数:	
* user (*str*) – 登陆的用户名
* host (*str*) – 链接的主机名
* port (*int*) – 链接的端口
* password (*str*) – 尝试使用密码认证
* key (*str*) – 尝试使用私钥认证。字符串应为实际的私钥。
* keyfile (*str*) – 尝试使用私钥认证。字符串应为文件名。
* proxy_command (*str*) – 作为代理命令。 它和`sshProxyCommand`中的`ssh(1)`的含义大致类似。
* proxy_sock (*str*) – 使用这个socket而不是链接主机。
* timeout – 超时时间，以秒为单位。
* level – 日志等级
* cache – 缓存下载的文件(使用hash/size/timestamp)
* ssh_agent – 如果为True, 通过ssh-agent启用密钥的使用。

注意：proxy_command和proxy_sock参数仅再新版本的paramiko中使用。

>### `checksec()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py#L2001-2035)

输出一个有关远程系统的帮助信息。

参数:	banner (*bool*) – 是否将path输出到ELF二进制文件。

>### `close()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py#L1279-1284)

关闭链接。

>### `connect_remote(`*`host, port, timeout = Timeout.default`*`) → ssh_connecter` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py#L1153-1174)

通过SSH链接到一个主机。这和在`ssh`上使用`-L`标志相同。

返回一个`pwnlib.tubes.ssh.ssh_connecter`对象。

#### 例

```shell
>>> from pwn import *
>>> l = listen()
>>> s =  ssh(host='example.pwnme',
...         user='travis',
...         password='demopass')
>>> a = s.connect_remote(s.host, l.lport)
>>> b = l.wait_for_connection()
>>> a.sendline('Hello')
>>> print repr(b.recvline())
'Hello\n'
```

>### `connected()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py#L1263-1277)

如果正在链接则返回True

#### 例

```shell
>>> s =  ssh(host='example.pwnme',
...         user='travis',
...         password='demopass')
>>> s.connected()
True
>>> s.close()
>>> s.connected()
False
```

>### `download(`*`file_or_directory, local=None`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py#L1623-1639)

从远程主机中下载文件或目录。

参数:	
* file_or_directory (*str*) – 下载文件或目录的路径
* local (*str*) – 用于储存数据的本地路径，默认使用当前目录。

>### `download_data(`*`remote`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py#L1410-1434)

从远程服务上下载文件，并将其作为字符串返回。

参数:	remote (*str*) – 要下载的远程文件。

#### 例

```shell
>>> with file('/tmp/bar','w+') as f:
...     f.write('Hello, world')
>>> s =  ssh(host='example.pwnme',
...         user='travis',
...         password='demopass',
...         cache=False)
>>> s.download_data('/tmp/bar')
'Hello, world'
>>> s._sftp = None
>>> s._tried_sftp = True
>>> s.download_data('/tmp/bar')
```

>### `download_dir(`*`remote=None, local=None`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py#L1461-1500)

递归从远程服务下载目录。

参数:	
* local – 本地目录。
* remote – 远程目录。

>### `download_file(`*`remote, local=None`*)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py#L1436-1459)

从远程服务上下载文件。

文件使用其自身的哈希值储存在/tmp/pwntools-ssh-cache,所以调用函数两次没有什么开销。

参数:	
* remote (*str*) – 要下载的远程文件。
* local (*str)* – 用于储存下载的本地文件。默认从远程文件名来推断。

>### `get(`*`file_or_directory, local=None`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py#L1623-1639)

download(file_or_directory, local=None)

从远程主机下载文件或目录。

参数:	
* file_or_directory (*str*) – 下载的文件或目录的路径。
* local (*str*) –  用于储存下载的本地路径，默认使用当前路径。

>### `getenv(`*`variable, **kwargs`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py#L1100-1127)

检索远程系统上的环境变量地址。

#### 注意：实际路径会基于环境变量和argv[0]而有所不同，为了确认实际路径完全相同，建议使用`argv=[]`调用该进程。

>### `interactive(`*`shell=None`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py#L1695-1709)

建立一个交互式会话

这是一个简单的封装用于建立一个新的`pwnlib.tubes.ssh.ssh_channel`对象和在其上调用`pwnlib.tubes.ssh.ssh_channel.interactive()`。

>### `libs(`*`remote, directory=None`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py#L1657-1693)

下载文件引用的库

这是通过在远程服务上运行ldd，解析输出，并下载相关文件来完成的。

目录参数指定了下载文件的位置，默认为‘./$HOSTNAME’，其中$HOSTNAME是远程服务的主机名。

>### `listen(`*`port=0, bind_address='', timeout=pwnlib.timeout.Timeout.default`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py#L1178-1200)

listen_remote(port = 0, bind_address = ‘’, timeout = Timeout.default) -> ssh_connecter

通过SSH链接远程监听，这相当于在`ssh`上使用`-R`标志

返回一个`pwnlib.tubes.ssh.ssh_listener`对象

#### 例

```shell
>>> from pwn import *
>>> s =  ssh(host='example.pwnme',
...         user='travis',
...         password='demopass')
>>> l = s.listen_remote()
>>> a = remote(s.host, l.port)
>>> b = l.wait_for_connection()
>>> a.sendline('Hello')
>>> print repr(b.recvline())
'Hello\n'
```

listen_remote(port = 0, bind_address = '', timeout = Timeout.default) → ssh_connecter [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py#L1178-1200)

通过SSH链接远程监听，这相当于在`ssh`上使用`-R`标志。

返回一个`pwnlib.tubes.ssh.ssh_listener`对象

#### 例 

```shell
>>> from pwn import *
>>> s =  ssh(host='example.pwnme',
...         user='travis',
...         password='demopass')
>>> l = s.listen_remote()
>>> a = remote(s.host, l.port)
>>> b = l.wait_for_connection()
>>> a.sendline('Hello')
>>> print repr(b.recvline())
'Hello\n'
```

>### `process(`*`argv=None, executable=None, tty=True, cwd=None, env=None, timeout=pwnlib.timeout.Timeout.default, run=True, stdin=0, stdout=1, stderr=2, preexec_fn=None, preexec_args=[], raw=True, aslr=None, setuid=None, shell=False`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py#L675-1047)

使用和`pwnlib.tubes.process.process`相同的方式在远程服务上执行进程。

为了达成这个目的, 需要创建一个用适当参数调用`os.execve`的python脚本。

为了达到更好的效果，`ssh_channel`对象返回一个用于pid进程的`pid`属性。

参数:	
* argv (*list*) – 传入进程的参数的列表。
* executable (*str*) – 可执行文件的路径， 如果为None, 则使用argv[0]。
* tty (*bool*) – 从服务请求一个`tty`， 这通常通过使`libc`立即写入数据，而不是通过缓存数据来修复缓冲问题。然而这会禁用控制代码的解释(如Ctrl+C)并中断`.shutdown`。
* cwd (*str*) – 工作目录，如果为`None`,使用`cwd`上指定的工作目录或通过`set_working_directory()`设置。
* env (*dict*) – 子选项的环境变量，如果为`None`, 则继承默认环境。
* timeout (*int*) – 用于与进程交流的通道上的超时时间。
* run (*bool*) – 设置为`True`来运行程序(默认状态)。如果为`False`, 返回路径到远程服务器上的可执行python脚本，当可执行时将被执行。
* stdin (*int, str*) – 如果为整数则使用带有标号的文件解释器代替stdin，如果为字符串, 用指定路径打开一个文件，并使用其文件解释器代替stdin，也可以时`sys.stdin`,`sys.stdout`,`sys.stderr`其中之一。如果为'None`文件解释器会关闭。
* stdout (*int, str*) – 参考stdin.
* stderr (*int, str*) – 参考stdin.
* preexec_fn (*callable*) – 在execve()之前在远程端执行的函数。这**必须**是一个自包含的函数，它必须实现自己的import，而且不能引用外部变量。
* preexec_args (*object*) – 传递给`preexec_fn`的参数，这**必须**只包含python本地对象。
* raw (*bool*) – 如果为`True`,禁用终端控制代码解释。
* aslr (*bool*) – 参考`pwnlib.tubes.process.process`以取得更多信息。
* setuid (*bool*) – 参考`pwnlib.tubes.process.process`以取得更多信息。
* shell (*bool*) – 传递命令行参数给shell。

返回:	一个新的SSH频道，如果`run=False`则是一个脚本的路径。

#### 注意：远程服务上需要python环境。

#### 例

```shell
>>> s = ssh(host='example.pwnme',
...         user='travis',
...         password='demopass')
>>> sh = s.process('/bin/sh', env={'PS1':''})
>>> sh.sendline('echo Hello; exit')
>>> sh.recvall()
'Hello\n'
>>> s.process(['/bin/echo', '\xff']).recvall()
'\xff\n'
>>> s.process(['readlink', '/proc/self/exe']).recvall()
'/bin/readlink\n'
>>> s.process(['LOLOLOL', '/proc/self/exe'], executable='readlink').recvall()
'/bin/readlink\n'
>>> s.process(['LOLOLOL\x00', '/proc/self/cmdline'], executable='cat').recvall()
'LOLOLOL\x00/proc/self/cmdline\x00'
>>> sh = s.process(executable='/bin/sh')
>>> sh.pid in pidof('sh') 
True
>>> s.process(['pwd'], cwd='/tmp').recvall()
'/tmp\n'
>>> p = s.process(['python','-c','import os; print os.read(2, 1024)'], stderr=0)
>>> p.send('hello')
>>> p.recv()
'hello\n'
>>> s.process(['/bin/echo', 'hello']).recvall()
'hello\n'
>>> s.process(['/bin/echo', 'hello'], stdout='/dev/null').recvall()
''
>>> s.process(['/usr/bin/env'], env={}).recvall()
''
>>> s.process('/usr/bin/env', env={'A':'B'}).recvall()
'A=B\n'
```

```shell
>>> s.process('false', preexec_fn=1234)
Traceback (most recent call last):
...
PwnlibException: preexec_fn must be a function
```

```shell
>>> s.process('false', preexec_fn=lambda: 1234)
Traceback (most recent call last):
...
PwnlibException: preexec_fn cannot be a lambda
```

```shell
>>> def uses_globals():
...     foo = bar
>>> print s.process('false', preexec_fn=uses_globals).recvall().strip() 
Traceback (most recent call last):
...
NameError: global name 'bar' is not defined
```

```shell
>>> s.process('echo hello', shell=True).recvall()
'hello\n'
```

>### `put(`*`file_or_directory, remote=None`*`) [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py#L1600-1620)

upload(file_or_directory, remote=None)

上传文件或目录到远程主机。

参数:	
* file_or_directory (*str*) – 要上传的文件或目录的路径。
* remote (*str*) – 储存数据的本地路径。默认为工作目录。

>### `read(`*`path`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py#L1800-1802)

封装`download_data`来适配`pwnlib.util.misc.read()`。

>### `remote(`*`host, port, timeout=pwnlib.timeout.Timeout.default`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py#L1153-1174)

connect_remote(host, port, timeout = Timeout.default) -> ssh_connecter

通过SSH来链接主机，等同于在`ssh`上使用`-L`标志

返回一个`pwnlib.tubes.ssh.ssh_connecter`对象。

#### 例

```shell
>>> from pwn import *
>>> l = listen()
>>> s =  ssh(host='example.pwnme',
...         user='travis',
...         password='demopass')
>>> a = s.connect_remote(s.host, l.lport)
>>> b = l.wait_for_connection()
>>> a.sendline('Hello')
>>> print repr(b.recvline())
'Hello\n'
```

>### `run(`*`process, tty=True, wd=None, env=None, timeout=None, raw=True`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py#L1066-1095)

如果需要向后兼容，使用`system()`。

>### `run_to_end(`*`process, tty = False, timeout = Timeout.default, env = None`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py#L1131-1151)

在远程服务上运行一个命令并返回一个包含(data, exit_status)的tuple。如果`tty`为True, 则该命令在远程服务的终端上运行。

#### 例

```shell
>>> s =  ssh(host='example.pwnme',
...         user='travis',
...         password='demopass')
>>> print s.run_to_end('echo Hello; exit 17')
('Hello\n', 17)
```

>### `set_working_directory(`*`wd=None, symlink=False`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py#L1711-1794)

设置命令即将运行在哪个工作目录(通过ssh.run)和设置如果没有提供路径时上传或下载那些文件。

#### 注意：这将会在底层实现`mktemp -d`，将目录权限设置为`0700`。这意味着setuid二进制文件将会无法访问在此目录中创建的文件。为了解决这个问题，我们需要在目录上使用`chmod +x`

参数:	
* wd (*string*) – 工作目录。默认根据在远程主机上运行`mktemp -d`的结果生成一个目录。
* symlink (*bool,str*) – 在新目录中创建符号链接。如果默认值为`False`意味着不应该创建符号链接。字符串值应被看作符号链接的路径，直接传送到远程端shell进行扩展，使通配符得以运行。其他值都应被看作布尔值，其中`True`表示“旧”工作目录中的文件都应被符号链接。

#### 例

```shell
>>> s =  ssh(host='example.pwnme',
...         user='travis',
...         password='demopass')
>>> cwd = s.set_working_directory()
>>> s.ls()
''
>>> s.pwd() == cwd
True
```

```shell
>>> s =  ssh(host='example.pwnme',
...         user='travis',
...         password='demopass')
>>> homedir = s.pwd()
>>> _=s.touch('foo')
```

```shell
>>> _=s.set_working_directory()
>>> assert s.ls() == ''
```

```shell
>>> _=s.set_working_directory(homedir)
>>> assert 'foo' in s.ls().split()
```

```shell
>>> _=s.set_working_directory(symlink=True)
>>> assert 'foo' in s.ls().split()
>>> assert homedir != s.pwd()
```

```shell
>>> symlink=os.path.join(homedir,'*')
>>> _=s.set_working_directory(symlink=symlink)
>>> assert 'foo' in s.ls().split()
>>> assert homedir != s.pwd()
```

>### `shell(`*`shell = None, tty = True, timeout = Timeout.default`*`) → ssh_channel` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py#L651-673)

开辟一个新的带有shell的频道。

参数:	
* shell (*str*) – shell程序运行的路径。 如果为`None`，提供默认shell给登入者使用。
* tty (*bool*) – 如果为`True`，在远程服务上请求一个终端。

返回:	返回一个`pwnlib.tubes.ssh.ssh_channel`对象

#### 例

```shell
>>> s =  ssh(host='example.pwnme',
...         user='travis',
...         password='demopass')
>>> sh = s.shell('/bin/sh')
>>> sh.sendline('echo Hello; exit')
>>> print 'Hello' in sh.recvall()
True
```

>### `system(`*`process, tty = True, wd = None, env = None, timeout = Timeout.default, raw = True`*`) → ssh_channel` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py#L1066-1095)

开辟一个新的带有指定程序的频道。如果`tty`为`True`，在远程服务上请求一个终端。

如果`raw`为`True`，终端控制代码会被忽略且没有回显。

返回一个`pwnlib.tubes.ssh.ssh_channel`对象。

#### 例

```shell
>>> s =  ssh(host='example.pwnme',
...         user='travis',
...         password='demopass')
>>> py = s.run('python -i')
>>> _ = py.recvuntil('>>> ')
>>> py.sendline('print 2+2')
>>> py.sendline('exit')
>>> print repr(py.recvline())
'4\n'
```

>### `unlink(`*`file`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py#L1644-1655)

删除远程主机上的文件。

参数:	file (*str*) – 文件的路径。

>### `upload(`*`file_or_directory, remote=None`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py#L1600-1620)

上传文件或目录到远程主机。

参数:	
* file_or_directory (*str*) – 下载文件或目录的路径。
* remote (*str*) – 用于储存数据的本地路径。默认使用工作目录。

>### `upload_data(`*`data, remote`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py#L1503-1542)

上传数据到远程服务的文件中。

参数:	
* data (*str*) – 上传的数据。
* remote (*str*) – 用于接收上传数据的文件。

#### 例

```shell
>>> s =  ssh(host='example.pwnme',
...         user='travis',
...         password='demopass')
>>> s.upload_data('Hello, world', '/tmp/upload_foo')
>>> print file('/tmp/upload_foo').read()
Hello, world
>>> s._sftp = False
>>> s._tried_sftp = True
>>> s.upload_data('Hello, world', '/tmp/upload_bar')
>>> print file('/tmp/upload_bar').read()
Hello, world
```

>### `upload_dir(`*`local, remote=None`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py#L1565-1598)

将一个目录递归上传到服务器上。

参数:	
* local – 本地目录
* remote – 远程目录

>### `upload_file(`*`filename, remote=None`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py#L1544-1563)

上传文件到远程服务，返回远程文件名称。

参数: 
* filename(*str*): 要下载的本地文件。
* remote(*str*): 该文件的远程文件名。默认从本地文件名来推断。

>### `which(`*`program`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py#L1049-1064)

直接调用远程系统的`which`修改，将当前工作目录加到`$PATH`的结尾。

>### `write(`*`path, data`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py#L1796-1798)

封装`upload_data`来适配`pwnlib.util.misc.write()`。

>### `arch` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py)
`str` – 远程机器的cpu架构。

aslr [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py)

>### `bool` – 系统上是否启用ASLR。

#### 例

```shell
>>> s = ssh("travis", "example.pwnme")
>>> s.aslr
True
```

>### `aslr_ulimit` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py)

`bool` – 32位进程的商是否可以通过ulimit减少。

>### `bits` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py)

`str` – 远程机器上的指针长度。

>### `cache =` *`True`* [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py)

允许SSH的下载缓存(`bool`)

>### `client =` *`None`* [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py)

Paramiko SSHClient支持这个对象。

>### `cwd =` *`None`* [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py)

工作目录(`str`)

>### `distro` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py)

`tuple` – Linux发行版名称和版本。

>### `host =` *`None`* [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py)

远程主机名称(`str`)

>### `os` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py)

`str` – 远程机器的操作系统

>### `pid =` *`None`* [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py)

用于该链接的远程sshd服务的PID。

>### `port =` *`None`* [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py)

远程端口(*int*)

>### `sftp` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py)

用于文件传输的Paramiko SFTPClient对象，设置为`None`来禁用`sftp`。

>### `version` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py)

`tuple` – 远程机器的内核版本。

### *`class`* `pwnlib.tubes.ssh.ssh_channel` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py)

基类: `pwnlib.tubes.sock.sock`

`interactive(`*`prompt = pwnlib.term.text.bold_red('$') + ' '`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py#L188-263)

如果不是在终端模式（TTY-mode），这和方法`pwnlib.tubes.tube.tube.interactive`效果完全相同，否则他们效果大致相同。

终端模式下的SSH链接通常会有自带的提示， 因此提示参数会被忽略。一旦`pwnlib.term`更加成熟，一些特定的SSH攻击会被移除。

>### `kill()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py#L135-141)

中止进程。

>### `poll() → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py#L165-178)

轮询进程的退出代码，如果进程未执行完成会返回`None`，否则会返回退出代码。

### *`class`* `pwnlib.tubes.ssh.ssh_connecter` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py)

基类: `pwnlib.tubes.sock.sock`

### *`class`* `pwnlib.tubes.ssh.ssh_listener` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/ssh.py)

基类: `pwnlib.tubes.sock.sock`
