# `pwnlib.tubes` - Talking to the World!

pwnlib不是一个独立的模块，它拥有很多对外通信的通道。

这是一个用于和socket、进程和ssh链接的库，这个库的目标是能够将同样的API用于不同地方，如TCP服务，本地终端或者是运行于ssh的程序。

大部分的功能都包含在`pwnlib.tubes.tube`中，剩下的类仅适用于该类的工作，而且可能仅适用于特定类型的渠道。

## 通信通道的种类

* `pwnlib.tubes.process` —— 进程
* `pwnlib.tubes.serialtube` —— 串口
* `pwnlib.tubes.sock` —— sockets
* `pwnlib.tubes.ssh` —— SSH

## `pwnlib.tubes.tube` — 通用功能

### *`class`* ` pwnlib.tubes.tube.tube ` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py)

包含socket，串行端口和ssh通用的所有渠道。

`can_recv(`*`timeout=0`*`)→bool` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L1061-1081)

如果链接在`timeout`秒之前有可用数据则返回true。

#### 例

```shell
>>> import time
>>> t = tube()
>>> t.can_recv_raw = lambda *a: False
>>> t.can_recv()
False
>>> _=t.unrecv('data')
>>> t.can_recv()
True
>>> _=t.recv()
>>> t.can_recv()
False
```

`clean(`*`timeout=0.05`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L848-875)

直到失败前，只要达到一个很短的超时时间，都会调用`pwnlib.tubes.tube.tube.recv()`清除通信通道中的缓冲区数据。

如果`timeout`设置为0，只清除缓存中的数据。

注意：如果`timeout`设置为0，则底层网络实际上未被轮询; 只有内部缓冲区被清除。

返回:所有接收到的数据。

#### 例

```shell
>>> t = tube()
>>> t.unrecv('clean me up')
>>> t.clean(0)
'clean me up'
>>> len(t.buffer)
0
```

`clean_and_log(`*`timeout=0.05`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L877-904)

与`pwnlib.tubes.tube.tube.clean()`完全一样，但是通过`pwnlib.self.info()`保存数据到日志。

返回:所有接收到的数据。

#### 例

```shell
>>> def recv(n, data=['', 'hooray_data']):
...     while data: return data.pop()
>>> t = tube()
>>> t.recv_raw      = recv
>>> t.connected_raw = lambda d: True
>>> t.fileno        = lambda: 1234
>>> with context.local(log_level='info'):
...     data = t.clean_and_log() 
[DEBUG] Received 0xb bytes:
    'hooray_data'
>>> data
'hooray_data'
>>> context.clear()
```

`close()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L1271-1276)

关闭通信通道。

`connect_both(`*`other`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L988-994)

将该通信通道的两个终端链接到另一个通信通道中。

`connect_input(`*`other`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L906-961)

将该通信通道的输入端链接到另一个通信通道的输出端。

#### 例

```shell
>>> def p(x): print x
>>> def recvone(n, data=['data']):
...     while data: return data.pop()
...     raise EOFError
>>> a = tube()
>>> b = tube()
>>> a.recv_raw = recvone
>>> b.send_raw = p
>>> a.connected_raw = lambda d: True
>>> b.connected_raw = lambda d: True
>>> a.shutdown      = lambda d: True
>>> b.shutdown      = lambda d: True
>>> import time
>>> _=(b.connect_input(a), time.sleep(0.1))
data
```

`connect_output(`*`other`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L963-986)

将该通道的输出端链接到另一个通信通道的输入端

#### 例

```shell
>>> def p(x): print x
>>> def recvone(n, data=['data']):
...     while data: return data.pop()
...     raise EOFError
>>> a = tube()
>>> b = tube()
>>> a.recv_raw = recvone
>>> b.send_raw = p
>>> a.connected_raw = lambda d: True
>>> b.connected_raw = lambda d: True
>>> a.shutdown      = lambda d: True
>>> b.shutdown      = lambda d: True
>>> _=(a.connect_output(b), time.sleep(0.1))
data
```

`connected(`*`direction='any'`*`)→bool` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L1151-1183)

如果通信通道按照指定的方式链接则返回True

参数:driection(*str*)-可以为以下字符串'any','in','read','recv','out','write','send'

#### 文本测试

```shell
>>> def p(x): print x
>>> t = tube()
>>> t.connected_raw = p
>>> _=map(t.connected, ('any', 'in', 'read', 'recv', 'out', 'write', 'send'))
any
recv
recv
recv
send
send
send
>>> t.connected('bad_value') 
Traceback (most recent call last):
...
KeyError: "direction must be in ['any', 'in', 'out', 'read', 'recv', 'send', 'write']"
```

`fileno()→int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L1281-1287)

返回一个用于读取的文件号码。

`interactive(`*`prompt=pwnlib.term.text.bold_red('$')+''`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L767-817)

同时在通信通道中写入和读取。原则上只是将通信通道链接到标准输入和输出。但实际上这可用性更高，当我们通过`pwnlib.term`来打印浮点显示的时候。因此它只能在`pwnlib.term.term_mode`下工作。

`recv(`*`numb = 4096, timeout = default`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L46-78)

最多从通信通道接收`numb`个字节的数据，同时当任意数量的数据可用时立即返回。

如果在`timeout`秒之前请求未被满足，所有数据会被置入缓冲区并返回一个空字符串(`''`)。

输出:exceptions.EOFError —— 链接被关闭

返回:一个包含从socket接收的字节的字符串，或当等待超时时返回''。

#### 例

```shell
>>> t = tube()
>>> # Fake a data source
>>> t.recv_raw = lambda n: 'Hello, world'
>>> t.recv() == 'Hello, world'
True
>>> t.unrecv('Woohoo')
>>> t.recv() == 'Woohoo'
True
>>> with context.local(log_level='debug'):
...    _ = t.recv() 
[...] Received 0xc bytes:
    'Hello, world'
```

`recvall() → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L656-676)

持续接收数据直到接收到EOF

`recvline(`*`keepends = True`*`) → str`

从通信通道中接收单行数据。

一“行”是由`newline`中设置的字节序中止的字节序列，默认为`'\n'`。

如果在`timeout`秒之前请求未被满足，所有数据会被置入缓冲区并返回一个空字符串(`''`)。

参数: 
* keepends (*bool*) —— 保持在行尾 (`True`)
* timeout (*int*) —— 超时时间

返回:在通信通道中接收到的所有字节，直到收到第一个换行符`'\n'`。可选择保留结尾。

#### 例

```shell
>>> t = tube()
>>> t.recv_raw = lambda n: 'Foo\nBar\r\nBaz\n'
>>> t.recvline()
'Foo\n'
>>> t.recvline()
'Bar\r\n'
>>> t.recvline(keepends = False)
'Baz'
>>> t.newline = '\r\n'
>>> t.recvline(keepends = False)
'Foo\nBar'
```

`recvline_contains(`*`items, keepends=False, timeout=pwnlib.timeout.Timeout.default`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L476-508)

持续接收数据行，直到某一行中包含有其中一个`items`。

参数:
* items (*str,tuple*) —— 要查找的字符串的list，或者单一一个字符串。
* keepends (*bool*) —— 当其为`True`时返回带有换行符的数据。
* timeout (int) —— 超时时间，以秒为单位。

#### 例

```shell
>>> t = tube()
>>> t.recv_raw = lambda n: "Hello\nWorld\nXylophone\n"
>>> t.recvline_contains('r')
'World'
>>> f = lambda n: "cat dog bird\napple pear orange\nbicycle car train\n"
>>> t = tube()
>>> t.recv_raw = f
>>> t.recvline_contains('pear')
'apple pear orange'
>>> t = tube()
>>> t.recv_raw = f
>>> t.recvline_contains(('car', 'train'))
'bicycle car train'
```

`recvline_endswith(`*`delims, keepends = False, timeout = default`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L546-576)

持续接收数据行，直到接收到一行以`delims`开始的数据。返回接收到的最后一行。

如果在`timeout`秒之前请求未被满足，所有数据会被置入缓冲区并返回一个空字符串(`''`)。

查看`recvline_startswith()`来获取更多细节。

#### 例

```shell
>>> t = tube()
>>> t.recv_raw = lambda n: 'Foo\nBar\nBaz\nKaboodle\n'
>>> t.recvline_endswith('r')
'Bar'
>>> t.recvline_endswith(tuple('abcde'), True)
'Kaboodle\n'
>>> t.recvline_endswith('oodle')
'Kaboodle'
```

`recvline_pred(`*`pred, keepends = False`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L428-474)

接收数据直到`pred(行)`返回一个真值，删除其他数据。

如果在`timeout`秒之前请求未被满足，所有数据会被置入缓冲区并返回一个空字符串。

参数:pred(*可调用*) —— 调用的函数。返回使这个函数返回`True`的行。

#### 例

```shell
>>> t = tube()
>>> t.recv_raw = lambda n: "Foo\nBar\nBaz\n"
>>> t.recvline_pred(lambda line: line == "Bar\n")
'Bar'
>>> t.recvline_pred(lambda line: line == "Bar\n", keepends=True)
'Bar\n'
>>> t.recvline_pred(lambda line: line == 'Nope!', timeout=0.1)
''
```

`recvline_regex(`*`regex, exact=False, keepends=False, timeout=pwnlib.timeout.Timeout.default`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L601-622)

recvregex(regex, exact = False, keepends = False, timeout = default) -> str

封装`recvline_pred()`，当正则表达式匹配某一行时将其返回。

默认使用`re.RegexObject.search()`，但是当`exact`设置为True时改用`re.RegexObject.match()`。

如果在`timeout`秒之前请求未被满足，所有数据会被置入缓冲区并返回一个空字符串(`''`)。

`recvline_startswith(`*`delims, keepends = False, timeout = default`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L510-544)

持续接收数据行，直到接收到一行以`delims`开始的数据。返回接收到的最后一行。

如果在`timeout`秒之前请求未被满足，所有数据会被置入缓冲区并返回一个空字符串(`''`)。

参数:
* delims (*str,tuple*) —— 要查找的字符串的list，或者单一字符。
* keepends (*bool*) —— 当其为`True`时返回带有换行符的数据。
* timeout (*int*) —— 超时时间，以秒为单位。

返回:第一行接收到的从`delims`开始的数据。

#### 例

```shell
>>> t = tube()
>>> t.recv_raw = lambda n: "Hello\nWorld\nXylophone\n"
>>> t.recvline_startswith(tuple('WXYZ'))
'World'
>>> t.recvline_startswith(tuple('WXYZ'), True)
'Xylophone\n'
>>> t.recvline_startswith('Wo')
'World'
```

`recvlines(`*`numlines, keepends = False, timeout = default`*`) → str list` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L335-390)

最多接收`numlines`行的数据。

一“行”是由`newline`中设置的字节序中止的字节序列，默认为`'\n'`。

如果在`timeout`秒之前请求未被满足，所有数据会被置入缓冲区并返回一个空字符串(`''`)。

参数:
* numlines (*int*) —— 最大接收的行数
* keepends (*bool*) —— 保持换行符在每一行的结尾。
* timeout (*int*) —— 最大超时时间。

输出:`exceptions.EOFError` —— 在请求满足之前链接关闭。

返回:一个包含从socket接收的字节的字符串，或当等待超时时返回''。

#### 例

```shell
>>> t = tube()
>>> t.recv_raw = lambda n: '\n'
>>> t.recvlines(3)
['', '', '']
>>> t.recv_raw = lambda n: 'Foo\nBar\nBaz\n'
>>> t.recvlines(3)
['Foo', 'Bar', 'Baz']
>>> t.recvlines(3, True)
['Foo\n', 'Bar\n', 'Baz\n']
```

`recvn(`*`numb, timeout = default`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L200-244)

接收刚好`numb`个字节。

如果在`timeout`秒之前请求未被满足，所有数据会被置入缓冲区并返回一个空字符串(`''`)。

输出:`exceptions.EOFError` —— 在请求满足之前链接关闭。

返回:一个包含从socket接收的字节的字符串，或当等待超时时返回''。

#### 例

```shell
>>> t = tube()
>>> data = 'hello world'
>>> t.recv_raw = lambda *a: data
>>> t.recvn(len(data)) == data
True
>>> t.recvn(len(data)+1) == data + data[0]
True
>>> t.recv_raw = lambda *a: None
>>> # The remaining data is buffered
>>> t.recv() == data[1:]
True
>>> t.recv_raw = lambda *a: time.sleep(0.01) or 'a'
>>> t.recvn(10, timeout=0.05)
''
>>> t.recvn(10, timeout=0.06) 
'aaaaaa...'
```

`recvpred(`*`pred, timeout = default`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L161-198)

每次只接收一个字节的数据, 直到`pred(bytes)`变成True。

如果在`timeout`秒之前请求未被满足，所有数据会被置入缓冲区并返回一个空字符串(`''`)。

参数:	
* pred (*callable*) – 调用带有当前积累的数据的函数。
* timeout (*int*) – 操作超时时间。

输出:`exceptions.EOFError` —— 链接关闭。

返回: 一个包含从socket接收的字节的字符串，或当等待超时时返回''。

`recvregex(`*`regex, exact = False, timeout = default`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L578-599)

封装`recvpred()`,当正则表达式匹配缓冲区中的字符时将其返回。

默认使用`re.RegexObject.search()`，但是当`exact`设置为True时改用`re.RegexObject.match()`。

如果在`timeout`秒之前请求未被满足，所有数据会被置入缓冲区并返回一个空字符串(`''`)。

`recvrepeat(`*`timeout = default`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L624-654)

接收数据直到接收到EOF或超时。

#### 例

```shell
>>> data = [
... 'd',
... '', # simulate timeout
... 'c',
... 'b',
... 'a',
... ]
>>> def delayrecv(n, data=data):
...     return data.pop()
>>> t = tube()
>>> t.recv_raw = delayrecv
>>> t.recvrepeat(0.2)
'abc'
>>> t.recv()
'd'
```

`recvuntil(`*`delims, timeout = default`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L246-333)

接收数据直到遇到其中一个`delims`。

如果在`timeout`秒之前请求未被满足，所有数据会被置入缓冲区并返回一个空字符串(`''`)。

参数:	
* delims (*str,tuple*) – 有关分隔符的字符串或者列表。
* drop (*bool*) – 删除结尾。 如果为`True`，从返回值的结尾移除。

输出:`exceptions.EOFError` —— 在请求满足之前链接关闭。

返回:	一个包含从socket接收的字节的字符串，或当等待超时时返回''。

#### 例

```shell
>>> t = tube()
>>> t.recv_raw = lambda n: "Hello World!"
>>> t.recvuntil(' ')
'Hello '
>>> _=t.clean(0)
>>> # Matches on 'o' in 'Hello'
>>> t.recvuntil(tuple(' Wor'))
'Hello'
>>> _=t.clean(0)
>>> # Matches expressly full string
>>> t.recvuntil(' Wor')
'Hello Wor'
>>> _=t.clean(0)
>>> # Matches on full string, drops match
>>> t.recvuntil(' Wor', drop=True)
'Hello'
```

```shell
>>> # Try with regex special characters
>>> t = tube()
>>> t.recv_raw = lambda n: "Hello|World"
>>> t.recvuntil('|', drop=True)
'Hello'
```

`send(`*`data`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L678-707)

发送数据

如果日志等级是DEBUG，那么同时输出接收到的数据。

如果因为链接关闭而无法发送更多数据，则输出`exceptions.EOFError`。

#### 例

```shell
>>> def p(x): print repr(x)
>>> t = tube()
>>> t.send_raw = p
>>> t.send('hello')
'hello'
```

`sendafter(`*`delim, data, timeout = default`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L732-740)

方法`recvuntil(delim, timeout)`和`send(data)`的结合。

`sendline(`*`data`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L709-726)

对`t.send(data + t.newline).`的速记。

#### 例

```shell
>>> def p(x): print repr(x)
>>> t = tube()
>>> t.send_raw = p
>>> t.sendline('hello')
'hello\n'
>>> t.newline = '\r\n'
>>> t.sendline('hello')
'hello\r\n'
```

`sendlineafter(`*`delim, data, timeout = default`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L742-749)

方法`recvuntil(delim, timeout)`和`sendline(data)`的结合。

`sendlinethen(`*`delim, data, timeout = default`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L759-765)

方法`sendline(data)`和`recvuntil(delim, timeout)`的结合。

`sendthen(`*`delim, data, timeout = default`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L751-757)

方法`send(data)`和`recvuntil(delim, timeout)`的结合

`settimeout(`*`timeout`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L1083-1099)

设置接收操作的超时时间。如果使用的是字符串"defalut"，则使用`context.timeout`的参数。如果什么都没有提供则无超时时间。

#### 例

```shell
>>> t = tube()
>>> t.settimeout_raw = lambda t: None
>>> t.settimeout(3)
>>> t.timeout == 3
True
```

`shutdown(`*`direction = "send"`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L1114-1149)

根据`direction`关闭通信通道以方便进一步的读取或写入。

参数:direction(*str*) —— 关闭的方向:"in","read"或"recv"从输入方向关闭通道；"out","write"或"send"从输出方向关闭通道。

返回:`None`

`spawn_process(`*`*args, **kwargs`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L996-1007)

生成一个新的进程，把通信通道作为stdin,stdout和stderr。

采用和`subprocess.Popen`相同的参数。

`stream()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L819-846)

接收数据直到退出通信通道，然后输出到stdout。

和`interactive()`类似，但是不发送出入。

和`print tube.recvall()`类似，不同之处在于数据在接收时马上打印，而不是接收所有数据后打印。

`timeout_change()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L1239-1250)

通知通信通道的原始层超时条件被更改。

不能被直接调用。

从超时开始继承。

`unrecv(`*`data`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L80-100)

将指定数据放回到接收缓冲区的开头

#### 例

```shell
>>> t = tube()
>>> t.recv_raw = lambda n: 'hello'
>>> t.recv()
'hello'
>>> t.recv()
'hello'
>>> t.unrecv('world')
>>> t.recv()
'world'
>>> t.recv()
'hello'
```

`wait()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L1053-1057)

等待直到通信通道关闭。


`wait_for_close()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py#L1053-1057)

等待直到通信通道关闭。

`newline=`*`\n`* [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/tube.py)

用于`sendline()`，`recvline()`和相关函数的分隔符。
