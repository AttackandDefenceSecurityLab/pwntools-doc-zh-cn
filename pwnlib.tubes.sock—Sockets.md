# pwnlib.tubes.sock — Sockets

### *`class`* `pwnlib.tubes.sock.sock` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/sock.py)

基类: `pwnlib.tubes.tube.tube`

用于`tubes.remote`和`tubes.listen`类的基础类型。

### *`class`* `pwnlib.tubes.remote.remote(`*`host, port, fam='any', typ='tcp', ssl=False, sock=None, *args, **kwargs`*`)`

基类：`pwnlib.tubes.sock.sock`

建立到远程主机的TCP/UDP链接，支持IPV4和IPV6。

返回值支持`pwnlib.tubes.sokc`和`pwnlib.tubes.tube`的所有方法。

参数:	
* host (*str*) – 链接的主机。
* port (int) – 链接的端口。
* fam – 用于传递给`socket.getaddrinfo()`的字符串：“any”，“ipv4”，“ipv6”或一个整数。
* typ – 用于传递给`socket.getaddrinfo()`的字符串：“tcp”，“udp”或一个整数。
* timeout – 一个正数,None或者字符串“default”。
* ssl (*bool*) – 用SSL封装socket。
* sock (*socket.socket*) – 用于继承的Socket，而不是用于链接。

#### 例

```shell
>>> r = remote('google.com', 443, ssl=True)
>>> r.send('GET /\r\n\r\n')
>>> r.recvn(4)
'HTTP'
```

如果无法建立链接会输出一个异常

```shell
>>> r = remote('127.0.0.1', 1)
Traceback (most recent call last):
...
PwnlibException: Could not connect to 127.0.0.1 on port 1
```

你也可以使用`remote.fromsocket()`来封装一个现有的socket.

```shell
>>> import socket
>>> s = socket.socket()
>>> s.connect(('google.com', 80))
>>> s.send('GET /' + '\r\n'*2)
9
>>> r = remote.fromsocket(s)
>>> r.recvn(4)
'HTTP'
```

`classmethod fromsocket(`*`socket`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/remote.py#L112-126)

用通道API来封装一个标准python`socket.socket`的辅助方法。

参数:	socket – socket.socket实例

返回:	pwnlib.tubes.remote.remote.实例

### *`class`* `pwnlib.tubes.listen.listen(`*`port=0, bindaddr='0.0.0.0', fam='any', typ='tcp', *args, **kwargs`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/listen.py)

基类：`pwnlib.tubes.sock.sock`

建立一个TCP/UDP的socket来接收数据。支持IPV4和IPV6。

返回值支持`pwnlib.tubes.sock`和`pwnlib.tubes.tube`的所有方法

参数:	
* port (*int*) – 链接的端口。默认为操作系统自动选择的端口。
* bindaddr (*str*) – 捆绑的地址。默认为0.0.0.0 / ::。
* fam – 用于传递给`socket.getaddrinfo()`的字符串：“any”，“ipv4”，“ipv6”或一个整数。
* typ – 用于传递给`socket.getaddrinfo()`的字符串：“tcp”，“udp”或一个整数。

#### 例

```shell
>>> l = listen(1234)
>>> r = remote('localhost', l.lport)
>>> _ = l.wait_for_connection()
>>> l.sendline('Hello')
>>> r.recvline()
'Hello\n'
```

```shell
>>> l = listen()
>>> l.spawn_process('/bin/sh')
>>> r = remote('localhost', l.lport)
>>> r.sendline('echo Goodbye')
>>> r.recvline()
'Goodbye\n'
```

`wait_for_connection()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/listen.py#L145-148)

阻止直到链接建立

`canonname =` `*None*` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/listen.py)

监听界面的规范名称

`family =` `*None*` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/listen.py)

Socket系

`lhost =` `*None*` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/listen.py)

本地主机

`lport =` *`0`* [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/listen.py)

本地端口

`protocol =` `*None*` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/listen.py)

Socket协议

`sockaddr =` `*None*` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/listen.py)

被监听的Sockaddr结构

`type =` `*None*` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/listen.py)

Socket类型(例：socket.SOCK_STREAM)

### *`class`* `pwnlib.tubes.server.server(`*`port=0, bindaddr='0.0.0.0', fam='any', typ='tcp', callback=None, blocking=False, *args, **kwargs`*`)` [source](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/server.py)

基类: `pwnlib.tubes.sock.sock`

建立一个TCP/UDP服务来监听链接。支持IPV4和IPV6。

参数:	
* port (*int*) – 链接的端口。默认为操作系统自动选择的端口。
* bindaddr (*str*) – 捆绑的地址。默认为0.0.0.0 / ::。
* fam – 用于传递给`socket.getaddrinfo()`的字符串：“any”，“ipv4”，“ipv6”或一个整数。
* typ – 用于传递给`socket.getaddrinfo()`的字符串：“tcp”，“udp”或一个整数。
* callback – 一个开始于传入链接的功能， 会使用`pwnlib.tubes.remote`作为其唯一参数。

#### 例

```shell
>>> s = server(8888)
>>> client_conn = remote('localhost', s.lport)
>>> server_conn = s.next_connection()
>>> client_conn.sendline('Hello')
>>> server_conn.recvline()
'Hello\n'
>>> def cb(r):
...     client_input = r.readline()
...     r.send(client_input[::-1])
...
>>> t = server(8889, callback=cb)
>>> client_conn = remote('localhost', t.lport)
>>> client_conn.sendline('callback')
>>> client_conn.recv()
'\nkcabllac'
```

`canonname =` `*None*` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/listen.py)

监听界面的规范名称

`family =` `*None*` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/listen.py)

Socket系

`lhost =` `*None*` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/listen.py)

本地主机

`lport =` *`0`* [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/listen.py)

本地端口

`protocol =` `*None*` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/listen.py)

Socket协议

`sockaddr =` `*None*` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/listen.py)

被监听的Sockaddr结构

`type =` `*None*` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/tubes/listen.py)

Socket类型(例：socket.SOCK_STREAM)