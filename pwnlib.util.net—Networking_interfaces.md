# pwnlib.util.net — Networking interfaces

### `pwnlib.util.net.getifaddrs() → dict list` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/net.py#L74-121)

libc中`getifaddrs`的封装。

参数:	无

返回:	代表结构`ifaddrs`的字典list。字典包含字段`name`，`flags`，`family`，`addr` 和 `netmask`。 详情参考`getifaddrs(3)`。 字段`addr`和`netmask`本身也是字典，它们的结构取决于`family`，如果`family`不是`socket.AF_INET`或`socket.AF_INET6`，那么它们为空。

### `pwnlib.util.net.interfaces(`*`all = False`*`) → dict` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/net.py#L123-147)

参数:	
* all (*bool*) – 是否包含不相关地址的接口。
* Default – `False`

返回:	将每个主机接口映射到有其地址的list的字典，每个list中的空位是一个tuple`(family, addr)`，并且`family`是 `either socket.AF_INET`或`socket.AF_INET6`。

### `pwnlib.util.net.interfaces4(`*`all = False`*`) → dict` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/net.py#L170-189)

和`interfaces()`类似但只包含IPv4地址，并且字典中的list只包含地址而不是family。

参数:	
* all (*bool*) – 是否包含不相关地址的接口。
* Default – `False`

返回:	将每个主机接口映射到有其IPv4地址的list的字典。

### `pwnlib.util.net.interfaces6(`*`all = False`*`) → dict` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/net.py#L170-189)

和`interfaces()`类似但只包含IPv6地址，并且字典中的list只包含地址而不是family。

参数:	
* all (*bool*) – 是否包含不相关地址的接口。
* Default – `False`

返回:	将每个主机接口映射到有其IPv6地址的list的字典。

### `pwnlib.util.net.sockaddr(`*`host, port, network = 'ipv4') -> (data, length, family`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/net.py#L191-226)

创建一个`sockaddr_in`或`sockaddr_in6`内存缓冲区用于shellcode

参数:	
* host (*str*) – 用于抬头的IP地址或主机名
* port (*int*) – TCP/UDP端口
* network (*str*) – ‘ipv4’或‘ipv6’

返回:	
一个包括sockaddr缓冲数据，长度与地址的family的tuple。