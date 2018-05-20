# pwnlib.util.proc — Working with `/proc/`

### `pwnlib.util.proc.ancestors(`*`pid`*`) → int list` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/proc.py#L134-147)

参数:	pid (*int*) – 进程的PID。

返回:	其父类进程为`pid`或`pid`的祖先的pid的list。

### `pwnlib.util.proc.children(`*`ppid`*`) → int list` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/proc.py#L123-132)

参数:	pid (*int*) – 进程的PID。

返回:	其父类进程为`pid`的pid的list

### `pwnlib.util.proc.cmdline(`*`pid`*`) → str list` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/proc.py#L194-203)

参数:	pid (*int*) – 进程的PID。

返回:	`/proc/<pid>/cmdline`中的字段的list。

### `pwnlib.util.proc.cwd(`*`pid`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/proc.py#L182-192)

参数:	pid (*int*) – 进程的PID。

返回:	当前进程工作目录的路径。即`/proc/<pid>/cwd`的指向。

### `pwnlib.util.proc.descendants(`*`pid`*`) → dict` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/proc.py#L149-169)

参数:	pid (*int*) – 进程的PID。

返回:	字典映射`pid`的每个子进程的pid到它的子进程。

### `pwnlib.util.proc.exe(`*`pid`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/proc.py#L171-180)

参数:	pid (*int*) – 进程的PID。

返回:	进程的二进制路径。即`/proc/<pid>/exe`的指向。 

### `pwnlib.util.proc.name(`*`pid`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/proc.py#L92-106)

参数:	pid (*int*) – 进程的PID。

返回:	`/proc/<pid>/status`的list中的进程名称。

#### 例

```shell
>>> pid = pidof('init')[0]
>>> name(pid) == 'init'
True
```

### `pwnlib.util.proc.parent(`*`pid`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/proc.py#L108-121)

参数:	pid (*int*) – 进程的PID。

返回:	`PPid`的`/proc/<pid>/status`中列出的父类`pid`，如果没有父类则为0。

### `pwnlib.util.proc.pid_by_name(`*`name`*`) → int list` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/proc.py#L61-90)

参数:	name (*str*) – 程序的名称。

返回:	按照从最小到最老的生命周期排序的有关pid的list。

#### 例

```shell
>>> os.getpid() in pid_by_name(name(os.getpid()))
True
```

### `pwnlib.util.proc.pidof(`*`target`*`) → int list` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/proc.py#L16-59)

获取`target`的pid。返回的pid取决于`target`的类型：
* `str`: 所有匹配`target`名称的进程的pid。
* `pwnlib.tubes.process.process`: `target`的pid的单例list。
* `pwnlib.tubes.sock.sock`: 如果在主机上运行，则为`target`远程终端的pdi单列list。 否则为空list。

参数:	target (*object*) – 查找pid的目标。

返回:	找到的pid的list。

### `pwnlib.util.proc.starttime(`*`pid`*`) → float` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/proc.py#L222-231)

参数:	pid (*int*) – 进程的PID。

返回:	系统引导后进程开始的时间（以秒为单位）。

### `pwnlib.util.proc.stat(`*`pid`*`) → str list` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/proc.py#L205-220)

参数:	pid (*int*) – 进程的PID。

返回:	`/proc/<pid>/stat`中的值的list， 但是（和）已从进程名称空间删除。

### `pwnlib.util.proc.state(`*`pid`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/proc.py#L275-288)

参数:	pid (*int*) – 进程的PID。

返回:	`/proc/<pid>/status`中列出的进程状态。详情查看`proc(5)`。

#### 例

```shell
>>> state(os.getpid())
'R (running)'
```

### `pwnlib.util.proc.status(`*`pid`*`) → dict` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/proc.py#L233-257)

获取进程状态

参数:	pid (*int*) – 进程的PID。

返回:	`/proc/<pid>/status`中的内容作为字典。

### `pwnlib.util.proc.tracer(`*`pid`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/proc.py#L259-273)

参数:	pid (*int*) – 进程的PID。

返回:	追踪`pid`的进程的pid。如果没有`pid`正在被追踪则为`None`.

#### 例

```shell
>>> tracer(os.getpid()) is None
True
```

### `pwnlib.util.proc.wait_for_debugger(`*`pid`*`) → None` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/proc.py#L290-304)

一直睡眠直到带有程序的pid为`pid`被追踪。

参数:	pid (*int*) – 进程的PID。

返回: `None`