# pwnlib.timeout — Timeout handling

封装了超时相关功能，包括倒计时和范围管理器。

### *`class`* `pwnlib.timeout.Timeout(`*`timeout=pwnlib.timeout.Timeout.default`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/timeout.py)

实现一个具有超时功能的基本类，并支持范围内的超时倒计时。

有效的超时值:

* `Timeout.default`使用全局默认值(`context.default`)
* `Timeout.forever`或`None`表示不会超时。
* 任何可用的浮点数，以秒为超时单位

#### 例

```shell
>>> context.timeout = 30
>>> t = Timeout()
>>> t.timeout == 30
True
>>> t = Timeout(5)
>>> t.timeout == 5
True
>>> i = 0
>>> with t.countdown():
...     print (4 <= t.timeout and t.timeout <= 5)
...
True
>>> with t.countdown(0.5):
...     while t.timeout:
...         print round(t.timeout,1)
...         time.sleep(0.1)
0.5
0.4
0.3
0.2
0.1
>>> print t.timeout
5.0
>>> with t.local(0.5):
...     for i in range(5):
...         print round(t.timeout,1)
...         time.sleep(0.1)
0.5
0.5
0.5
0.5
0.5
>>> print t.timeout
5.0
```

`countdown(`*`timeout=pwnlib.timeout.Timeout.default`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/timeout.py#L175-198)

作用域超时设置器。设置范围内的超时时间，并在超出范围时恢复。

在范围内达到`timeout`，则会通过倒计时的方式计算输入范围的时间。

如果`None`被指定为`timeout`，那么使用当前会被设置为超时。这允许`None`被指定为具有较小复杂度的默认参数。

`local(`*`timeout`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/timeout.py#L200-208)

作用域超时设置器。设置范围内的超时时间，并在超出范围时恢复。

`timeout_change()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/timeout.py#L169-173)

用于提供给子类来hook超时变化。

`default =` *`pwnlib.timeout.Timeout.default`* [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/timeout.py)

指出超时时不应更改的值

`forever =` *`None`* [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/timeout.py)

指出超时不应出现的值。

`maximum =` *`pwnlib.timeout.maximum`* [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/timeout.py)

超时时间的最大值，用于解决具有较大超时时间的平台问题。

OSX不允许设置socket的超时时间为2**22，假设我们接收到等于或大于2**21的超时时间，实际上该值为无限。

`timeout` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/timeout.py)

obj操作的超时设置，默认使用`context.timeout`。
