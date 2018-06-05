## `pwnlib.config` - Pwntools配置文件

允许每个用户和每个主机配置Pwntools设置。

可配置选项列表包括所有日志记录符号和颜色，以及全局context对象上的所有默认值。

配置文件是从`~/.pwn.conf`和`/etc/pwn.conf`中读取的。

配置文件只能在`from pwn import *`模式读入，而不能在库模式下使用（`import pwnlib`）。若要在库模式下读取配置文件，请调用`config.initialize()`。

`context`部分支持复杂类型，至少在`pwnlib.util.safeeval.expr`支持的范围内。

```
[log]
success.symbol=😎
error.symbol=☠
info.color=blue

[context]
adb_port=4141
randomize=1
timeout=60
terminal=['x-terminal-emulator', '-e']
```