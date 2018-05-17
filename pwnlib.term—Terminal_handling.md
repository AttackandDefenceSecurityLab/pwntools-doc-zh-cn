# pwnlib.term — Terminal handling

>### `pwnlib.term.can_init()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/term.py#L23-55)

如果stderr是终端（TTY）而且不在REPL内，则该函数返回`True`。如果该函数返回`True`，对`init()`的调用会使`pwnlib` 控制终端。

>### `pwnlib.term.init()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/term.py#L58-83)

调用该函数将会接管终端 (如果`can_init()`返回`True`) ，直到当前python解释器关闭。

在TODO上，创建一个功能，在不关闭解释器的情况下，将终端控制“返回”。

>### `pwnlib.term.term_mode =` *`False`* [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/term.py)

当我们使用`init()`接管终端时，这个选项应为`True`。
