# pwnlib.ui — Functions for user interaction

### `pwnlib.ui.more(`*`text`*`)` [source](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/ui.py#L168-192)

显示类似命令行工具`more`的文本。

如果不在term_mode，只输出数据到屏幕上。

参数:	text (*str*) – 显示的文本。

返回:	`None`

### `pwnlib.ui.options(`*`prompt, opts, default=None`*`)` [source](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/ui.py#L63-147)

显示给用户提示(通常以问题的形式)和一些选项。

参数:	
* prompt (*str*) – 显示的提示
* opts (*list*) – 显示给用户的选项
* default – 默认选项

返回:	以整数表示的用户选项。

### `pwnlib.ui.pause(`*`n=None`*`)` [source](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/ui.py#L149-166)

等待用户输入或指定的秒数。

### `pwnlib.ui.yesno(`*`prompt, default=None`*`)` [source](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/ui.py#L11-61)

显示给用户提示(通常以问题的形式)，用户必须选择是或否。

参数:	
* prompt (*str*) – 显示的提示。
* default – 默认选项；`True`表示“是”

返回:	如果为“是”则返回`True`，如果为“否”则返回`False`。

