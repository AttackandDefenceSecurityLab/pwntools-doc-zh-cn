# pwnlib.update — Updating Pwntools

\# Pwntools的升级

为了确保Pwntools的用户能一直用到最新最好的版本，Pwntools会自动检查升级。

因为升级检查会需要一些时间，所以每周只执行一次。可以通过以下方式永久禁用：

`$ echo never > ~/.pwntools-cache/update`

### `pwnlib.update.available_on_pypi(`*`prerelease=False`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/update.py#L39-54)

如果PyPI上有可用的更新则返回`True`。

```shell
>>> available_on_pypi() 
<Version('...')>
>>> available_on_pypi(prerelease=False).is_prerelease
False
```

### `pwnlib.update.cache_file()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/update.py#L56-71)

返回用于缓存升级数据的文件路径，并确认其是否存在。

### `pwnlib.update.last_check()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/update.py#L73-80)

返回最后一次升级检查的日期。

### `pwnlib.update.perform_check(`*`prerelease=False`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/update.py#L94-156)

进行升级检查并报告给用户。

参数:	prerelease (*bool*) – 是否包含预发行版本。

返回:	升级命令的参数列表。

```shell
>>> from packaging.version import Version
>>> pwnlib.update.current_version = Version("999.0.0")
>>> print perform_check()
None
>>> pwnlib.update.current_version = Version("0.0.0")
>>> perform_check() 
['pip', 'install', '-U', ...]
```

```shel
>>> def bail(*a): raise Exception()
>>> pypi   = pwnlib.update.available_on_pypi
```

```shell
>>> perform_check(prerelease=False)
['pip', 'install', '-U', 'pwntools']
>>> perform_check(prerelease=True)  
['pip', 'install', '-U', 'pwntools...']
```

### `pwnlib.update.should_check()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/update.py#L82-92)

如果应进行升级检查则返回`True`。
