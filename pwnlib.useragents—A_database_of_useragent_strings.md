# pwnlib.useragents — A database of useragent strings

大于22,000个用户代理字符串的数据库。

### `pwnlib.useragents.getall() → str set` [source](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/useragents.py#L23-40)

获取所知的所有用户代理。

参数:	**None –**

返回:	一套用户代理字符串

#### 例

```shell
>>> 'libcurl-agent/1.0' in getall()
True
>>> 'wget' in getall()
True
```

### `pwnlib.useragents.random() → str` [source](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/useragents.py#L42-58)

获取一个随机的用户代理字符串。

参数:	**None –**

返回:	一个由`getall()`选择的随机用户代理字符串。

```shell
>>> import random as randommod
>>> randommod.seed(1)
>>> random()
'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; FunWebProducts; FunWebProducts-MyTotalSearch; iebar)'
```
