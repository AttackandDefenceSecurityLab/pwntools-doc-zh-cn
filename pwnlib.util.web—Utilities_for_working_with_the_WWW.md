# pwnlib.util.web — Utilities for working with the WWW

### `pwnlib.util.web.wget(`*`url, save=None, timeout=5`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/web.py#L13-78)

通过HTTP/HTTPS下载文件。

参数:	
* url (*str*) – 下载的URL
* save (*str or bool*) – 另存为的名称， 任何真实的值都会自动通过URL生成一个名字。
* timeout (*int*) – 超时时间，以秒为单位。

#### 例

```shell
>>> url    = 'https://httpbin.org/robots.txt'
>>> result = wget(url, timeout=60)
>>> result
'User-agent: *\nDisallow: /deny\n'
>>> result2 = wget(url, True, timeout=60)
>>> result == file('robots.txt').read()
True
```