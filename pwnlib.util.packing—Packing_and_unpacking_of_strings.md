# pwnlib.util.packing — Packing and unpacking of strings

用于打包和解包整数的模块。

简化对标准`struct.pack`和`struct.unpack`函数的访问，同时增加对任意宽度整数的打包/解包的支持。

封包器对`endian`和`signed`参数是全文感知的，尽管它们可以在参数中被覆盖。

#### 例

```shell
>>> p8(0)
'\x00'
>>> p32(0xdeadbeef)
'\xef\xbe\xad\xde'
>>> p32(0xdeadbeef, endian='big')
'\xde\xad\xbe\xef'
>>> with context.local(endian='big'): p32(0xdeadbeef)
'\xde\xad\xbe\xef'
```

设置一个固定的不会被context更改的封包器

```shell
>>> p=make_packer('all')
>>> p(0xff)
'\xff'
>>> p(0x1ff)
'\xff\x01'
>>> with context.local(endian='big'): print repr(p(0x1ff))
'\xff\x01'
```

### `pwnlib.util.packing.dd(`*`dst, src, count = 0, skip = 0, seek = 0, truncate = False`*`) → dst` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/packing.py#L683-861)

受到命令行工具`dd`的启发，这个函数将`count`字节值从`src`中的偏移量`seek`复制到`dst`的偏移量`skip`中。如果`count`为0，所有`src[seek:]`将会被复制。

如果`dst`是一个可变类型，那么它将会被升级。否则将会创建相同类型的新实例。无论哪种结果，结果将会被返回。

`src`可以是iterable类型的字符或者是整数，unicode字符串或者是文件对象。如果是一个iterable类型整数，每个整数必须在范围[0;255]中。如果是一个unicode字符串，将使用其UTF-8编码。

文件对象的查找偏移量将会被保留。

参数:	
* dst – 支持的格式有`:class:file`，`:class:list`，`:class:tuple`，`:class:str`，`:class:bytearray`和`:class:unicode`。
* src – 一个iterable类型的字节值（字符或整数），一个unicode字符串或文件对象。
* count (*int*) –复制的字节数量。如果`count`为0或大于`len(src[seek:])`，所有`src`结尾前的字节都会被复制。
* skip (*int*) – 内容将会复制到的`dst`的偏移。
* seek (*int*) – 内容将从`src`的偏移中复制。
* truncate (*bool*) – 如果`:const:`为`True`，`dst`将在最后复制的字节处截断。

返回:	
`dst`的修改版本。如果`dst`是可变类型，那么将会在其本身进行修改。

#### 例

```shell
>>> dd(tuple('Hello!'), '?', skip = 5)
('H', 'e', 'l', 'l', 'o', '?')
>>> dd(list('Hello!'), (63,), skip = 5)
['H', 'e', 'l', 'l', 'o', '?']
>>> file('/tmp/foo', 'w').write('A' * 10)
>>> dd(file('/tmp/foo'), file('/dev/zero'), skip = 3, count = 4).read()
'AAA\x00\x00\x00\x00AAA'
>>> file('/tmp/foo', 'w').write('A' * 10)
>>> dd(file('/tmp/foo'), file('/dev/zero'), skip = 3, count = 4, truncate = True).read()
'AAA\x00\x00\x00\x00'
```

### `pwnlib.util.packing.fit(`*`pieces, filler = de_bruijn(), length = None, preprocessor = None`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/packing.py#L1388-1395)

从字典映射的中生成一个字符串作为数据放在该偏移处。

对于`pieces`中的每个键值对，键是一个偏移或一个字节序列。在后一种情况下，偏移将会成为序列在`filler`中最低位的索引。可以查看以下例子。

每个数据片段都会和关键参数`word_size`，`endianness`和`sign`一起传输给`flat()`。

数据片段之间的空间使用itearble`filler`，如果输出的第`n`个字节为有限长度或是在索引`n`处的字节，那么将会成为索引`n % len(iterable)`处的字节。

如果`length`是给定的，输出将会以该大小填充`filler`中的字节。如果输出大于该`length`，将会引发`ValueError`异常。

如果片段的条目重叠，将会引发`ValueError`异常。

参数:	
* pieces – 输出的值和偏移。
* length – 输出的长度
* filler – 用于填充的iterable。
* preprocessor (*function*) – 获取每个元素的调用并在展开之前可选择性地转换。如果返回`None`，那么将使用原始数据。
* word_size (*int*) – 转换整数的字节大小 （以bits为单位）。
* endianness (*str*) – 转换后整数的字节序 (“little”/”big”)。
* sign (*str*) – 转换整数的符号 (`False`/`True`)

#### 例

```shell
>>> fit({12: 0x41414141,
...      24: 'Hello',
...     })
'aaaabaaacaaaAAAAeaaafaaaHello'
>>> fit({'caaa': ''})
'aaaabaaa'
>>> fit({12: 'XXXX'}, filler = 'AB', length = 20)
'ABABABABABABXXXXABAB'
>>> fit({ 8: [0x41414141, 0x42424242],
...      20: 'CCCC'})
'aaaabaaaAAAABBBBeaaaCCCC'
>>> fit({ 0x61616162: 'X'})
'aaaaX'
```

### `pwnlib.util.packing.flat(`*`*args, preprocessor = None, word_size = None, endianness = None, sign = None`*`) [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/packing.py#L1388-1395)

展开参数为字符串格式。

这个函数采用任意数量的任意嵌套list和tuple。然后会查找其中的每一个字符串和数字并将其展开。字符串会在数字使用`pack()`函数打包时直接插入。

如果`word_size`，`endianness`和`sign`没有被指定为参数，那么将会使用`pwnlib.context`中的值。

参数:	
* args – 用于展开的的值
* preprocessor (*function*) – 获取每个元素的调用并在展开之前可选择性地转换。如果返回`None`，那么将使用原始数据。
* word_size (*int*) – 转换整数的字节大小 （以bits为单位）。
* endianness (*str*) – 转换后整数的字节序 (“little”/”big”)。
* sign (*str*) – 转换整数的符号 (`False`/`True)

#### 例

```shell
>>> flat(1, "test", [[["AB"]*2]*3], endianness = 'little', word_size = 16, sign = False)
'\x01\x00testABABABABABAB'
>>> flat([1, [2, 3]], preprocessor = lambda x: str(x+1))
'234'
```

### `pwnlib.util.packing.make_packer(`*`word_size = None, endianness = None, sign = None`*`) → number → str` [源码]()

通过“固定”给定的参数来创建一个解包器。

语义上，调用`make_packer(w, e, s)(data)`相当于调用`pack(data, w, e, s)`。如果`word_size`是8，16，32或64之中一个，那么调用该函数将会更快，因为会使用特定版本。

参数:	
* word_size (*int*) – 转换整数的字节大小 （以bits为单位）。
* endianness (*str*) – 转换后整数的字节序 (“little”/”big”)。
* sign (*str*) – 转换整数的符号 (`False`/`True)
* kwargs – 通过别名设置的上下文标志。 (如 `endian=`，而不是使用索引）

返回:	以一个字符串的形式获取一个参数，并返回其解包格式的数字的函数。

#### 例

```shell
>>> p = make_packer(32, endian='little', sign='unsigned')
>>> p
<function _p32lu at 0x...>
>>> p(42)
'*\x00\x00\x00'
>>> p(-1)
Traceback (most recent call last):
    ...
error: integer out of range for 'I' format code
>>> make_packer(33, endian='little', sign='unsigned')
<function <lambda> at 0x...>
```

### `pwnlib.util.packing.make_unpacker(word_size = None, endianness = None, sign = None, **kwargs) → str → number[源码]\

通过“固定”给定的参数来创建一个解包器。

语义上，调用`make_packer(w, e, s)(data)`相当于调用`pack(data, w, e, s)`。如果`word_size`是8，16，32或64之中一个，那么调用该函数将会更快，因为会使用特定版本。

参数:	
* word_size (*int*) – 转换整数的字节大小 （以bits为单位）。
* endianness (*str*) – 转换后整数的字节序 (“little”/”big”)。
* sign (*str*) – 转换整数的符号 (`False`/`True)
* kwargs – 通过别名设置的上下文标志。 (如 `endian=`，而不是使用索引）

返回:	以一个字符串的形式获取一个参数，并返回其解包格式的数字的函数。

#### 例

```shell
>>> u = make_unpacker(32, endian='little', sign='unsigned')
>>> u
<function _u32lu at 0x...>
>>> hex(u('/bin'))
'0x6e69622f'
>>> u('abcde')
Traceback (most recent call last):
    ...
error: unpack requires a string argument of length 4
>>> make_unpacker(33, endian='little', sign='unsigned')
<function <lambda> at 0x...>
```

### `pwnlib.util.packing.p16(`*`number, sign, endian, ...`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/packing.py#L1388-1395)

打包一个16位整数。

参数:	
* number (*int*) – 用于转换的数字
* endianness (*str*) – 转换后整数的字节序 (“little”/”big”)。
* sign (*str*) – 已转换数字的签名 (“unsigned”/”signed”)
* kwargs (*dict*) – 传送给`context.local()`的参数，如`endian`或`signed`。

返回:	字符串形式的已打包数字。

### `pwnlib.util.packing.p32(`*`number, sign, endian, ...`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/packing.py#L1388-1395)

打包一个32位整数.

参数:	
* number (*int*) – 用于转换的数字
* endianness (*str*) – 转换后整数的字节序 (“little”/”big”)。
* sign (*str*) – 已转换数字的签名 (“unsigned”/”signed”)
* kwargs (*dict*) – 传送给`context.local()`的参数，如`endian`或`signed`。

返回:	字符串形式的已打包数字。

### `pwnlib.util.packing.p64(`*`number, sign, endian, ...`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/packing.py#L1388-1395)

打包一个64位整数。

参数:	
* number (*int*) – 用于转换的数字
* endianness (*str*) – 转换后整数的字节序 (“little”/”big”)。
* sign (*str*) – 已转换数字的签名 (“unsigned”/”signed”)
* kwargs (*dict*) – 传送给`context.local()`的参数，如`endian`或`signed`。

返回:	字符串形式的已打包数字。

### `pwnlib.util.packing.p8(`*`number, sign, endian, ...`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/packing.py#L1388-1395)

打包一个8位整数。

参数:	
* number (*int*) – 用于转换的数字
* endianness (*str*) – 转换后整数的字节序 (“little”/”big”)。
* sign (*str*) – 已转换数字的签名 (“unsigned”/”signed”)
* kwargs (*dict*) – 传送给`context.local()`的参数，如`endian`或`signed`。

返回:	字符串形式的已打包数字。

### `pwnlib.util.packing.pack(`*`number, word_size = None, endianness = None, sign = None, **kwargs`*`) → str`[源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/packing.py#L1388-1395)

打包任意大小的整数。

根据context来决定`world _size`，`endianness`，`signedness`。

`word_size` 可以是任意数字或字符串"all"，选择字符串"all"会输出一个足够长的字符串来包含所有有效位，因此可以通过`unpack()`解码。

`word_size`可以是任意正数，输出将会包含`word_size/8`向上舍入的字节数。如果`word_size`不是8的倍数，那么将会用0填充到字节边界。 

参数:	
* number (*int*) – 用于转换的数字
* word_size (*int*) – 转换整数的字节大小 （以bits为单位）。
* endianness (*str*) – 转换后整数的字节序 (“little”/”big”)。
* sign (*str*) – 已转换数字的签名 (“unsigned”/”signed”)
* kwargs (*dict*) – 传送给`context.local()`的参数，如`endian`或`signed`。

返回:	字符串形式的已打包数字。

#### 例

```shell
>>> pack(0x414243, 24, 'big', True)
'ABC'
>>> pack(0x414243, 24, 'little', True)
'CBA'
>>> pack(0x814243, 24, 'big', False)
'\x81BC'
>>> pack(0x814243, 24, 'big', True)
Traceback (most recent call last):
   ...
ValueError: pack(): number does not fit within word_size
>>> pack(0x814243, 25, 'big', True)
'\x00\x81BC'
>>> pack(-1, 'all', 'little', True)
'\xff'
>>> pack(-256, 'all', 'big', True)
'\xff\x00'
>>> pack(0x0102030405, 'all', 'little', True)
'\x05\x04\x03\x02\x01'
>>> pack(-1)
'\xff\xff\xff\xff'
>>> pack(0x80000000, 'all', 'big', True)
'\x00\x80\x00\x00\x00'
```

### `pwnlib.util.packing.routine(`*`*a, **kw`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/packing.py#L1388-1395)

u32(number, sign, endian, …) -> int

解包一个32位整数。

参数:	
* data (*str*) – 用于转换的字符串。
* endianness (*str*) – 转换后整数的字节序 (“little”/”big”)。
* sign (*str*) – 已转换数字的签名 (“unsigned”/”signed”)
* kwargs (*dict*) – 传送给`context.local()`的参数，如`endian`或`signed`。

返回:	解包得到的数字。

### `pwnlib.util.packing.u16(`*`number, sign, endian, ...`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/packing.py#L1388-1395)

解包一个16位整数。

参数:	
* data (*str*) – 用于转换的字符串。
* endianness (*str*) – 转换后整数的字节序 (“little”/”big”)。
* sign (*str*) – 已转换数字的签名 (“unsigned”/”signed”)
* kwargs (*dict*) – 传送给`context.local()`的参数，如`endian`或`signed`。

返回:	解包得到的数字。

### `pwnlib.util.packing.u32(`*`number, sign, endian, ...`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/packing.py#L1388-1395)

解包一个32位整数。

参数:	
* data (*str*) – 用于转换的字符串。
* endianness (*str*) – 转换后整数的字节序 (“little”/”big”)。
* sign (*str*) – 已转换数字的签名 (“unsigned”/”signed”)
* kwargs (*dict*) – 传送给`context.local()`的参数，如`endian`或`signed`。

返回:	解包得到的数字。

### `pwnlib.util.packing.u64(`*`number, sign, endian, ...`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/packing.py#L1388-1395)

解包一个64位整数。

参数:	
* data (*str*) – 用于转换的字符串。
* endianness (*str*) – 转换后整数的字节序 (“little”/”big”)。
* sign (*str*) – 已转换数字的签名 (“unsigned”/”signed”)
* kwargs (*dict*) – 传送给`context.local()`的参数，如`endian`或`signed`。

返回:	解包得到的数字。

### `pwnlib.util.packing.u8(`*`number, sign, endian, ...`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/packing.py#L1388-1395)

解包一个8位整数。

参数:	
* data (*str*) – 用于转换的字符串。
* endianness (*str*) – 转换后整数的字节序 (“little”/”big”)。
* sign (*str*) – 已转换数字的签名 (“unsigned”/”signed”)
* kwargs (*dict*) – 传送给`context.local()`的参数，如`endian`或`signed`。

返回:	解包得到的数字。

### `pwnlib.util.packing.unpack(`*`data, word_size = None, endianness = None, sign = None, **kwargs`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/packing.py#L1388-1395)

解包任意大小的数字。

根据`context`来决定`Word-size`，`endianness`和 `signedness`。

`word_size`可以是任意正数或字符串"all"，如果选择字符串"all"等同于`len(data)*8`。

如果`word_size`不是8的倍数，那么将会抛弃用于填充的位。

参数:	
* number (*int*) – 用于转换的字符串
* word_size (*int*) – 转换的整数的字节大小或字符串"all" (以bits为单位)
* endianness (*str*) – 转换后的字节序 (“little”/”big”)
* sign (*str*) – 以转换数字的签名 (False/True)
* kwargs – 任何可以传送给`context.local`的值

返回:	解包得到的数字。

#### 例

```shell
>>> hex(unpack('\xaa\x55', 16, endian='little', sign=False))
'0x55aa'
>>> hex(unpack('\xaa\x55', 16, endian='big', sign=False))
'0xaa55'
>>> hex(unpack('\xaa\x55', 16, endian='big', sign=True))
'-0x55ab'
>>> hex(unpack('\xaa\x55', 15, endian='big', sign=True))
'0x2a55'
>>> hex(unpack('\xff\x02\x03', 'all', endian='little', sign=True))
'0x302ff'
>>> hex(unpack('\xff\x02\x03', 'all', endian='big', sign=True))
'-0xfdfd'
```

### `pwnlib.util.packing.unpack_many(`*`*a, **kw`*`) [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/packing.py#L1388-1395)

unpack(data, word_size = None, endianness = None, sign = None) -> int list

拆分数据为`word_size//8`字节的分组，并分别调用`unpack()`。返回结果的list。

`word_size`必须是8的倍数或字符串"all"。在后一个情况下，总会返回一个单例列表。

>Args:
>* number (*int*) – 用于转换的字符串
>* word_size (*int*) – 转换的整数的字节大小或字符串"all" (以bits为单位)
>* endianness (*str*) – 转换后的字节序 (“little”/”big”)
>* sign (*str*) – 以转换数字的签名 (False/True)
>* kwargs – 任何可以传送给`context.local`的值

返回:	解包得到的数字。

#### 例

```shell
>>> map(hex, unpack_many('\xaa\x55\xcc\x33', 16, endian='little', sign=False))
['0x55aa', '0x33cc']
>>> map(hex, unpack_many('\xaa\x55\xcc\x33', 16, endian='big', sign=False))
['0xaa55', '0xcc33']
>>> map(hex, unpack_many('\xaa\x55\xcc\x33', 16, endian='big', sign=True))
['-0x55ab', '-0x33cd']
>>> map(hex, unpack_many('\xff\x02\x03', 'all', endian='little', sign=True))
['0x302ff']
>>> map(hex, unpack_many('\xff\x02\x03', 'all', endian='big', sign=True))
['-0xfdfd']
```