# pwnlib.util.cyclic — Generation of unique sequences

### `pwnlib.util.cyclic.cyclic(`*`length = None, alphabet = None, n = None`*`) → list/str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/cyclic.py#L47-138)

`de_bruijn()`的简单封装。该函数返回最大的长度元素。

如果给定的字母表是一个字符串，那么返回一个字符串，否则返回一个list。

参数:	
* length – 如果需要整个序列，那么为list的期望长度或`None`。
* alphabet – 用于生成序列的List或字符串。
* n (*int*) – 唯一的子序列的长度。

#### 注意

最大的长度为`len(alphabet)**n`.

`alphabet`和`n`的默认总值限制在446KB以内.

如果需要生成更长的循环字符，需要提供更长的`alphabet`或更大的`n`

#### 例

循环样式通常通过提供特定长度来生成

```shell
>>> cyclic(20)
'aaaabaaacaaadaaaeaaa'
```

```shell
>>> cyclic(32)
'aaaabaaacaaadaaaeaaafaaagaaahaaa'
```

`alphabet`和`n`参数会控制实际的输出格式。

```shell
>>> cyclic(20, alphabet=string.ascii_uppercase)
'AAAABAAACAAADAAAEAAA'
```

```shell
>>> cyclic(20, n=8)
'aaaaaaaabaaaaaaacaaa'
>>> cyclic(20, n=2)
'aabacadaeafagahaiaja'
```

`n`的大小和`alphabet`限制了最大可生成长度。如果不提供`length`，可用的循环空间都回被生成。

```shell
>>> cyclic(alphabet = "ABC", n = 3)
'AAABAACABBABCACBACCBBBCBCCC'
```

```shell
>>> cyclic(length=512, alphabet = "ABC", n = 3)
Traceback (most recent call last):
...
PwnlibException: Can't create a pattern length=512 with len(alphabet)==3 and n==3
```

`alphabet`可在`context`中设置，这在某些字符不可用时非常有用。参考` context.cyclic_alphabet`

```
>>> context.cyclic_alphabet = "ABC"
>>> cyclic(10)
'AAAABAAACA'
```

原始值可通过该方式恢复

```shell
>>> context.clear()
```

以下只是一个用于确认长度正确的测试

```shell
>>> alphabet, n = range(30), 3
>>> len(alphabet)**n, len(cyclic(alphabet = alphabet, n = n))
(27000, 27000)
```

### `pwnlib.util.cyclic.cyclic_find(`*`subseq, alphabet = None, n = None`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/cyclic.py#L1388-1395)

计算子序列在De Bruijn序列中的位置。

参数:	
* subseq – 查找的子序列。可用时一个字符串，一个list或一个整数。如果提供的时一个整数，将会被打包成一个小位数整数。
* alphabet – 用于生成序列的list或字符串。默认使用` context.cyclic_alphabet`
* n (*int*) – 唯一的子序列的长度，默认使用`context.cyclic_size`

#### 例

来生成一个循环序列作为例子

```shell
>>> cyclic(16)
'aaaabaaacaaadaaa'
```

注意‘baaa’从偏移量4开始。`cyclic_find`显示如下:

```
>>> cyclic_find('baaa')
4
```

循环生成子序列的`default`长度为4。如果提供一个更长的值，会自动截断为4个字节。

```shell
>>> cyclic_find('baaacaaa')
4
```

如果提供如`n=8`给`cyclic`生成更大的子序列，你必须明确地提供这个参数。

```shell
>>> cyclic_find('baaacaaa', n=8)
3515208
```

我们可以生成一个大的循环序列，并通过其中一个子序列来查看更大的偏移量。

```shell
>>> cyclic_find(cyclic(1000)[514:518])
514
```

除了可以传入序列通过字节的形式，还可以传入整数值，注意这对于通过`context.endian`选择的字节序非常敏感。

```shell
>>> cyclic_find(0x61616162)
4
>>> cyclic_find(0x61616162, endian='big')
1
```

您可以在循环序列中使用任何内容，包括不可打印的字符。

```shell
>>> cyclic_find(0x00000000, alphabet=unhex('DEADBEEF00'))
621
```

### `pwnlib.util.cyclic.cyclic_metasploit(`*`length = None, sets = [ string.ascii_uppercase, string.ascii_lowercase, string.digits ]`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/cyclic.py#L261-296)

`metasploit_pattern()`的简单封装，这个函数返回一个长度为`length`的字符串

参数:	
* length – 所需的字符串长度或None（如果需要整个序列）。
* sets – 用于生成序列的字符串的List。

#### 例

```shell
>>> cyclic_metasploit(32)
'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab'
>>> cyclic_metasploit(sets = ["AB","ab","12"])
'Aa1Aa2Ab1Ab2Ba1Ba2Bb1Bb2'
>>> cyclic_metasploit()[1337:1341]
'5Bs6'
>>> len(cyclic_metasploit())
20280
```

### `pwnlib.util.cyclic.cyclic_metasploit_find(`*`subseq, sets = [ string.ascii_uppercase, string.ascii_lowercase, string.digits ]`*`) → int`[源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/cyclic.py#L298-321)

计算子字符串在`Metasploit Pattern`序列中的位置。

参数:	
* subseq – 查找的子序列。可用时一个字符串，一个list或一个整数。如果提供的时一个整数，将会被打包成一个小位数整数。
* sets – 要生成序列的字符串的list。

#### Examples

```shell
>>> cyclic_metasploit_find(cyclic_metasploit(1000)[514:518])
514
>>> cyclic_metasploit_find(0x61413161)
4
```

### `pwnlib.util.cyclic.de_bruijn(`*`alphabet = None, n = None`*`) → generator` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/cyclic.py#L12-45)

生成长度为`n`的唯一子序列。 这是通过给定字母的De Bruijn序列实现的。

返回的生成器最多包含`len(alphabet)**n`个元素

参数:	
* alphabet – 用于生成序列的字符串或list。
* n (*int*) – 唯一子序列的长度。

### `pwnlib.util.cyclic.metasploit_pattern(`*`sets = [ string.ascii_uppercase, string.ascii_lowercase, string.digits ]`*`) → generator` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/cyclic.py#L233-259)

根据Metasploit Framework的`Rex :: Text.pattern_create（aka pattern_create.rb）`生成一系列字符的生成器。

返回的生成器最多包含`len(sets) * reduce(lambda x,y: x*y, map(len, sets))`个元素。

参数:	sets – 用于生成序列的字符串或list。