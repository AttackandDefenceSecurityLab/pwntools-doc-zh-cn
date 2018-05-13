# pwnlib.util.fiddling — Utilities bit fiddling

### `pwnlib.util.fiddling.b64d(`*`s`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/fiddling.py#L274-284)

对一个字符串进行Base64解码

#### 例

```shell
>>> b64d('dGVzdA==')
'test'
```
### `pwnlib.util.fiddling.b64e(`*`s`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/fiddling.py#L262-272)

对一个字符串进行Base64编码。

#### 例

```shell
>>> b64e("test")
'dGVzdA=='
```

### `pwnlib.util.fiddling.bits(`*`s, endian = 'big', zero = 0, one = 1`*`) → list` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/fiddling.py#L97-153)

将参数转换为位的list。

参数:	
* s – 转换为位的字符串或数字
* endian (*str*) – 二进制的`endian`, 默认位‘big’.
* zero – 表示为0位
* one – 表示为1位

返回:	由0和1中指定的值组成的列表。

#### 例

```shell
>>> bits(511, zero = "+", one = "-")
['+', '+', '+', '+', '+', '+', '+', '-', '-', '-', '-', '-', '-', '-', '-', '-']
>>> sum(bits("test"))
17
>>> bits(0)
[0, 0, 0, 0, 0, 0, 0, 0]
```

### `pwnlib.util.fiddling.bits_str(`*`s, endian = 'big', zero = '0', one = '1'`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/fiddling.py#L155-167)

对`bits()`的封装，其将输出转换为字符串。

#### 例

```shell
>>> bits_str(511)
'0000000111111111'
>>> bits_str("bits_str", endian = "little")
'0100011010010110001011101100111011111010110011100010111001001110'
```

### `pwnlib.util.fiddling.bitswap(`*`s`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/fiddling.py#L216-231)

将给定字符串的位颠倒

#### 例

```shell
>>> bitswap("1234")
'\x8cL\xcc,'
```

### `pwnlib.util.fiddling.bitswap_int(`*`n`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/fiddling.py#L233-259)

颠倒数字的位并将结果作为新的数字返回。

参数:	
* n (*int*) – 进行交换的数字。
* width (int) – 整数的位宽

#### 例

```shell
>>> hex(bitswap_int(0x1234, 8))
'0x2c'
>>> hex(bitswap_int(0x1234, 16))
'0x2c48'
>>> hex(bitswap_int(0x1234, 24))
'0x2c4800'
>>> hex(bitswap_int(0x1234, 25))
'0x589000'
```

### pwnlib.util.fiddling.bnot(value, width=None)[源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/fiddling.py#L917-924)

返回`value`的二进制倒数

### `pwnlib.util.fiddling.enhex(`*`x`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/fiddling.py#L39-49)

对一个字符串进行十六进制编码

#### 例

```shell
>>> enhex("test")
'74657374'
```

### `pwnlib.util.fiddling.hexdump(`*`s, width=16, skip=True, hexii=False, begin=0, style=None, highlight=None, cyclic=False`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/fiddling.py#L731-906)

hexdump(s, width = 16, skip = True, hexii = False, begin = 0, style = None, highlight = None, cyclic = False) -> str generator

返回一个字符串的hexdump转储。

参数:	
* s (*str*) – 用于hexdump的数据
* width (*int*) – 每行的字符数。
* skip (*bool*) – 如果重复的行使用“*”代替则设为`True`。
* hexii (*bool*) – 如果返回值从hexdump改为hexii转储则设置为`True`。
* begin (*int*) – 要在左列中打印的第一个字节的偏移量。
* style (*dict*) – 使用的颜色方案。
* highlight (*iterable*) – 字节高亮。
* cyclic (*bool*) – 尝试跳过连续未修改的循环行。

返回:	一个以string格式的hexdump转储。

#### 例

```shell
>>> print hexdump("abc")
00000000  61 62 63                                            │abc│
00000003
```

```shell
>>> print hexdump('A'*32)
00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
*
00000020
```

```shell
>>> print hexdump('A'*32, width=8)
00000000  41 41 41 41  41 41 41 41   │AAAA│AAAA│
*
00000020
```

```shell
>>> print hexdump(cyclic(32), width=8, begin=0xdead0000, hexii=True)
dead0000  .a  .a  .a  .a   .b  .a  .a  .a  │
dead0008  .c  .a  .a  .a   .d  .a  .a  .a  │
dead0010  .e  .a  .a  .a   .f  .a  .a  .a  │
dead0018  .g  .a  .a  .a   .h  .a  .a  .a  │
dead0020
```

```shell
>>> print hexdump(list(map(chr, range(256))))
00000000  00 01 02 03  04 05 06 07  08 09 0a 0b  0c 0d 0e 0f  │····│····│····│····│
00000010  10 11 12 13  14 15 16 17  18 19 1a 1b  1c 1d 1e 1f  │····│····│····│····│
00000020  20 21 22 23  24 25 26 27  28 29 2a 2b  2c 2d 2e 2f  │ !"#│$%&'│()*+│,-./│
00000030  30 31 32 33  34 35 36 37  38 39 3a 3b  3c 3d 3e 3f  │0123│4567│89:;│<=>?│
00000040  40 41 42 43  44 45 46 47  48 49 4a 4b  4c 4d 4e 4f  │@ABC│DEFG│HIJK│LMNO│
00000050  50 51 52 53  54 55 56 57  58 59 5a 5b  5c 5d 5e 5f  │PQRS│TUVW│XYZ[│\]^_│
00000060  60 61 62 63  64 65 66 67  68 69 6a 6b  6c 6d 6e 6f  │`abc│defg│hijk│lmno│
00000070  70 71 72 73  74 75 76 77  78 79 7a 7b  7c 7d 7e 7f  │pqrs│tuvw│xyz{│|}~·│
00000080  80 81 82 83  84 85 86 87  88 89 8a 8b  8c 8d 8e 8f  │····│····│····│····│
00000090  90 91 92 93  94 95 96 97  98 99 9a 9b  9c 9d 9e 9f  │····│····│····│····│
000000a0  a0 a1 a2 a3  a4 a5 a6 a7  a8 a9 aa ab  ac ad ae af  │····│····│····│····│
000000b0  b0 b1 b2 b3  b4 b5 b6 b7  b8 b9 ba bb  bc bd be bf  │····│····│····│····│
000000c0  c0 c1 c2 c3  c4 c5 c6 c7  c8 c9 ca cb  cc cd ce cf  │····│····│····│····│
000000d0  d0 d1 d2 d3  d4 d5 d6 d7  d8 d9 da db  dc dd de df  │····│····│····│····│
000000e0  e0 e1 e2 e3  e4 e5 e6 e7  e8 e9 ea eb  ec ed ee ef  │····│····│····│····│
000000f0  f0 f1 f2 f3  f4 f5 f6 f7  f8 f9 fa fb  fc fd fe ff  │····│····│····│····│
00000100
```

```shell
>>> print hexdump(list(map(chr, range(256))), hexii=True)
00000000      01  02  03   04  05  06  07   08  09  0a  0b   0c  0d  0e  0f  │
00000010  10  11  12  13   14  15  16  17   18  19  1a  1b   1c  1d  1e  1f  │
00000020  20  .!  ."  .#   .$  .%  .&  .'   .(  .)  .*  .+   .,  .-  ..  ./  │
00000030  .0  .1  .2  .3   .4  .5  .6  .7   .8  .9  .:  .;   .<  .=  .>  .?  │
00000040  .@  .A  .B  .C   .D  .E  .F  .G   .H  .I  .J  .K   .L  .M  .N  .O  │
00000050  .P  .Q  .R  .S   .T  .U  .V  .W   .X  .Y  .Z  .[   .\  .]  .^  ._  │
00000060  .`  .a  .b  .c   .d  .e  .f  .g   .h  .i  .j  .k   .l  .m  .n  .o  │
00000070  .p  .q  .r  .s   .t  .u  .v  .w   .x  .y  .z  .{   .|  .}  .~  7f  │
00000080  80  81  82  83   84  85  86  87   88  89  8a  8b   8c  8d  8e  8f  │
00000090  90  91  92  93   94  95  96  97   98  99  9a  9b   9c  9d  9e  9f  │
000000a0  a0  a1  a2  a3   a4  a5  a6  a7   a8  a9  aa  ab   ac  ad  ae  af  │
000000b0  b0  b1  b2  b3   b4  b5  b6  b7   b8  b9  ba  bb   bc  bd  be  bf  │
000000c0  c0  c1  c2  c3   c4  c5  c6  c7   c8  c9  ca  cb   cc  cd  ce  cf  │
000000d0  d0  d1  d2  d3   d4  d5  d6  d7   d8  d9  da  db   dc  dd  de  df  │
000000e0  e0  e1  e2  e3   e4  e5  e6  e7   e8  e9  ea  eb   ec  ed  ee  ef  │
000000f0  f0  f1  f2  f3   f4  f5  f6  f7   f8  f9  fa  fb   fc  fd  fe  ##  │
00000100
```

```shell
>>> print hexdump('X' * 64)
00000000  58 58 58 58  58 58 58 58  58 58 58 58  58 58 58 58  │XXXX│XXXX│XXXX│XXXX│
*
00000040
```

```shell
>>> print hexdump('X' * 64, skip=False)
00000000  58 58 58 58  58 58 58 58  58 58 58 58  58 58 58 58  │XXXX│XXXX│XXXX│XXXX│
00000010  58 58 58 58  58 58 58 58  58 58 58 58  58 58 58 58  │XXXX│XXXX│XXXX│XXXX│
00000020  58 58 58 58  58 58 58 58  58 58 58 58  58 58 58 58  │XXXX│XXXX│XXXX│XXXX│
00000030  58 58 58 58  58 58 58 58  58 58 58 58  58 58 58 58  │XXXX│XXXX│XXXX│XXXX│
00000040
```

```shell
>>> print hexdump(fit({0x10: 'X'*0x20, 0x50-1: '\xff'*20}, length=0xc0) + '\x00'*32)
00000000  61 61 61 61  62 61 61 61  63 61 61 61  64 61 61 61  │aaaa│baaa│caaa│daaa│
00000010  58 58 58 58  58 58 58 58  58 58 58 58  58 58 58 58  │XXXX│XXXX│XXXX│XXXX│
*
00000030  6d 61 61 61  6e 61 61 61  6f 61 61 61  70 61 61 61  │maaa│naaa│oaaa│paaa│
00000040  71 61 61 61  72 61 61 61  73 61 61 61  74 61 61 ff  │qaaa│raaa│saaa│taa·│
00000050  ff ff ff ff  ff ff ff ff  ff ff ff ff  ff ff ff ff  │····│····│····│····│
00000060  ff ff ff 61  7a 61 61 62  62 61 61 62  63 61 61 62  │···a│zaab│baab│caab│
00000070  64 61 61 62  65 61 61 62  66 61 61 62  67 61 61 62  │daab│eaab│faab│gaab│
00000080  68 61 61 62  69 61 61 62  6a 61 61 62  6b 61 61 62  │haab│iaab│jaab│kaab│
00000090  6c 61 61 62  6d 61 61 62  6e 61 61 62  6f 61 61 62  │laab│maab│naab│oaab│
000000a0  70 61 61 62  71 61 61 62  72 61 61 62  73 61 61 62  │paab│qaab│raab│saab│
000000b0  74 61 61 62  75 61 61 62  76 61 61 62  77 61 61 62  │taab│uaab│vaab│waab│
000000c0  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
*
000000e0
```

```shell
>>> print hexdump(fit({0x10: 'X'*0x20, 0x50-1: '\xff'*20}, length=0xc0) + '\x00'*32, cyclic=1)
00000000  61 61 61 61  62 61 61 61  63 61 61 61  64 61 61 61  │aaaa│baaa│caaa│daaa│
00000010  58 58 58 58  58 58 58 58  58 58 58 58  58 58 58 58  │XXXX│XXXX│XXXX│XXXX│
*
00000030  6d 61 61 61  6e 61 61 61  6f 61 61 61  70 61 61 61  │maaa│naaa│oaaa│paaa│
00000040  71 61 61 61  72 61 61 61  73 61 61 61  74 61 61 ff  │qaaa│raaa│saaa│taa·│
00000050  ff ff ff ff  ff ff ff ff  ff ff ff ff  ff ff ff ff  │····│····│····│····│
00000060  ff ff ff 61  7a 61 61 62  62 61 61 62  63 61 61 62  │···a│zaab│baab│caab│
00000070  64 61 61 62  65 61 61 62  66 61 61 62  67 61 61 62  │daab│eaab│faab│gaab│
*
000000c0  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
*
000000e0
```

```shell
>>> print hexdump(fit({0x10: 'X'*0x20, 0x50-1: '\xff'*20}, length=0xc0) + '\x00'*32, cyclic=1, hexii=1)
00000000  .a  .a  .a  .a   .b  .a  .a  .a   .c  .a  .a  .a   .d  .a  .a  .a  │
00000010  .X  .X  .X  .X   .X  .X  .X  .X   .X  .X  .X  .X   .X  .X  .X  .X  │
*
00000030  .m  .a  .a  .a   .n  .a  .a  .a   .o  .a  .a  .a   .p  .a  .a  .a  │
00000040  .q  .a  .a  .a   .r  .a  .a  .a   .s  .a  .a  .a   .t  .a  .a  ##  │
00000050  ##  ##  ##  ##   ##  ##  ##  ##   ##  ##  ##  ##   ##  ##  ##  ##  │
00000060  ##  ##  ##  .a   .z  .a  .a  .b   .b  .a  .a  .b   .c  .a  .a  .b  │
00000070  .d  .a  .a  .b   .e  .a  .a  .b   .f  .a  .a  .b   .g  .a  .a  .b  │
*
000000c0                                                                     │
*
000000e0
```

```shell
>>> print hexdump('A'*16, width=9)
00000000  41 41 41 41  41 41 41 41  41  │AAAA│AAAA│A│
00000009  41 41 41 41  41 41 41         │AAAA│AAA│
00000010
>>> print hexdump('A'*16, width=10)
00000000  41 41 41 41  41 41 41 41  41 41  │AAAA│AAAA│AA│
0000000a  41 41 41 41  41 41               │AAAA│AA│
00000010
>>> print hexdump('A'*16, width=11)
00000000  41 41 41 41  41 41 41 41  41 41 41  │AAAA│AAAA│AAA│
0000000b  41 41 41 41  41                     │AAAA│A│
00000010
>>> print hexdump('A'*16, width=12)
00000000  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│
0000000c  41 41 41 41                            │AAAA││
00000010
>>> print hexdump('A'*16, width=13)
00000000  41 41 41 41  41 41 41 41  41 41 41 41  41  │AAAA│AAAA│AAAA│A│
0000000d  41 41 41                                   │AAA│
00000010
>>> print hexdump('A'*16, width=14)
00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41  │AAAA│AAAA│AAAA│AA│
0000000e  41 41                                         │AA│
00000010
>>> print hexdump('A'*16, width=15)
00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41  │AAAA│AAAA│AAAA│AAA│
0000000f  41                                               │A│
00000010
```

### `pwnlib.util.fiddling.hexdump_iter(`*`fd, width=16, skip=True, hexii=False, begin=0, style=None, highlight=None, cyclic=False`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/fiddling.py#L576-729)

hexdump_iter(s, width = 16, skip = True, hexii = False, begin = 0, style = None, highlight = None, cyclic = False) -> str generator

返回一个字符串格式的hexdump转储作为行生成器，除非你有大量的数据，否则你可能想用`hexdump()`。

参数:	
* fd (*file*) – 要转储的文件。使用`StringIO.StringIO()`或`hexdump()`来转储一个字符串。
* width (*int*) – 每行的字符数。
* skip (*bool*) – 如果重复的行使用“*”代替则设为`True`。
* hexii (*bool*) – 如果返回值从hexdump改为hexii转储则设置为`True`。
* begin (*int*) – 要在左列中打印的第一个字节的偏移量。
* style (*dict*) – 使用的颜色方案。
* highlight (*iterable*) – 字节高亮。
* cyclic (*bool*) – 尝试跳过连续未修改的循环行。

返回:	生成器一次生成的一行hexdump转储。

#### 例

```shell
>>> tmp = tempfile.NamedTemporaryFile()
>>> tmp.write('XXXXHELLO, WORLD')
>>> tmp.flush()
>>> tmp.seek(4)
>>> print '\n'.join(hexdump_iter(tmp))
00000000  48 45 4c 4c  4f 2c 20 57  4f 52 4c 44               │HELL│O, W│ORLD││
0000000c
```

```shell
>>> t = tube()
>>> t.unrecv('I know kung fu')
>>> print '\n'.join(hexdump_iter(t))
00000000  49 20 6b 6e  6f 77 20 6b  75 6e 67 20  66 75        │I kn│ow k│ung │fu│
0000000e
```

### `pwnlib.util.fiddling.hexii(`*`s, width = 16, skip = True`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/fiddling.py#L530-544)

返回一个字符串的HEXII转储。

参数:	
* s (*str*) – 转储的字符串。
* width (*int*) – 每行的字符数。
* skip (*bool*) – 重复的行使用“*”代替。

返回:	字符串格式的HEXII转储。

### `pwnlib.util.fiddling.isprint(`*`c`*`) → bool` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/fiddling.py#L523-527)

如果字符是可打印的，返回`True`。

### `pwnlib.util.fiddling.naf(`*`int`*`) → int generator` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/fiddling.py#L497-521)

返回一个数字n的非相邻形式(NAF[1])生成器。如果`naf(n)`生成`z_0, z_1, …`，那么`n == z_0 + z_1 * 2 + z_2 * 2**2, …`。

[1] https://en.wikipedia.org/wiki/Non-adjacent_form

#### 例

```shell
>>> n = 45
>>> m = 0
>>> x = 1
>>> for z in naf(n):
...     m += x * z
...     x *= 2
>>> n == m
True
```

### `pwnlib.util.fiddling.negate(`*`value, width=None`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/fiddling.py#L908-915)

返回`value`的二进制补码。

### `pwnlib.util.fiddling.randoms(`*`count, alphabet = string.lowercase`*`) → str` [s源码()

仅使用指定的字母返回一个给定长度的随机字符串。

参数:	
* count (*int*) – 随机字符串的长度
* alphabet – 允许使用的字母。默认为所有小写字母。

返回:	一个随机字符串

#### 例

```shell
>>> randoms(10) 
'evafjilupm'
```

### `pwnlib.util.fiddling.rol(`*`n, k, word_size=None`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/fiddling.py#L449-490)

返回`n`轮转`k`位的结果

当`n`是一个数字，这意味着`((n << k) | (n >> (word_size - k)))`截断为`word_size`位。

当`n`是一个list, tuple或字符串，那么就是`n[k % len(n):] + n[:k % len(n)]`

参数:	
* n – 用于轮转的值
* k (*int*) – 轮转的量，可以为正数或者负数。
* word_size (*int*) – 如果`n`是一个数字，那么这就是`n`的假定比特数，默认是`pwnlib.context.word_size`如果为`None`。

#### 例

```shell
>>> rol('abcdefg', 2)
'cdefgab'
>>> rol('abcdefg', -2)
'fgabcde'
>>> hex(rol(0x86, 3, 8))
'0x34'
>>> hex(rol(0x86, -3, 8))
'0xd0'
```

### `pwnlib.util.fiddling.ror(`*`n, k, word_size=None`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/fiddling.py#L492-495)

对`rol()`的简单封装, 这无效了`k`的值。

### `pwnlib.util.fiddling.unbits(`*`s, endian = 'big'`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/fiddling.py#L169-213)

将可迭代的位转换为字符串。

参数:	
* s – 迭代的位。
* endian (*str*) – 字符串“little”或“big”，指定了位字节顺序。

Returns:	一个字符串的解码位。

#### 例

```shell
>>> unbits([1])
'\x80'
>>> unbits([1], endian = 'little')
'\x01'
>>> unbits(bits('hello'), endian = 'little')
'\x16\xa666\xf6'
```

### `pwnlib.util.fiddling.unhex(`*`s`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/fiddling.py#L22-37)

十六进制解码一个字符串。

#### 例

```shell
>>> unhex("74657374")
'test'
>>> unhex("F\n")
'\x0f'
```

### `pwnlib.util.fiddling.urldecode(`*`s, ignore_invalid = False`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/fiddling.py#L63-95)

URL解码一个字符串。

#### 例

```shell
>>> urldecode("test%20%41")
'test A'
>>> urldecode("%qq")
Traceback (most recent call last):
...
ValueError: Invalid input to urldecode
>>> urldecode("%qq", ignore_invalid = True)
'%qq'
```

### `pwnlib.util.fiddling.urlencode(`*`s`*`) → str` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/fiddling.py#L51-61)

URL编码一个字符串

#### 例

```shell
>>> urlencode("test")
'%74%65%73%74'
```

### `pwnlib.util.fiddling.xor(`*`*args, cut = 'max'`*`) → str` [s源码()
使用`pwnlib.util.packing.flat()`展开参数并将它们异或（xors）到一起。如果到达字符串的末尾，将会放在字符串中。

参数:	
* args – 异或（xor）到一起的参数
* cut – 返回的字符串的长度，可以是‘min’/’max’/’left’/’right’或数字。

返回:	参数被异或（xor）到一起生成的字符串

#### 例

```shell
>>> xor('lol', 'hello', 42)
'. ***'
```

### `pwnlib.util.fiddling.xor_key(`*`data, size=None, avoid='x00n') -> None or (int, str`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/fiddling.py#L339-378)

找到一个`size`宽度值可以与字符串异或（xor）生成`data`，异或（xor）生成值或异或（xor）生成字符串都不包含任意`avoid`的字节。

参数:	
* data (*str*) – 所需的字符串。
* avoid – 禁用的字符的list，默认为null和换行符。
* size (*int*) – 所需输出值的大小，默认为一个字节。

Returns:	包含两个字符串的tuple;用于异或（xor）的key和用于异或（xor）的字符串，如果没有这样一对数据，则返回`None`。

#### 例

```shell
>>> xor_key("Hello, world")
('\x01\x01\x01\x01', 'Idmmn-!vnsme')
```

### `pwnlib.util.fiddling.xor_pair(`*`data, avoid = 'x00n') -> None or (str, str`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/fiddling.py#L339-378)

找到两个可以异或（xor）成为给定字符串的字符串，而只使用给定的字母。

参数:	
* data (*str*) – 给定的字符串
* avoid – 禁用的字符的list，默认为null和换行符。

返回:	两个可以异或（xor）称为给定字符串的字符串，如果没有这样两个字符串，则返回`None`。

#### 例

```shell
>>> xor_pair("test")
('\x01\x01\x01\x01', 'udru')
```