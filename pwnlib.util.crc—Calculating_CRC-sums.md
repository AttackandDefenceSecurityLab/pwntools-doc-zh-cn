# pwnlib.util.crc — Calculating CRC-sums

用于计算CRC校验和的模块。

包含interwebz上已知的所有crc实现。对于大多数实现，它只包含核心crc算法，而不包含如：填充方案的部分。

它的运行非常缓慢，因为使用了一个非常原始的算法直接在位多项式上操作。该类以位多项式显示。

当前算法是超线性的，需要大约4秒来计算`'A'*40000`的crc32校验和。

一个显著的优化是生成一些查找表。

### *`class`* `pwnlib.util.crc.BitPolynom(`*`n`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py)

用于表示GF(2)[X]的类, 即GF(2)上多项式的域。

在实际运用中，多项式表示位数据， 使得*x\*\*n*对应*1 << n*。在这种表示中，计算非常简单：只需要照常完成所有事情，除了忘记carrise。

加法变成异或（xor）而乘法变为进位乘法。

#### 例

```shell
>>> p1 = BitPolynom("x**3 + x + 1")
>>> p1
BitPolynom('x**3 + x + 1')
>>> int(p1)
11
>>> p1 == BitPolynom(11)
True
>>> p2 = BitPolynom("x**2 + x + 1")
>>> p1 + p2
BitPolynom('x**3 + x**2')
>>> p1 * p2
BitPolynom('x**5 + x**4 + 1')
>>> p1 / p2
BitPolynom('x + 1')
>>> p1 % p2
BitPolynom('x')
>>> d, r = divmod(p1, p2)
>>> d * p2 + r == p1
True
>>> BitPolynom(-1)
Traceback (most recent call last):
    ...
ValueError: Polynomials cannot be negative: -1
>>> BitPolynom('y')
Traceback (most recent call last):
    ...
ValueError: Not a valid polynomial: y
```

`degree()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L191-209)

返回多项式的阶数。

#### 例

```shell
>>> BitPolynom(0).degree()
0
>>> BitPolynom(1).degree()
0
>>> BitPolynom(2).degree()
1
>>> BitPolynom(7).degree()
2
>>> BitPolynom((1 << 10) - 1).degree()
9
>>> BitPolynom(1 << 10).degree()
10
```

### `pwnlib.util.crc.generic_crc(`*`data, polynom, * width, * init, * refin, * refout, * xorout`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L254-297)

一个通用的CRC校验函数。

这适用于: http://reveng.sourceforge.net/crc-catalogue/all.htm

文档中的“check”值是字符串“123456789”的CRC校验和。

参数:	
* data (*str*) – 需要计算CRC校验和的数据。这应该为字符串或者是字节的list
* polynom (*int*) – 使用的多项式。
* init (*int*) – 如果CRC校验和，这将会是校验和寄存器的初始值。
* refin (*bool*) – 输入字节是否要显示。
* refout (bool) – 校验和是否要显示。
* xorout (int) – 用于输出前和校验值进行异或（xor）运算的值。

### `pwnlib.util.crc.cksum(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L331-347)

计算和UNIX-tool`cksum`返回的校验和相同的校验和。

参数:	data (*str*) – 得到校验和的数据。

#### 例

```shell
>>> print cksum('123456789')
930766865
```

### `pwnlib.util.crc.find_crc_function(`*`data, checksum`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L349-366)

查找所有已知的将一段数据散列成特定校验和的CRC函数。 它通过一个接一个地尝试所有已知的CRC函数实现。

参数:	data (*str*) – 已知校验和的数据。

#### 例

```shell
>>> find_crc_function('test', 46197)
[<function crc_crc_16_dnp at ...>]
```

### `pwnlib.util.crc.arc(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算arc校验和。

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x8005
* width = 16
* init = 0x0
* refin = True
* refout = True
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat-bits.16

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print arc('123456789')
47933
```

### `pwnlib.util.crc.crc_10(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_10校验和。

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x233
* width = 10
* init = 0x0
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat-bits.10

参数:	data (*str*) – 计算校验和的数据

#### 例

```shell
>>> print crc_10('123456789')
409
```

### `pwnlib.util.crc.crc_10_cdma2000(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_10_cdma2000校验和。

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x3d9
* width = 10
* init = 0x3ff
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-10-cdma2000

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_10_cdma2000('123456789')
563
```

### `pwnlib.util.crc.crc_10_gsm(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_10_gsm校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x175
* width = 10
* init = 0x0
* refin = False
* refout = False
* xorout = 0x3ff

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-10-gsm

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_10_gsm('123456789')
298
```

### `pwnlib.util.crc.crc_11(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_11校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x385
* width = 11
* init = 0x1a
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat-bits.11

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_11('123456789')
1443
```

### `pwnlib.util.crc.crc_11_umts(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_11_umts校验和。

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x307
* width = 11
* init = 0x0
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-11-umts

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_11_umts('123456789')
97
```

### `pwnlib.util.crc.crc_12_cdma2000(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_12_cdma2000校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0xf13
* width = 12
* init = 0xfff
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat-bits.12

参数:	data (*str*) – 计算校验和的数据。

#### 例

```
>>> print crc_12_cdma2000('123456789')
3405
```

### `pwnlib.util.crc.crc_12_dect(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_12_dect校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x80f
* width = 12
* init = 0x0
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-12-dect

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_12_dect('123456789')
3931
```

### `pwnlib.util.crc.crc_12_gsm(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_12_gsm校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0xd31
* width = 12
* init = 0x0
* refin = False
* refout = False
* xorout = 0xfff

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-12-gsm

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_12_gsm('123456789')
2868
```

### `pwnlib.util.crc.crc_12_umts(`*data*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_12_umts校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x80f
* width = 12
* init = 0x0
* refin = False
* refout = True
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-12-umts

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_12_umts('123456789')
3503
```

### `pwnlib.util.crc.crc_13_bbc(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_13_bbc校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x1cf5
* width = 13
* init = 0x0
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat-bits.13

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_13_bbc('123456789')
1274
```

### `pwnlib.util.crc.crc_14_darc(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_14_darc校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x805
* width = 14
* init = 0x0
* refin = True
* refout = True
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat-bits.14

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_14_darc('123456789')
2093
```

### `pwnlib.util.crc.crc_14_gsm(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_14_gsm校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x202d
* width = 14
* init = 0x0
* refin = False
* refout = False
* xorout = 0x3fff

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-14-gsm

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_14_gsm('123456789')
12462
```

### `pwnlib.util.crc.crc_15(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_15校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x4599
* width = 15
* init = 0x0
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat-bits.15

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_15('123456789')
1438
```

### `pwnlib.util.crc.crc_15_mpt1327(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_15_mpt1327校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x6815
* width = 15
* init = 0x0
* refin = False
* refout = False
* xorout = 0x1

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-15-mpt1327

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_15_mpt1327('123456789')
9574
```

### `pwnlib.util.crc.crc_16_aug_ccitt(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_16_aug_ccitt校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x1021
* width = 16
* init = 0x1d0f
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-16-aug-ccitt

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_16_aug_ccitt('123456789')
58828
```

### `pwnlib.util.crc.crc_16_buypass(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_16_buypass校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x8005
* width = 16
* init = 0x0
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-16-buypass

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_16_buypass('123456789')
65256
```

### `pwnlib.util.crc.crc_16_ccitt_false(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_16_ccitt_false校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x1021
* width = 16
* init = 0xffff
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-16-ccitt-false

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_16_ccitt_false('123456789')
10673
```

### `pwnlib.util.crc.crc_16_cdma2000(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_16_cdma2000校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0xc867
* width = 16
* init = 0xffff
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-16-cdma2000

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_16_cdma2000('123456789')
19462
```

### `pwnlib.util.crc.crc_16_cms(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_16_cms校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x8005
* width = 16
* init = 0xffff
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-16-cms

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_16_cms('123456789')
44775
```

### `pwnlib.util.crc.crc_16_dds_110(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_16_dds_110校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x8005
* width = 16
* init = 0x800d
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-16-dds-110

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_16_dds_110('123456789')
40655
```

### `pwnlib.util.crc.crc_16_dect_r(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_16_dect_r校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x589
* width = 16
* init = 0x0
* refin = False
* refout = False
* xorout = 0x1

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-16-dect-r

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_16_dect_r('123456789')
126
```

### `pwnlib.util.crc.crc_16_dect_x(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_16_dect_x校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x589
* width = 16
* init = 0x0
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-16-dect-x

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_16_dect_x('123456789')
127
```

### `pwnlib.util.crc.crc_16_dnp(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_16_dnp校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x3d65
* width = 16
* init = 0x0
* refin = True
* refout = True
* xorout = 0xffff

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-16-dnp

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_16_dnp('123456789')
60034
```

### `pwnlib.util.crc.crc_16_en_13757(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_16_en_13757校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x3d65
* width = 16
* init = 0x0
* refin = False
* refout = False
* xorout = 0xffff

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-16-en-13757

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_16_en_13757('123456789')
49847
```

### `pwnlib.util.crc.crc_16_genibus(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_16_genibus校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x1021
* width = 16
* init = 0xffff
* refin = False
* refout = False
* xorout = 0xffff

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-16-genibus

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_16_genibus('123456789')
54862
```

### `pwnlib.util.crc.crc_16_gsm(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_16_gsm校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x1021
* width = 16
* init = 0x0
* refin = False
* refout = False
* xorout = 0xffff

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-16-gsm

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_16_gsm('123456789')
52796
```

### `pwnlib.util.crc.crc_16_lj1200(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_16_lj1200校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x6f63
* width = 16
* init = 0x0
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-16-lj1200

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_16_lj1200('123456789')
48628
```

### `pwnlib.util.crc.crc_16_maxim(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_16_maxim校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x8005
* width = 16
* init = 0x0
* refin = True
* refout = True
* xorout = 0xffff

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-16-maxim

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_16_maxim('123456789')
17602
```

### `pwnlib.util.crc.crc_16_mcrf4xx(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)
计算crc_16_mcrf4xx校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x1021
* width = 16
* init = 0xffff
* refin = True
* refout = True
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-16-mcrf4xx

参数:	data (*str*) – 计算校验和的数据。

#### 例

>>> print crc_16_mcrf4xx('123456789')
28561

### `pwnlib.util.crc.crc_16_opensafety_a(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_16_opensafety_a校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x5935
* width = 16
* init = 0x0
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-16-opensafety-a

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_16_opensafety_a('123456789')
23864
```

### `pwnlib.util.crc.crc_16_opensafety_b(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_16_opensafety_b校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x755b
* width = 16
* init = 0x0
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-16-opensafety-a

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_16_opensafety_b('123456789')
8446
```

### `pwnlib.util.crc.crc_16_profibus(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_16_profibus校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x1dcf
* width = 16
* init = 0xffff
* refin = False
* refout = False
* xorout = 0xffff

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-16-profibus

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_16_profibus('123456789')
43033
```

### `pwnlib.util.crc.crc_16_riello(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_16_riello校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x1021
* width = 16
* init = 0xb2aa
* refin = True
* refout = True
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-16-riello

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_16_riello('123456789')
25552
```

### `pwnlib.util.crc.crc_16_t10_dif(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_16_t10_dif校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x8bb7
* width = 16
* init = 0x0
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-16-t10-dif

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_16_t10_dif('123456789')
53467
```

### `pwnlib.util.crc.crc_16_teledisk(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_16_teledisk校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0xa097
* width = 16
* init = 0x0
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-16-teledisk

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_16_teledisk('123456789')
4019
```

### `pwnlib.util.crc.crc_16_tms37157(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_16_tms37157校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x1021
* width = 16
* init = 0x89ec
* refin = True
* refout = True
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-16-tms37157

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_16_tms37157('123456789')
9905
```

### `pwnlib.util.crc.crc_16_usb(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_16_usb校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x8005
* width = 16
* init = 0xffff
* refin = True
* refout = True
* xorout = 0xffff

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-16-usb

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_16_usb('123456789')
46280
```

### `pwnlib.util.crc.crc_24(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_24校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x864cfb
* width = 24
* init = 0xb704ce
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat-bits.24

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_24('123456789')
2215682
```

### `pwnlib.util.crc.crc_24_ble(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_24_ble校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x65b
* width = 24
* init = 0x555555
* refin = True
* refout = True
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-24-ble

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_24_ble('123456789')
12737110
```

### `1`pwnlib.util.crc.crc_24_flexray_a(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_24_flexray_a校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x5d6dcb
* width = 24
* init = 0xfedcba
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-24-flexray-a

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_24_flexray_a('123456789')
7961021
```

### `pwnlib.util.crc.crc_24_flexray_b(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_24_flexray_b校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x5d6dcb
* width = 24
* init = 0xabcdef
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-24-flexray-b

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_24_flexray_b('123456789')
2040760
```

### `pwnlib.util.crc.crc_24_interlaken(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_24_interlaken校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x328b63
* width = 24
* init = 0xffffff
* refin = False
* refout = False
* xorout = 0xffffff

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-24-interlaken

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_24_interlaken('123456789')
11858918
```

### `pwnlib.util.crc.crc_24_lte_a(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_24_lte_a校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x864cfb
* width = 24
* init = 0x0
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-24-lte-a

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_24_lte_a('123456789')
13494019
```

### `pwnlib.util.crc.crc_24_lte_b(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_24_lte_b校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x800063
* width = 24
* init = 0x0
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-24-lte-b

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_24_lte_b('123456789')
2355026
```

### `pwnlib.util.crc.crc_30_cdma(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_30_cdma校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x2030b9c7
* width = 30
* init = 0x3fffffff
* refin = False
* refout = False
* xorout = 0x3fffffff

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat-bits.30

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_30_cdma('123456789')
79907519
```

### `pwnlib.util.crc.crc_31_philips(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_31_philips校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x4c11db7
* width = 31
* init = 0x7fffffff
* refin = False
* refout = False
* xorout = 0x7fffffff

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat-bits.31

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_31_philips('123456789')
216654956
```

### `pwnlib.util.crc.crc_32(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_32校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x4c11db7
* width = 32
* init = 0xffffffff
* refin = True
* refout = True
* xorout = 0xffffffff

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat-bits.32

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_32('123456789')
3421780262
```

### `pwnlib.util.crc.crc_32_autosar(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_32_autosar校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0xf4acfb13
* width = 32
* init = 0xffffffff
* refin = True
* refout = True
* xorout = 0xffffffff

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-32-autosar

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_32_autosar('123456789')
379048042
```

### `pwnlib.util.crc.crc_32_bzip2(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_32_bzip2校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x4c11db7
* width = 32
* init = 0xffffffff
* refin = False
* refout = False
* xorout = 0xffffffff

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-32-bzip2

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_32_bzip2('123456789')
4236843288
```

### `pwnlib.util.crc.crc_32_mpeg_2(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_32_mpeg_2校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x4c11db7
* width = 32
* init = 0xffffffff
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-32-mpeg-2

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_32_mpeg_2('123456789')
58124007
```

### `pwnlib.util.crc.crc_32_posix(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_32_posix校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x4c11db7
* width = 32
* init = 0x0
* refin = False
* refout = False
* xorout = 0xffffffff

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-32-posix

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_32_posix('123456789')
1985902208
```

### `pwnlib.util.crc.crc_32c(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_32c校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x1edc6f41
* width = 32
* init = 0xffffffff
* refin = True
* refout = True
* xorout = 0xffffffff

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-32c

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_32c('123456789')
3808858755
```

### `pwnlib.util.crc.crc_32d(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_32d校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0xa833982b
* width = 32
* init = 0xffffffff
* refin = True
* refout = True
* xorout = 0xffffffff

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-32d

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_32d('123456789')
2268157302
```

### `pwnlib.util.crc.crc_32q(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_32q校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x814141ab
* width = 32
* init = 0x0
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-32q

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_32q('123456789')
806403967
```

### `pwnlib.util.crc.crc_3_gsm(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_3_gsm校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x3
* width = 3
* init = 0x0
* refin = False
* refout = False
* xorout = 0x7

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat-bits.3

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_3_gsm('123456789')
4
```

### `pwnlib.util.crc.crc_3_rohc(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_3_rohc校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x3
* width = 3
* init = 0x7
* refin = True
* refout = True
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-3-rohc

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_3_rohc('123456789')
6
```

### `pwnlib.util.crc.crc_40_gsm(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_40_gsm校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x4820009
* width = 40
* init = 0x0
* refin = False
* refout = False
* xorout = 0xffffffffff

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat-bits.40

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_40_gsm('123456789')
910907393606
```

### `pwnlib.util.crc.crc_4_interlaken(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_4_interlaken校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x3
* width = 4
* init = 0xf
* refin = False
* refout = False
* xorout = 0xf

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat-bits.4

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_4_interlaken('123456789')
11
```

### `pwnlib.util.crc.crc_4_itu(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_4_itu校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x3
* width = 4
* init = 0x0
* refin = True
* refout = True
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-4-itu

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_4_itu('123456789')
7
```

### `pwnlib.util.crc.crc_5_epc(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_5_epc校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x9
* width = 5
* init = 0x9
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat-bits.5

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_5_epc('123456789')
0
```

### `pwnlib.util.crc.crc_5_itu(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_5_itu校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x15
* width = 5
* init = 0x0
* refin = True
* refout = True
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-5-itu

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_5_itu('123456789')
7
```

### `pwnlib.util.crc.crc_5_usb(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_5_usb校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x5
* width = 5
* init = 0x1f
* refin = True
* refout = True
* xorout = 0x1f

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-5-usb

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_5_usb('123456789')
25
```

### `pwnlib.util.crc.crc_64(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_64校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x42f0e1eba9ea3693
* width = 64
* init = 0x0
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat-bits.64

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_64('123456789')
7800480153909949255
```

### `pwnlib.util.crc.crc_64_go_iso(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_64_go_iso校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x1b
* width = 64
* init = 0xffffffffffffffff
* refin = True
* refout = True
* xorout = 0xffffffffffffffff

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-64-go-iso

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_64_go_iso('123456789')
13333283586479230977
```

### `pwnlib.util.crc.crc_64_we(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_64_we校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x42f0e1eba9ea3693
* width = 64
* init = 0xffffffffffffffff
* refin = False
* refout = False
* xorout = 0xffffffffffffffff

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-64-we

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_64_we('123456789')
7128171145767219210
```

### `pwnlib.util.crc.crc_64_xz(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_64_xz校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x42f0e1eba9ea3693
* width = 64
* init = 0xffffffffffffffff
* refin = True
* refout = True
* xorout = 0xffffffffffffffff

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-64-xz

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_64_xz('123456789')
11051210869376104954
```

### `pwnlib.util.crc.crc_6_cdma2000_a(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_6_cdma2000_a校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x27
* width = 6
* init = 0x3f
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat-bits.6

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_6_cdma2000_a('123456789')
13
```

### `pwnlib.util.crc.crc_6_cdma2000_b(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)
计算crc_6_cdma2000_b校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x7
* width = 6
* init = 0x3f
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-6-cdma2000-b

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_6_cdma2000_b('123456789')
59
```

### `pwnlib.util.crc.crc_6_darc(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_6_darc校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x19
* width = 6
* init = 0x0
* refin = True
* refout = True
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-6-darc

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_6_darc('123456789')
38
```

### `pwnlib.util.crc.crc_6_gsm(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_6_gsm校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x2f
* width = 6
* init = 0x0
* refin = False
* refout = False
* xorout = 0x3f

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-6-gsm

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_6_gsm('123456789')
19
```

### `pwnlib.util.crc.crc_6_itu(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_6_itu校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x3
* width = 6
* init = 0x0
* refin = True
* refout = True
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-6-itu

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_6_itu('123456789')
6
```

### `pwnlib.util.crc.crc_7(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_7校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x9
* width = 7
* init = 0x0
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat-bits.7

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_7('123456789')
117
```

### `pwnlib.util.crc.crc_7_rohc(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_7_rohc校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x4f
* width = 7
* init = 0x7f
* refin = True
* refout = True
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-7-rohc

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_7_rohc('123456789')
83
```

### `pwnlib.util.crc.crc_7_umts(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_7_umts校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x45
* width = 7
* init = 0x0
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-7-umts

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_7_umts('123456789')
97
```

### `pwnlib.util.crc.crc_8(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_8校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x7
* width = 8
* init = 0x0
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat-bits.8

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_8('123456789')
244
```

### `pwnlib.util.crc.crc_82_darc(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_82_darc校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x308c0111011401440411
* width = 82
* init = 0x0
* refin = True
* refout = True
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat-bits.82

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_82_darc('123456789')
749237524598872659187218
```

### `pwnlib.util.crc.crc_8_autosar(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_8_autosar校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x2f
* width = 8
* init = 0xff
* refin = False
* refout = False
* xorout = 0xff

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-8-autosar

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_8_autosar('123456789')
223
```

### `pwnlib.util.crc.crc_8_cdma2000(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_8_cdma2000校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x9b
* width = 8
* init = 0xff
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-8-cdma2000

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_8_cdma2000('123456789')
218
```

### `pwnlib.util.crc.crc_8_darc(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)
计算crc_8_darc校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x39
* width = 8
* init = 0x0
* refin = True
* refout = True
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-8-darc

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_8_darc('123456789')
21
```

### `pwnlib.util.crc.crc_8_dvb_s2(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_8_dvb_s2校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0xd5
* width = 8
* init = 0x0
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-8-dvb-s2

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_8_dvb_s2('123456789')
188
```

### `pwnlib.util.crc.crc_8_ebu(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_8_ebu校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x1d
* width = 8
* init = 0xff
* refin = True
* refout = True
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-8-ebu

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_8_ebu('123456789')
151
```

### `pwnlib.util.crc.crc_8_gsm_a(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_8_gsm_a校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x1d
* width = 8
* init = 0x0
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-8-gsm-a

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_8_gsm_a('123456789')
55
```

### `pwnlib.util.crc.crc_8_gsm_b(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_8_gsm_b校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x49
* width = 8
* init = 0x0
* refin = False
* refout = False
* xorout = 0xff

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-8-gsm-b

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_8_gsm_b('123456789')
148
```

### `pwnlib.util.crc.crc_8_i_code(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_8_i_code校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x1d
* width = 8
* init = 0xfd
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-8-i-code

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_8_i_code('123456789')
126
```

### `pwnlib.util.crc.crc_8_itu(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_8_itu校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x7
* width = 8
* init = 0x0
* refin = False
* refout = False
* xorout = 0x55

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-8-itu

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_8_itu('123456789')
161
```

### `pwnlib.util.crc.crc_8_lte(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_8_lte校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x9b
* width = 8
* init = 0x0
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-8-lte

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_8_lte('123456789')
234
```

### `pwnlib.util.crc.crc_8_maxim(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_8_maxim校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x31
* width = 8
* init = 0x0
* refin = True
* refout = True
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-8-maxim

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_8_maxim('123456789')
161
```

### `pwnlib.util.crc.crc_8_opensafety(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_8_opensafety校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x2f
* width = 8
* init = 0x0
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-8-opensafety

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_8_opensafety('123456789')
62
```

### `pwnlib.util.crc.crc_8_rohc(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_8_rohc校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x7
* width = 8
* init = 0xff
* refin = True
* refout = True
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-8-rohc

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_8_rohc('123456789')
208
```

### `pwnlib.util.crc.crc_8_sae_j1850(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_8_sae_j1850校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x1d
* width = 8
* init = 0xff
* refin = False
* refout = False
* xorout = 0xff

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-8-sae-j1850

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_8_sae_j1850('123456789')
75
```

### `pwnlib.util.crc.crc_8_wcdma(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)
计算crc_8_wcdma校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x9b
* width = 8
* init = 0x0
* refin = True
* refout = True
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-8-wdcma

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_8_wcdma('123456789')
37
```

### `pwnlib.util.crc.crc_a(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算crc_a校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x1021
* width = 16
* init = 0xc6c6
* refin = True
* refout = True
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.crc-a

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print crc_a('123456789')
48901
```

### `pwnlib.util.crc.jamcrc(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算jamcrc校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x4c11db7
* width = 32
* init = 0xffffffff
* refin = True
* refout = True
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.jamcrc

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print jamcrc('123456789')
873187033
```

### `pwnlib.util.crc.kermit(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)
计算kermit校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x1021
* width = 16
* init = 0x0
* refin = True
* refout = True
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.kermit

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print kermit('123456789')
8585
```

### `pwnlib.util.crc.modbus(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算modbus校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x8005
* width = 16
* init = 0xffff
* refin = True
* refout = True
* xorout = 0x0
同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.modbus

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print modbus('123456789')
19255
```

### `pwnlib.util.crc.x_25(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算x_25校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x1021
* width = 16
* init = 0xffff
* refin = True
* refout = True
* xorout = 0xffff

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.x-25

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print x_25('123456789')
36974
```

### `pwnlib.util.crc.xfer(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算xfer校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0xaf
* width = 32
* init = 0x0
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.xfer

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print xfer('123456789')
3171672888
```

### `pwnlib.util.crc.xmodem(`*`data`*`) → int` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/crc.py#L301-302)

计算xmodem校验和

这只是简单的具有以下固定参数的`generic_crc()`:

* polynom = 0x1021
* width = 16
* init = 0x0
* refin = False
* refout = False
* xorout = 0x0

同时可以参考: http://reveng.sourceforge.net/crc-catalogue/all.htm#crc.cat.xmodem

参数:	data (*str*) – 计算校验和的数据。

#### 例

```shell
>>> print xmodem('123456789')
12739
```