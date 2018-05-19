# pwnlib.util.iters — Extension of standard module `itertools`

这个模块包含并扩展了标准模块`itertools`。

### `pwnlib.util.iters.bruteforce(`*`func, alphabet, length, method = 'upto', start = None`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py#L735-832)

尽最大可能使`func`返回`True`。`func`应接收一个字符串输入并返回一个`bool()`。`func`会被`alphabet`中的字符串调用，直到返回`True`或搜索空间耗尽。

参数开始可以用于分割搜索空间，当CPU有多核心可用时非常有用。

参数:	
* func (*function*) – 强制执行的的功能。
* alphabet – 用于限定标记的字母。
* length – 用于尝试的字符串的最大长度。
* method – 如果为‘upto’，尝试长度为`1 .. length`的字符串；如果为‘fixed’，只尝试长度为`length`的字符串；如果未‘downfrom’，尝试长度为`length .. 1`的字符串.
* start – tuple`(i, N)`将搜索空间分割为`N`份并从第i个`(1..N)`开始。`None`则等同于`(1, 1)`。

返回:	
当`func(s)`返回`True`或当搜索空间耗尽时返回`None`时，返回字符串`s`。

#### 例

```shell
>>> bruteforce(lambda x: x == 'hello', string.lowercase, length = 10)
'hello'
>>> bruteforce(lambda x: x == 'hello', 'hllo', 5) is None
True
```

### `pwnlib.util.iters.mbruteforce(`*`func, alphabet, length, method = 'upto', start = None, threads = None`*`)` 源码e](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py#L836-917)

和`bruteforce()`功能相同，但是为多线程。

参数:	
* alphabet, length, method, start (func,) – 和`bruteforce()`的相同。
* threads – 生成的线程数量，默认为核心数量。

### `pwnlib.util.iters.chained(`*`func`*`)` 源码e](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py#L709-733)

一个链接`func`的结果的装饰器。对生成器有用。

参数:	func (*function*) – 用于装饰器的函数。

返回:	一个具有和`func(*args, **kwargs)`的返回值相关连的元素的生成器。

#### 例

```shell
>>> @chained
... def g():
...     for x in count():
...         yield (x, -x)
>>> take(6, g())
[0, 0, 1, -1, 2, -2]
```

### `pwnlib.util.iters.consume(`*`n, iterator`*`)` 源码e](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py#L117-146)

将iter前移`n`步，如果*n 为 :const:`None*，消去所有。

参数:	
* n (*int*) – 消去的元素数量。
* iterator (*iterator*) – 一个迭代器

返回:	`None`

#### 例

```shell
>>> i = count()
>>> consume(5, i)
>>> i.next()
5
>>> i = iter([1, 2, 3, 4, 5])
>>> consume(2, i)
>>> list(i)
[3, 4, 5]
```

### `pwnlib.util.iters.cyclen(`*`n, iterable`*`) → iterator` 源码e](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py#L225-244)

将迭代的元素重复`n`次

参数:	
* n (*int*) – 重复迭代的次数。
* iterable – 一个iterable。

返回:	迭代器重复n次生成的的元素。

#### 例 

```shell
>>> take(4, cyclen(2, [1, 2]))
[1, 2, 1, 2]
>>> list(cyclen(10, []))
[]
```

### `pwnlib.util.iters.dotproduct(`*`x, y`*`) → int` 源码e](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py#L246-263)

计算`x`和`y`的点积

参数:	
* x (*iterable*) – 一个iterable
* y (*iterable*) – 一个iterable

返回:	`x`和`y`的点积，即– `x[0] * y[0] + x[1] * y[1] + ....`

Example

```shell
>>> dotproduct([1, 2, 3], [4, 5, 6])
... # 1 * 4 + 2 * 5 + 3 * 6 == 32
32
```

### `pwnlib.util.iters.flatten(`*`xss`*`) → iterator` 源码e](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py#L265-285)

整合一层嵌套；当xss可迭代时，返回一个元素是`xss`元素的iter。

参数:	xss – 几个iterable中的一个的iterable。

返回:	一个元素为`xss`中的iterable的迭代器

#### 例

```shell
>>> list(flatten([[1, 2], [3, 4]]))
[1, 2, 3, 4]
>>> take(6, flatten([[43, 42], [41, 40], count()]))
[43, 42, 41, 40, 0, 1]
```

### `pwnlib.util.iters.group(`*`n, iterable, fill_value = None`*`) → iterator` 源码e](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py#L352-376)

和`pwnlib.util.lists.group()`相似，但返回是一个并使用`itertools`的快速内置功能。

参数:	
*  n(*int*) – 组的大小。
* iterable – 一个iterable。
* fill_value – `n`不能分配可迭代元素的数量时用于填入最后一组的剩余位置的值。

返回:	元素为iterable的元素的n-tuples的迭代器。

#### 例

```shell
>>> list(group(2, range(5)))
[(0, 1), (2, 3), (4, None)]
>>> take(3, group(2, count()))
[(0, 1), (2, 3), (4, 5)]
>>> [''.join(x) for x in group(3, 'ABCDEFG', 'x')]
['ABC', 'DEF', 'Gxx']
```

### `pwnlib.util.iters.iter_except(`*`func, exception`*`)` 源码e](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py#L529-563)

重复调用`func`直到引发异常。 和内置`iter()`的工作方式相同，但使用异常而不是标记来表示结尾。

参数:	
* func (*callable*) – 调用的函数。
* exception (*Exception*) – 用于表示结尾的异常。 其它异常不会被捕捉。

返回:	元素为引发匹配`exception`的异常前调用`func()`的结果的iter。

#### 例

```shell
>>> s = {1, 2, 3}
>>> i = iter_except(s.pop, KeyError)
>>> i.next()
1
>>> i.next()
2
>>> i.next()
3
>>> i.next()
Traceback (most recent call last):
    ...
StopIteration
```

### `pwnlib.util.iters.lexicographic(`*`alphabet`*`) → iterator` 源码e](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py#L688-707)

`alphabet`中的词，以字典顺序(由`alphabet`中的顺序决定)。

参数:	alphabet – 用于作为标记的字母。

返回:	带有以字典顺序的`alphabet`中标记的词的元素的iter。

Example

```shell
>>> take(8, imap(lambda x: ''.join(x), lexicographic('01')))
['', '0', '1', '00', '01', '10', '11', '000']
```

### `pwnlib.util.iters.lookahead(`*`n, iterable`*`) → object` 源码e](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py#L657-686)

没有前移iter的情况下检索下标为`n`的元素，如果元素过少则引发`IndexError`异常。

参数:	
* n (*int*) – 元素的下标。
* iterable – 一个iterable

返回:	`iterable`中下表为`n`的元素。

#### 例

```shell
>>> i = count()
>>> lookahead(4, i)
4
>>> i.next()
0
>>> i = count()
>>> nth(4, i)
4
>>> i.next()
5
>>> lookahead(4, i)
10
```

### `pwnlib.util.iters.nth(`*`n, iterable, default = None) → object源码e](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py#L148-174)

返回`iterable`中下标位`n`的元素，如果`iterable`是一个迭代器，它将会被前移。

参数:	
* n (*int*) – 元素的下标
* iterable – 一个iterable.
* default (*objext*) – 一个默认值。

返回:	
iterable中下标为`n`的元素，如果元素过少则为`defalut`的元素。

#### 例

```shell
>>> nth(2, [0, 1, 2, 3])
2
>>> nth(2, [0, 1], 42)
42
>>> i = count()
>>> nth(42, i)
42
>>> nth(42, i)
85
```

### `pwnlib.util.iters.pad(`*`iterable, value = None`*`) → iterator` 源码e](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py#L198-223)

使用`value`填充`iterable`，即返回一个元素首先为`iterable`中的元素，其余为无限赋值的迭代器。

参数:	
* iterable – 一个iterable.
* value – 用于填充的值。

返回:	一个元素首先为`iterable`中的元素，其余为无限赋值的迭代器。

#### 例

```shell
>>> take(3, pad([1, 2]))
[1, 2, None]
>>> i = pad(iter([1, 2, 3]), 42)
>>> take(2, i)
[1, 2]
>>> take(2, i)
[3, 42]
>>> take(2, i)
[42, 42]
```

### `pwnlib.util.iters.pairwise(`*`iterable`*`) → iterator` 源码e](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py#L331-350)

参数:	iterable – 一个iterable.

返回:	元素为`iterable`的元素的相邻元素对的迭代器。

#### 例

```shell
>>> list(pairwise([1, 2, 3, 4]))
[(1, 2), (2, 3), (3, 4)]
>>> i = starmap(operator.add, pairwise(count()))
>>> take(5, i)
[1, 3, 5, 7, 9]
```

### `pwnlib.util.iters.powerset(`*`iterable, include_empty = True`*`) → iterator` 源码e](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py#L407-429)

`iterable`的幂集。

参数:	
* iterable – 一个iterable.
* include_empty (*bool*) – 是否包括空集。

返回:	以tuple形式的迭代器的`iterable`幂集

#### 例

```shell
>>> list(powerset(range(3)))
[(), (0,), (1,), (2,), (0, 1), (0, 2), (1, 2), (0, 1, 2)]
>>> list(powerset(range(2), include_empty = False))
[(0,), (1,), (0, 1)]
```

### `pwnlib.util.iters.quantify(`*`iterable, pred = bool`*`) → int` [源码]()

计算`pred`为`True`的次数。

参数:	
* iterable – 一个iterable.
* pred – 用于使`iterable`中的元素返回`True`或`False`的函数。

返回:	`iterable`中的元素使`pred`返回`True`的次数

#### 例

```shell
>>> quantify([1, 2, 3, 4], lambda x: x % 2 == 0)
2
>>> quantify(['1', 'two', '3', '42'], str.isdigit)
3
```

### `pwnlib.util.iters.random_combination(`*`iterable, r`*`) → tuple` 源码e](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py#L612-631)

参数:	
* iterable – 一个iterable.
* r (*int*) – 结合的大小。

返回:	从`itertools.combinations(iterable, r = r)`得到的随机元素

#### 例

```shell
>>> random_combination(range(2), 2)
(0, 1)
>>> random_combination(range(10), r = 2) in combinations(range(10), r = 2)
True
```

### `pwnlib.util.iters.random_permutation(`*`iterable, r=None`*`)` 源码e](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py#L591-610)

random_product(iterable, r = None) -> tuple

参数:	
* iterable – 一个iterable.
* r (*int*) – 置换的大小，如果为`None`则选择所有`iterable`的元素。

返回:	从`itertools.permutations(iterable, r = r)`得到的随机元素

#### 例

```shell
>>> random_permutation(range(2)) in {(0, 1), (1, 0)}
True
>>> random_permutation(range(10), r = 2) in permutations(range(10), r = 2)
True
```

### `pwnlib.util.iters.random_product(`*`*args, repeat = 1`*`) → tuple` 源码e](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py#L565-589)

参数:	
* args – 一个或多个iterables
* repeat (*int*) – 重复`args`的次数。

返回:	从`itertools.product(*args, repeat = repeat)`得到的随机元素。

#### 例

```shell
>>> args = (range(2), range(2))
>>> random_product(*args) in {(0, 0), (0, 1), (1, 0), (1, 1)}
True
>>> args = (range(3), range(3), range(3))
>>> random_product(*args, repeat = 2) in product(*args, repeat = 2)
True
```

### `pwnlib.util.iters.repeat_func(`*`func, *args, **kwargs`*`) → iterator` [源码]()

使用位置参数`args`和关键字参数`kwargs`重复调用`func()`。如果没有关键词提供，那么将使用`itertools`中得快速函数计算得到得迭代器。

参数:	
* func (*function*) – 调用的参数
* args – 位置参数
* kwargs – 关键字参数
返回:	
元素为重复调用`func(*args, **kwargs)`的结果的迭代器。

#### 例

```shell
>>> def f(x):
...     x[0] += 1
...     return x[0]
>>> i = repeat_func(f, [0])
>>> take(2, i)
[1, 2]
>>> take(2, i)
[3, 4]
>>> def f(**kwargs):
...     return kwargs.get('x', 43)
>>> i = repeat_func(f, x = 42)
>>> take(2, i)
[42, 42]
>>> i = repeat_func(f, 42)
>>> take(2, i)
Traceback (most recent call last):
    ...
TypeError: f() takes exactly 0 arguments (1 given)
```

### `pwnlib.util.iters.roundrobin(`*`*iterables`*`)` 源码e](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py#L378-405)

以循环方式从`iterables`中获取元素。

参数:	*iterables – 一个或多个iterable

返回:	以循环方式从`iterables`中获取元素的迭代器。

#### 例

```shell
>>> ''.join(roundrobin('ABC', 'D', 'EF'))
'ADEBFC'
>>> ''.join(take(10, roundrobin('ABC', 'DE', repeat('x'))))
'ADxBExCxxx'
```

### `pwnlib.util.iters.tabulate(`*`func, start = 0`*`) → iterator` 源码e](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py#L99-115)

参数:	
* func (*function*) – 用于制表的功能。
* start (*int*) – 开始的数值。

返回:	带有元素`func(start), func(start + 1), ....`的iterator。

#### 例

```shell
>>> take(2, tabulate(str))
['0', '1']
>>> take(5, tabulate(lambda x: x**2, start = 1))
[1, 4, 9, 16, 25]
```

### `pwnlib.util.iters.take(`*`n, iterable`*`) → list` 源码e](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py#L72-97)

返回`iterable`的前`n`个元素。如果`iterable`是迭代器则会往前移动。

参数:	
* n (int) – 得到的元素数量。
* iterable – 一个iterable。

返回:	
`iterable`的前`n`个元素，如果元素数量少于`n`则元素会被返回。

#### 例

```shell
>>> take(2, range(10))
[0, 1]
>>> i = count()
>>> take(2, i)
[0, 1]
>>> take(2, i)
[2, 3]
>>> take(9001, [1, 2, 3])
[1, 2, 3]
```

### `pwnlib.util.iters.unique_everseen(`*`iterable, key = None`*`) → iterator` 源码e](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py#L431-464)

获取独特的元素，保持其顺序，记录所有得到的元素。如果`key`不为`None`，对于`iterable`的每个元素`elm`，会被记录的是`key(elm)`。 否则`elm`会被记录。

参数:	
* iterable – 一个iterable.
* key – 在记录前用于映射每个`iterable`中的元素的函数，设置为`None`则与特征功能相同。

返回:	包含`iterable`中独特元素的迭代器。

#### 例

```shell
>>> ''.join(unique_everseen('AAAABBBCCDAABBB'))
'ABCD'
>>> ''.join(unique_everseen('ABBCcAD', str.lower))
'ABCD'
```

### `pwnlib.util.iters.unique_justseen(`*`iterable, key=None`*`) 源码e](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py#L490-527)

unique_everseen(iterable, key = None) -> iterator

获取独特的元素，保持其顺序。只记录当前的元素。如果`key`不为`None`，对于`iterable`的每个元素`elm`，会被记录的是`key(elm)`。 否则`elm`会被记录。

参数:	
* iterable – 一个iterable.
* key – 用于记录前匹配`iterable`中的每一个元素的函数， 设置为`None`则与特征功能相同。

返回:	包含`iterable`中独特元素的迭代器。

#### 例

```shell
>>> ''.join(unique_justseen('AAAABBBCCDAABBB'))
'ABCDAB'
>>> ''.join(unique_justseen('ABBCcAD', str.lower))
'ABCAD'
```

### `pwnlib.util.iters.unique_window(`*`iterable, window, key=None`*`)` 源码e](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py#L490-527)

unique_everseen(iterable, window, key = None) -> iterator

获取独特的元素，保持其顺序。只记录最后的窗口元素。如果`key`不为`None`，对于`iterable`的每个元素`elm`，会被记录的是`key(elm)`。 否则`elm`会被记录。

参数:	
* iterable – 一个iterable.
* window (*int*) – 记录的元素数量。
* key – 用于记录前匹配`iterable`中的每一个元素的函数， 设置为`None`则与特征功能相同。

返回:	包含`iterable`中独特元素的迭代器。

#### 例

```shell
>>> ''.join(unique_window('AAAABBBCCDAABBB', 6))
'ABCDA'
>>> ''.join(unique_window('ABBCcAD', 5, str.lower))
'ABCD'
>>> ''.join(unique_window('ABBCcAD', 4, str.lower))
'ABCAD'
```

### `pwnlib.util.iters.chain()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py)

`itertools.chain()`的别名。

### `pwnlib.util.iters.combinations()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py)

`itertools.combinations()`的别名。

### `pwnlib.util.iters.combinations_with_replacement()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py)

`itertools.combinations_with_replacement()`的别名。

### `pwnlib.util.iters.compress()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py)

`itertools.compress()`的别名。

### `pwnlib.util.iters.count()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py)

`itertools.count()`的别名。

### `pwnlib.util.iters.cycle()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py)

`itertools.cycle()`的别名。

### `pwnlib.util.iters.dropwhile()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py)

`itertools.dropwhile()`的别名。

### `pwnlib.util.iters.groupby()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py)

`itertools.groupby()`的别名。

### `pwnlib.util.iters.ifilter()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py)

`itertools.ifilter()`的别名。

### `pwnlib.util.iters.ifilterfalse()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py)

`itertools.ifilterfalse()`的别名。

### `pwnlib.util.iters.imap()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py)

`itertools.imap()`的别名。

### `pwnlib.util.iters.islice()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py)

`itertools.islice()`的别名。

### `pwnlib.util.iters.izip()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py)

`itertools.izip()`的别名。

### `pwnlib.util.iters.izip_longest()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py)

`itertools.izip_longest()`的别名。

### `pwnlib.util.iters.permutations()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py)

`itertools.permutations()`的别名。

### `pwnlib.util.iters.product()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py)

`itertools.product()`的别名。

### `pwnlib.util.iters.repeat()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py)

`itertools.repeat()`的别名。

### `pwnlib.util.iters.starmap()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py)

`itertools.starmap()`的别名。

### `pwnlib.util.iters.takewhile()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py)

`itertools.takewhile()`的别名。

### `pwnlib.util.iters.tee()` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/iters.py)

`itertools.tee()`的别名。