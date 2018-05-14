# pwnlib.util.lists — Operations on lists

### `pwnlib.util.lists.concat(`*`l`*`) → list` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/lists.py#L89-105)

将有关list的list放入list。

#### 例

```shell
>>> concat([[1, 2], [3]])
[1, 2, 3]
```

### `pwnlib.util.lists.concat_all(`*`*args`*`) → list` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/lists.py#L107-125)

将所有参数放到一起

#### 例

```shell
>>> concat_all(0, [1, (2, 3)], [([[4, 5, 6]])])
[0, 1, 2, 3, 4, 5, 6]
```

### `pwnlib.util.lists.findall(`*`l, e`*`) → l` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/lists.py#L149-208)

使用Knuth-Morris-Pratt算法生成所有指数。

#### 例

```shell
>>> foo = findall([1,2,3,4,4,3,4,2,1], 4)
>>> foo.next()
3
>>> foo.next()
4
>>> foo.next()
6
```

### `pwnlib.util.lists.group(`*`n, lst, underfull_action = 'ignore', fill_value = None`*`) → list` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/lists.py#L34-87)

将序列分割成指定大小的子序列。如果值不能均匀分布到组中，最后一组将原样返回，抛出或填充`fill_value`的值。

参数:	
* n (*int*) – 生成的组的大小。
* lst – 需要分组的list, tuple或字符串。
* underfull_action (*str*) – 最后一组采取的行为。 可能的值是“ignore”，“drop”或“fill”。
* fill_value – 填充到最后一组的值。

返回: 包含分组值的list。

#### 例

```shell
>>> group(3, "ABCDEFG")
['ABC', 'DEF', 'G']
>>> group(3, 'ABCDEFG', 'drop')
['ABC', 'DEF']
>>> group(3, 'ABCDEFG', 'fill', 'Z')
['ABC', 'DEF', 'GZZ']
>>> group(3, list('ABCDEFG'), 'fill')
[['A', 'B', 'C'], ['D', 'E', 'F'], ['G', None, None]]
```

### `pwnlib.util.lists.ordlist(`*`s`*`) → list` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/lists.py#L127-136)

将字符串转换为相应ascii值的list。

#### 例

```shell
>>> ordlist("hello")
[104, 101, 108, 108, 111]
```

### `pwnlib.util.lists.partition(`*`lst, f, save_keys = False`*`) → list` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/lists.py#L4-32)

使用函数将迭代器分割成子列表，以指定它们属于哪个组。

它通过在每个元素上调用`f`并将结果保存到`collections.OrderedDict`中来工作。

参数:	
* lst – 可迭代的分区。
* f (*function*) – 用作分组程序的函数。
* save_keys (*bool*) – 如果你想返回`OrderedDict`而不仅仅是值，将其设置为`True`。

#### 例

```shell
>>> partition([1,2,3,4,5], lambda x: x&1)
[[1, 3, 5], [2, 4]]
```

### `pwnlib.util.lists.unordlist(`*`cs`*`) → str` [源码]()

获取ascii值list并返回相应的字符串。

#### 例

```shell
>>> unordlist([104, 101, 108, 108, 111])
'hello'
```