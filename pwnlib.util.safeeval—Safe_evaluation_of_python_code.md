# pwnlib.util.safeeval — Safe evaluation of python code

### `pwnlib.util.safeeval.const(`*`expression`*`) → value` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/safeeval.py#L59-81)

python的持续安全评估

评估一个包含描述python常量表达式的字符串。字符串不是有效的python表达式，或包含常量之外的其他代码会引发ValueError异常。

#### 例

```shell
>>> const("10")
10
>>> const("[1,2, (3,4), {'foo':'bar'}]")
[1, 2, (3, 4), {'foo': 'bar'}]
>>> const("[1]+[2]")
Traceback (most recent call last):
...
ValueError: opcode BINARY_ADD not allowed
```

### `pwnlib.util.safeeval.expr(`*`expression`*`) → value` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/safeeval.py#L83-105)

安全的python表达式评估。

评估一个包含只使用python常量表达式的字符串。这可以用于如：评估来自不可信来源的数字表达式。

#### 例

```shell
>>> expr("1+2")
3
>>> expr("[1,2]*2")
[1, 2, 1, 2]
>>> expr("__import__('sys').modules")
Traceback (most recent call last):
...
ValueError: opcode LOAD_NAME not allowed
```

### `pwnlib.util.safeeval.test_expr(`*`expr, allowed_codes`*`) → codeobj` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/safeeval.py#L40-57)

测试该表达式是否只包含列出的的操作码。如果表达式是有效的而且只包含允许的代码，返回编译后的代码对象。否则引发ValueError异常。

### `pwnlib.util.safeeval.values(`*`expression, dict`*`) → value` [源码]()

安全的python表达式评估。

评估一个包含只使用python表达式和提供的字典中的值的字符串。这可以用于如：评估系统调用参数。

>Note: 这可能是不安全的，如：在`__add__`方法上有副作用。

#### 例

```shell
>>> values("A + 4", {'A': 6})
10
>>> class Foo:
...    def __add__(self, other):
...        print "Firing the missiles"
>>> values("A + 1", {'A': Foo()})
Firing the missiles
>>> values("A.x", {'A': Foo()})
Traceback (most recent call last):
...
ValueError: opcode LOAD_ATTR not allowed
```