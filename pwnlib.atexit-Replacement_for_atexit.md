## `pwnlib.atexit` - python内置atexit的替代品

替换Python标准库的atexit.py。

虽然标准的`atexit`模块只定义了`atexit.register()`,但这个替换模块还定义了`unregister()`。

这个模块还修复了使用标准的`atexit`时退出处理程序引发异常被打印两次的问题。


>**pwnlib.atexception.register**(_func, \*args, **kwargs_)   [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/atexit.py#L24-58)

注册一个在程序终止时调用的函数。该函数在使用位置参数`args`和关键字参数`kwargs`时调用，即`func(*args, **kwargs)`。当前_context_会被记录下来，这样可以在处理程序运行时使用该_context_。

例如，为了阻止退出处理程序的日志记录输出，可以编写：

```
with context.local(log_level = 'error'):
  atexit.register(handler)
```

返回一个可用于注销退出处理程序的标识符。

这个函数可以用作装饰器：

```
@atexit.register
def handler():
  ...
```

需要注意的是，这是将处理程序绑定到标识符，而不是实际的退出处理程序。然后，退出处理程序可以通过以下方式注销：

```
atexit.unregister(handler)
```

这个函数是线程安全的。


>**pwnlib.atexception.unregister**(_ident_)   [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/atexit.py#L60-67)


从注册处理程序列表中删除由_ident_标识的退出处理程序。 如果_ident_没有注册，这是一个空操作。