## `pwnlib.atexception` - 回调未处理的异常

类似于atexit，该模块允许程序员在未处理的异常发生时注册运行函数。

>**pwnlib.atexception.register**(_func, \*args, **kwargs_)   [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/atexception.py#L19-55)

注册一个在未处理的异常发生时被调用的函数。该函数可用位置参数_args_和关键字参数_kwargs_来调用，即`func(*args, **kwargs)`。当前_context_会被记录下来，这样可以在处理程序运行时使用该_context_。

例如，为了阻止异常处理程序的日志记录输出，可以编写：

```
with context.local(log_level = 'error'):
  atexception.register(handler)
```

返回一个可用于注销异常处理程序的标识符。

这个函数可以用作装饰器：

```
@atexception.register
def handler():
  ...
```

需要注意的是，这是将处理程序绑定到标识符，而不是实际的异常处理程序。然后，异常处理程序可以通过以下方式注销：

```
atexception.unregister(handler)
```

这个函数是线程安全的。


>**pwnlib.atexception.unregister**(_func_)   [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/atexception.py#L57-64)

从注册函数集合中删除函数。如果函数没有注册，这是一个空操作。




