## `pwnlib.flag` - CTF flag 管理工具

类似于atexit，该模块允许程序员在未处理的异常发生时注册运行函数。

>**pwnlib.flag.submit_flag**(_flag, exploit='unnamed-exploit', target='unknown-target', server='flag-submission-server', port='31337', proto='tcp', team='unknown-team'_)   [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/flag.py#L21-73)

向比赛的服务器提交flag

**Parameters**:

- **flag**(_str_) \- 要提交的flag。
- **exploit**(_str_) \- 漏洞标识符，可选
- **target**(_str_) \- 目标标识符，可选
- **server**(_str_) \- flag服务器主机名，可选
- **port**(_int_) \- flag服务器端口，可选
- **proto**(_str_) \-


可选参数是从环境中推断出的，如果没有设置，则省略。


**Returns**:  指示密钥提交状态的字符串，或错误代码。

**Doctest**:  
```
>>> l = listen()
>>> _ = submit_flag('flag', server='localhost', port=l.lport)
>>> c = l.wait_for_connection()
>>> c.recvall().split()
['flag', 'unnamed-exploit', 'unknown-target', 'unknown-team']

```

