# pwnlib.encoders—Shellcode编码处理(Encoding Shellcode)
该模块用于编码处理shellcode来防止输入过滤。

####  pwnlib.encoders.encoder.alphanumeric(*raw_bytes*)→str

该模块可以编码处理shellcode`raw_bytes`，使它们不包含于A-Z、a-z、0-9的范围内

接受像`encode()`这样的参数

####  pwnlib.encoders.encoder.encode(*raw_bytes, avoid, expr, force*) → str
该模块可以编码处理shellcode`raw_bytes`中的除`avoid`或`expr`中指定字节外的`raw_bytes`

参数说明：
    
* **raw_bytes**(*str*) - 待处理的shellcode比特序列
* **avoid**(*str*) - 待处理字符排除的序列
* **expr**(*str*) - 可能匹配到无效字符(bad characters)的序列
* **force**(*bool*) - 是否强制重新编码shellcode。

#### pwnlib.encoders.encoder.line(*raw_bytes*)→str
对shellcode`raw_bytes`进行编码，使它们不包括任何**空字节或者空格**

接受像`encode()`这样的参数

#### pwnlib.encoders.encoder.null(*raw_bytes*)→str
对shellcode`raw_bytes`进行编码，使它们不包括任何**空字节**

接受像`encode()`这样的参数

#### pwnlib.encoders.encoder.printable(*raw_bytes*)→str
对shellcode`raw_bytes`进行编码，使它们仅包括**可打印字符**

接受像`encode()`这样的参数

#### pwnlib.encoders.encoder.scramble(*raw_bytes*)→str
随机选择一种编码方式对传入数据进行编码。

接受像`encode()`这样的参数

#### *class*.pwnlib.encoders.i386.xor.1386XorEncoder
生成一个适用于i386机器的异或解码类(XOR decoder)。
`
    
    >>> context.clear(arch='i386')
    >>> shellcode = asm(shellcraft.sh())
    >>> avoid = '/bin/sh\xcc\xcd\x80'
    >>> encoded = pwnlib.encoders.i386.xor.encode(shellcode, avoid)
    >>> assert not any(c in encoded for c in avoid)
    >>> p = run_shellcode(encoded)
    >>> p.sendline('echo hello; exit')
    >>> p.recvline()
    'hello\n'