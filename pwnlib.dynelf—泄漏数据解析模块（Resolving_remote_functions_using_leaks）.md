# `pwnlib.dynelf`—泄漏数据解析模块（Resolving remote functions using leaks）
`pwnlib.dynelf`模块能借以读取内存泄漏数据，来解析装载动态链接库的ELF文件的符号。

### **示例**

    # 监听一个进程或远程连接
    p = process('./pwnme')
    
    # leak()函数声明
    # 这个函数可以从传入的地址中读出至少一个字节
    # 的数据。
    def leak(address):
        data = p.read(address, 4)
        log.debug("%#x => %s" % (address, (data or '').encode('hex')))
        return data
    
    # 这个示例中，第一个指针main指向目标二进制文件
    # 其余两个指针指向linc库函数
    main   = 0xfeedf4ce
    libc   = 0xdeadb000
    system = 0xdeadbeef
    
    # 借以leak函数和指向目标二进制文件的指针，
    # 我们可以对目标文件的任意地址进行解析
    #
    # 实际上，我们可以不留一份目标文件的拷贝来
    # 使之工作
    d = DynELF(leak, main)
    assert d.lookup(None,     'libc') == libc
    assert d.lookup('system', 'libc') == system
    
    
    # 当然，如果我们已经留了一份关于目标文件的拷贝
    # 我们也可以跳过一些步骤，直接解析，如下
    d = DynELF(leak, main, elf=ELF('./pwnme'))
    assert d.lookup(None,     'libc') == libc
    assert d.lookup('system', 'libc') == system
    
    # 我们也可以通过传入指向其他库的指针来解析其中
    # 对应库的符号
    # Alternately, we can resolve symbols inside another library,
    # given a pointer into it.
    d = DynELF(leak, libc + 0x1234)
    assert d.lookup('system')      == system
    
### DynELF
原型声明：*class* **pwnlib.dynelf.DynELF**(*leak, pointer=None, elf=None, libcdb=True*)

DynELF可以借助封装在`pwnlib.memleak.MemLeak`内存泄漏模块，来解析进程的符号表。
#### 功能原理：
- 函数解析：
    
    对于由库(像libc. so)导出符号的Elf文件，它们有一个记录输出符号名、输出符号地址及对应`哈希(hash)`的表。 程序会利用哈希函数将符号(例如`'printf'`)定位到其哈希表中，这份表中提供了一个关于字符串表(strtab)和符号地址表(symtab)的索引。
    
    假定我们有`libc.so`的基址，要解析出`printf`的地址就需要在符号表(symtab)、字符串表(strtab)和相应哈希表定位它。字符串`"printf"`将会以SYSV或GNU的哈希计算方式计算出一个值，并在对应哈希表中定位直至匹配到合适入口点。我们可以通过检查字符串表来辨识这个匹配的位置，进而从符号表中获得它在`libc.so`中的偏移量。
- 库地址解析：

    当我们有一个指向动态链接可执行文件的指针时，我们就可以利用一个叫`link map`的结构，这是一个链接表式的结构体，包含了关于程序每一个装载的库、绝对路径及基址。
    
    有两种方法可以让我们找到`link map`的地址。这两种方式都需要到利用动态数组空间(the DYNAMIC array)。
    * 在未采用RELRO数据段保护技术的二进制文件中，.got.plt保存了重定位地址，我们可以通过查找全局偏移表地址(DT_PLTGOT段)来实现。
    * 在所有二进制文件中，我们可以从被标记为DT_DEBUG的段中寻找`link map`的地址，甚至对于去符号信息的二进制文件(stripped)也有效。
    
    在解析时，这两种机制均会被运用。
    
- 当传入由`pwnlib.memleak.Memleak`实例化的一个对象和一个地址时，DynELF对象便可实例化并进行符号解析。
    
    **DynELF参数**： 
            
    - **leak** *(MemLeak)* - `pwnlib.memleak.MemLeak`模块实例化对象
    - **pointer** *(int)* - 一个ELF文件内的地址
    - **elf** *(str,ELF)* - ELF文件在磁盘中的路径，或者`pwnlib.elf.ELF`实装对象
    - **libcdb** *(bool)* - 尝试使用libcdb去加速查询
    
> bases()
    
    解析所有被装载文件的基址
    返回一个由库地址映射到其基址的索引

> *static* find_base(*leak,ptr*)
    
    根据传入的pwnlib.memleak.MemLeak实例化对象及指针，查找出对应的基址
    
> heap()
    
    通过__curbrk找到当前堆顶
    
> lookup(*symb = None, lib = None*) -> int

    找到lib中符号symbol的地址，并将其返回，否则返回None
    ·symb(str) - 指定待查找的符号，若不填，则默认返回该lib的基址
    ·lib(str) - 指定待查找符号所在库，若不填，则默认在当前库查找，如'libc'、'lib.so'

> stack()
    
    通过__environ找到栈的地址
    
> dynamic
    
    返回指向.DYNAMIC段的指针

> elfclass
    
    32 或 64
    
> elftype
    
    根据elf文件头，通常的这个值会是'EXEC'或者'DYN'。
    如果这个值是其他结构性值(ET_LOPROC、ET_HIPROC之间)或非法值，此处将会提示错误
    
> linc
    
    从linc.so获得Build ID号，下载文件并以当前基址装载一个ELF文件
    返回一个ELF对象或者None
    
其他声明：

**pwnlib.dynelf.gnu_hash(*str*)->int**
    
    用于生成GNU格式字符串的哈希值
    
**pwnlib.dynelf.sysv_hash(*str*)->int**
    用于生成SYSV格式字符串的哈希值