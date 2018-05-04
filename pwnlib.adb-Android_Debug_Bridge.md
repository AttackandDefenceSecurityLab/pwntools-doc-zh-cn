## `pwnlib.adb` -Android调试桥

通过Android调试桥提供用于与Android设备进行交互的实用工具

### Pwntools与Android设备搭配使用

Pwntools试图将其与Android设备的搭配使用变得更加方便！

如果你只连接了一台设备，那么一切都会“运行正常”。

如果你需要连接多个设备，你可以选择一个或者多个设备进行迭代。

最首要同时也是最重要的就是`context.device`属性，它允许在任何范围内声明“当前”已经选择的设备。它可以被手动设置为序列号或者设备实例。

```
# Take the first available device
context.device = adb.wait_for_device()

# Set a device by serial number
context.device = 'ZX1G22LH8S'

# Set a device by its product name
for device in adb.devices():
    if device.product == 'shamu':
        break
else:
    error("Could not find any shamus!")
```

一台设备一旦被选择，你可以使用`pwnlib.adb`上面任何的功能模块对它进行操作。

```
# Get a process listing
print adb.process(['ps']).recvall()

# Fetch properties
print adb.properties.ro.build.fingerprint

# Read and write files
print adb.read('/proc/version')
adb.write('/data/local/tmp/foo', 'my data')

```

 

*class* pwnlib.adb.adb.AdbDevice(_serial, type, port=None, product='unknown', model='unknown', device='unknown', features=None, **kw_)    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py)

与已连接设备相关的封装信息。

**Example**

```
>>> device = adb.wait_for_device()
>>> device.arch
'arm'
>>> device.bits
32
>>> device.os
'android'
>>> device.product
'sdk_phone_armv7'
>>> device.serial
'emulator-5554'
```

 

pwnlib.adb.adb.adb(_argv, \*a, **kw_)    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L74-89)

返回ADB子命令的输出。

```
>>> adb.adb(['get-serialno'])
'emulator-5554\n'
```

 

pwnlib.adb.adb.boot_time() → int     [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L127-136)

**Returns:**在Unix时间戳上的设备引导时间会四舍五入成最接近的秒数

 

pwnlib.adb.adb.build(_\*a, **kw_)     [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L127-136)

返回设备的构建版本号。

 

pwnlib.adb.adb.compile_(source)_    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L1184-1237)

使用Android NDK编译源文件或项目。

 

pwnlib.adb.adb.current_device_(any=False)_    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L109-124)

为当前选择的设备返回一个`AdbDevice`实例(通过`context.device`)。

**Example**

```
>>> device = adb.current_device(any=True)
>>> device
AdbDevice(serial='emulator-5554', type='device', port='emulator', product='sdk_phone_armv7', model='sdk phone armv7', device='generic')
>>> device.port
'emulator'
```

 

pwnlib.adb.adb.devices(_\*a, **kw_)     [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L549-555)

返回与连接设备对应的设备对象列表。

 

pwnlib.adb.adb.disable_verity_(\*a, **kw)_     [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L127-136)

禁用设备上的dm-verity。

 

pwnlib.adb.adb.exists(_\*a, **kw_)     [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L549-555)

如果目标设备上存在`path`，则返回`True`

**Examples**

```
>>> adb.exists('/')
True
>>> adb.exists('/init')
True
>>> adb.exists('/does/not/exist')
False
```

 

pwnlib.adb.adb.fastboot_(\*a, **kw)_     [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L127-136)

执行fastboot命令。

**Returns:**命令输出。

 

pwnlib.adb.adb.find_ndk_project_root_(source)_     [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L1119-1132)

给定一个目录路径，找到最顶层的项目的根目录。

tl;dr “foo/bar/jni/baz.cpp” ==> “foo/bar”

 

pwnlib.adb.adb.fingerprint_(\*a, **kw)_      [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L127-136)

返回设备所构建的指纹信息。

 

pwnlib.adb.adb.forward_(\*a, **kw)_     [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L127-136)

设置一个端口转发到设备。

 

pwnlib.adb.adb.getprop_(\*a, **kw)_     [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L127-136)

从系统属性存储中读取一项属性。

**Parameters:**  **name** (_str_) - 可选，读取单个属性。

**Returns:**如果没有指定名称，则返回所有属性的字典。 否则，将返回一个包含指定属性的内容的字符串。

 

pwnlib.adb.adb.install_(apk, \*arguments)_     [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L1339-1365)

将APK安装到设备上。

这是'pm install'的封装，它支持'adb install'。

**Parameters:**

- **apk** *(str)* - 安装APK的路径(e.g.`'foo.apk'`）
- **arguments** - 'pm install'的补充参数(e.g.`'-l', '-g'`)。




pwnlib.adb.adb.interactive_(\*a, **kw)_    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L127-136)

产生一个交互式shell。

 

pwnlib.adb.adb.isdir_(\*a, **kw)_   [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L549-555)

如果`path`位于目标设备上，则返回`True`。

**Examples**

```
>>> adb.isdir('/')
True
>>> adb.isdir('/init')
False
>>> adb.isdir('/does/not/exist')
False
```

 

pwnlib.adb.adb.listdir_(\*a, **kw)_    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L127-136)

返回包含所提供目录中的条目的列表。

- **Note**

这使用了SYNC LIST功能，该功能在adbd SELinux环境中运行。如果adbd在su domain中运行(‘adb root’)，则它的行为将如期进行。另外，可能会因在adbd上的限制性SELinux策略而返回更少的文件

 

pwnlib.adb.adb.logcat_(\*a, **kw)_    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L549-555)

读取系统日志文件。

默认情况下，读取文件后会导致logcat退出。

**Parameters:  stream** (*bool*) - 如果为`True`，则内容将流式传输，而不是以一次性方式读取。 默认值是`False`。

**Returns**:如果`stream`是`False`，则返回一个包含日志数据的字符串。否则，它将返回一个连接到日志输出的`pwnlib.tubes.tube.tube`。

 

pwnlib.adb.adb.makedirs_(\*a, **kw)_    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L549-555)

在目标设备上创建一个目录和所有父目录。

- **Note**

如果目录已经存在，则默认创建成功。

**Examples**

```
>>> adb.makedirs('/data/local/tmp/this/is/a/directory/heirarchy')
>>> adb.listdir('/data/local/tmp/this/is/a/directory')
['heirarchy']
```

 

pwnlib.adb.adb.mkdir_(\*a, **kw)_   [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L549-555)

在目标设备上创建一个目录。

- **Note**

如果目录已经存在，则默认创建成功。

**Parameters:  path**(*str*) - 所需创建的目录。

**Examples**

```
>>> adb.mkdir('/')
```

```
>>> path = '/data/local/tmp/mkdir_test'
>>> adb.exists(path)
False
>>> adb.mkdir(path)
>>> adb.exists(path)
True
```

```
>>> adb.mkdir('/init')
Traceback (most recent call last):
...
PwnlibException: mkdir failed for /init, File exists
```

 

pwnlib.adb.adb.packages_(\*a, **kw)_    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L549-555)

返回系统上安装的软件包列表。

 

pwnlib.adb.adb.pidof_(\*a, **kw)_    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L127-136)

返回指定进程的PID列表。

 

pwnlib.adb.adb.proc_exe_(\*a, **kw)_    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L127-136)

返回所提供的PID的可执行文件的完整路径。

 

pwnlib.adb.adb.process_(\*a, **kw)_   [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L127-136)

在设备上执行一个进程。

有关更多信息，请参阅`pwnlib.tubes.process.process`文档。

**Returns:** 一份`pwnlib.tubes.process.process`文档通道。

**Examples**

```
>>> adb.root()
>>> print adb.process(['cat','/proc/version']).recvall() 
Linux version ...
```

 

pwnlib.adb.adb.product_(\*a, **kw)_    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L127-136)

返回设备的产品标识符。

 

pwnlib.adb.adb.pull_(\*a, **kw)_     [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L127-136)

从设备下载文件。

**Parameters:**

- **remote_path** (*str*) - 设备上文件的路径或目录。
- **local_path** (*str*) - 保存文件的路径。 默认使用该文件的名称。

**Returns:**  文件的内容。

**Example**

```
>>> _=adb.pull('/proc/version', './proc-version')
>>> print read('./proc-version') 
Linux version ...
```

 

pwnlib.adb.adb.push_(\*a, **kw)_     [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L127-136)

上传文件到设备。

**Parameters:**

- **local_path** (*str*)- 推送本地文件的路径。
- **remote_path** (*str*) - 在设备上存储文件的路径或目录。

**Returns:**文件的远程路径。

**Example**

```
>>> write('./filename', 'contents')
>>> adb.push('./filename', '/data/local/tmp')
'/data/local/tmp/filename'
>>> adb.read('/data/local/tmp/filename')
'contents'
>>> adb.push('./filename', '/does/not/exist')
Traceback (most recent call last):
...
PwnlibException: Could not stat '/does/not/exist'
```

 

pwnlib.adb.adb.read_(\*a, **kw)_    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L549-555)

从设备下载文件，并提取其内容。

**Parameters:**

- **path** (*str*) - 设备上文件的路径。
- **target** (*str*) - 可选，用于存储文件的位置。默认使用临时文件。
- **callback** (*callable*) - 请参阅文档 `adb.protocol.AdbClient.read`。

**Examples**

```
>>> print adb.read('/proc/version') 
Linux version ...
>>> adb.read('/does/not/exist')
Traceback (most recent call last):
...
PwnlibException: Could not stat '/does/not/exist'
```

 

pwnlib.adb.adb.reboot_(\*a, **kw)_    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L163-168)

重启设备。

 

pwnlib.adb.adb.reboot_bootloader_(\*a, **kw)_     [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L163-168)

将设备重新引导到引导加载程序。

 

pwnlib.adb.adb.remount_(\*a, **kw)_    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L127-136)

将文件系统重新设置为可写。

 

pwnlib.adb.adb.root_(\*a, **kw)_    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L127-136)

以root身份重新启动adbd。

```
>>> adb.root()
```

 

pwnlib.adb.adb.setprop_(\*a, **kw)_    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L127-136)

将属性写入系统属性存储区。

 

pwnlib.adb.adb.shell_(\*a, **kw)_   [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L127-136)

返回交互式shell。

 

pwnlib.adb.adb.uninstall_(package, \*arguments)_    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L1367-1378)

从设备上卸载APK。

这是'pm uninstall'的一个包装，它支持'adb uninstall'。

**Parameters:**

- **package**(*str*) - Name of the package to uninstall (e.g. `'com.foo.MyPackage'`)
- **arguments** - Supplementary arguments to `'pm install'`, e.g. `'-k'`。




pwnlib.adb.adb.unlink_(\*a, **kw)_ [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L549-555)

断开目标设备上的文件或目录。

**Examples**

```
>>> adb.unlink("/does/not/exist")
Traceback (most recent call last):
...
PwnlibException: Could not unlink '/does/not/exist': Does not exist
```

```
>>> filename = '/data/local/tmp/unlink-test'
>>> adb.write(filename, 'hello')
>>> adb.exists(filename)
True
>>> adb.unlink(filename)
>>> adb.exists(filename)
False
```

```
>>> adb.mkdir(filename)
>>> adb.write(filename + '/contents', 'hello')
>>> adb.unlink(filename)
Traceback (most recent call last):
...
PwnlibException: Cannot delete non-empty directory '/data/local/tmp/unlink-test' without recursive=True
```

```
>>> adb.unlink(filename, recursive=True)
>>> adb.exists(filename)
False
```

 

pwnlib.adb.adb.unlock_bootloader_(\*a, **kw)_    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L127-136)

解锁设备的引导加载程序。

- **Note**

这需要与设备进行物理交互。

 

pwnlib.adb.adb.unroot_(\*a, **kw)_    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L127-136)

将adbd重新启动为AID_SHELL。

 

pwnlib.adb.adb.uptime() → float     [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L127-136)

**Returns:**   设备的正常运行时间，以秒为单位

 

pwnlib.adb.adb.wait_for_device_(\*a, **kw)_    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L1388-1395)

等待设备连接。

默认情况下，等待当前选择的设备(通过`context.device`)。要等待特定设备，设置`context.device`。要等待任何设备，清除`context.device`。

**Returns:**

设备`AdbDevice`的实例。

**Examples**

```
>>> device = adb.wait_for_device()
```

 

pwnlib.adb.adb.which_(\*a, **kw)_    [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L127-136)

在设备上检索`$PATH`中的二进制文件的完整路径

**Parameters:**

- **name** (*str*) - 二进制名称
- **all**(*bool*) - 是否返回所有路径，或者只返回第一条路径
- ***a** - adb.process()函数的附加参数
- ***\*kw** - adb.process()函数的附加参数

**Returns:**   路径或路径列表

**Example**

```
>>> adb.which('sh')
'/system/bin/sh'
>>> adb.which('sh', all=True)
['/system/bin/sh']
```

```
>>> adb.which('foobar') is None
True
>>> adb.which('foobar', all=True)
[]
```

 

pwnlib.adb.adb.write_(\*a, **kw)_     [[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/adb/adb.py#L549-555)

根据所提供的内容在设备上创建一个文件。

**Parameters:**

- **path**(*str*) - 设备上文件的路径
- **data**(*str*) - 存储在文件中的内容

**Examples**

```
>>> adb.write('/dev/null', 'data')
>>> adb.write('/data/local/tmp/')
```

该文件仅用于向后兼容
