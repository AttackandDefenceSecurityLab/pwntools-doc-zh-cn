# 命令行工具

pwntools附带有一些命令行实用程序，封装了某些内部功能。

## pwn

调用Pwntools的命令行指令。

```shell
使用方式: pwn [-h]
{asm,checksec,constgrep,cyclic,debug,disasm,disablenx,elfdiff,elfpatch,errno,hex,phd,pwnstrip,scramble,shellcraft,template,unhex,update}
             ...
```

`-h, --help`

显示帮助信息并退出。

## pwn asm

```shell
使用方式: pwn asm [-h] [-f {raw,hex,string,elf}] [-o file] [-c context]
                 [-v AVOID] [-n] [-z] [-d] [-e ENCODER] [-i INFILE] [-r]
                 [line [line ...]]
```

`line`

需要转换为十六进制的汇编指令。如果没有填入的指令，则从stdin读取。

`-h, --help`

显示帮助信息并退出。

`-f {raw,hex,string,elf}, --format {raw,hex,string,elf}`

输出格式（默认输出十六进制到串行端口，除此之外输出原始格式）。

`-o <flie>, --output<file>`

输出到指定文件（默认输出到stdout）。

```shell
-c {16,32,64,android,cgc,freebsd,linux,windows,powerpc64,aarch64,sparc64,powerpc,mips64,msp430 thumb,amd64,sparc,alpha,s390,i386,m68k,mips,ia64,cris,vax,avr,arm,little,big,el,le,be,eb}, --context {16,32,64,android,cgc,freebsd,linux,windows,powerpc64,aarch64,sparc64,power}
```

设置shellcode运行的环境（系统/处理器架构/字节序/位宽；默认为linux/i386）：
[‘16’, ‘32’, ‘64’, ‘android’, ‘cgc’, ‘freebsd’, ‘linux’, ‘windows’, ‘powerpc64’, ‘aarch64’, ‘sparc64’, ‘powerpc’, ‘mips64’, ‘msp430’, ‘thumb’, ‘amd64’, ‘sparc’, ‘alpha’, ‘s390’, ‘i386’, ‘m68k’, ‘mips’, ‘ia64’, ‘cris’, ‘vax’, ‘avr’, ‘arm’, ‘little’, ‘big’, ‘el’, ‘le’, ‘be’, ‘eb’]

`-v <avoid>, --avoid<avoid>`

编码shellcode的时候跳过使用列出的字节（用十六进制表示；默认为：000a）。

`-n, --newline`

编码shellcode的时候跳过换行符。

`-z, --zero`

编码shellcode的时候跳过空字节（NULL）。

`-d, --debug`

用GDB来调试shellcode。

`-e <encoder>, --encoder <encoder>`

使用指定的编码器。

`-i <infile>, --infile <infile>`

输入指定的文档。

`-r, --run`

运行并输出。

## pwn  checksec

```shell
使用方式: pwn checksec [-h] [--file [elf [elf ...]]] [elf [elf ...]]
```
`elf`

要查看的文件。

`-h, --help`

显示帮助信息并退出。

`--file <elf>`

要查看的文件（为了与checksec.sh兼容）。

## pwn constgrep

```shell
使用方式: pwn constgrep [-h] [-e constant] [-i] [-m] [-c arch_or_os] [regex] [constant]
```

`regex`

用于查找你想要的常量的正则表达式。

`constant`

需要查找的常量。

`-h, --help`

显示帮助信息并退出。


`-e <constant>, --exact <constant>`

使用匹配来查找常量，而不是使用正则表达式。

`-i, --case-insensitive`

不区分大小写查找。

`-m, --mask-mode`

搜索不包含少于给定值的位数的值，而不是搜索特定位数的值。

```shell
-c {16,32,64,android,cgc,freebsd,linux,windows,powerpc64,aarch64,sparc64,powerpc,mips64,msp430 thumb,amd64,sparc,alpha,s390,i386,m68k,mips,ia64,cris,vax,avr,arm,little,big,el,le,be,eb}, --context {16,32,64,android,cgc,freebsd,linux,windows,powerpc64,aarch64,sparc64,power}
```

设置shellcode运行的环境（系统/处理器架构/字节序/位宽；默认为linux/i386）：
[‘16’, ‘32’, ‘64’, ‘android’, ‘cgc’, ‘freebsd’, ‘linux’, ‘windows’, ‘powerpc64’, ‘aarch64’, ‘sparc64’, ‘powerpc’, ‘mips64’, ‘msp430’, ‘thumb’, ‘amd64’, ‘sparc’, ‘alpha’, ‘s390’, ‘i386’, ‘m68k’, ‘mips’, ‘ia64’, ‘cris’, ‘vax’, ‘avr’, ‘arm’, ‘little’, ‘big’, ‘el’, ‘le’, ‘be’, ‘eb’]

## pwn cyclic

```shell
使用方式: pwn cyclic [-h] [-a alphabet] [-n length] [-c context]
                    [-l lookup_value]
                    [count]
```

`count`

要打印的字符数量。

`-h, --help`

显示帮助信息并退出。

`-a <alphabet>, --alphabet <alphabet>`

用于cyclic pattern的字母（默认为全部小写字母）。

`-n <length>, --length <length>`

独立子序列的大小（默认为4）。

```shell
-c {16,32,64,android,cgc,freebsd,linux,windows,powerpc64,aarch64,sparc64,powerpc,mips64,msp430 thumb,amd64,sparc,alpha,s390,i386,m68k,mips,ia64,cris,vax,avr,arm,little,big,el,le,be,eb}, --context {16,32,64,android,cgc,freebsd,linux,windows,powerpc64,aarch64,sparc64,power}
```

设置shellcode运行的环境（系统/处理器架构/字节序/位宽；默认为linux/i386）：
[‘16’, ‘32’, ‘64’, ‘android’, ‘cgc’, ‘freebsd’, ‘linux’, ‘windows’, ‘powerpc64’, ‘aarch64’, ‘sparc64’, ‘powerpc’, ‘mips64’, ‘msp430’, ‘thumb’, ‘amd64’, ‘sparc’, ‘alpha’, ‘s390’, ‘i386’, ‘m68k’, ‘mips’, ‘ia64’, ‘cris’, ‘vax’, ‘avr’, ‘arm’, ‘little’, ‘big’, ‘el’, ‘le’, ‘be’, ‘eb’]

`-l <lookup_value>, -o <lookup_value>, --offset <lookup_value>, --lookup <lookup_value>`

查找参数而不打印字母。

## pwn debug

```shell
使用方式: pwn debug [-h] [-x GDBSCRIPT] [--pid PID] [-c context]
                 [--exec EXECUTABLE] [--process PROCESS_NAME]
                 [--sysroot SYSROOT]
```

`-h, --help`

显示帮助信息并退出。

`-x <gdbscript>`

执行该文件中的GDB命令。

`--pid <pid>`

要跟踪的程序的pid。

```shell
-c {16,32,64,android,cgc,freebsd,linux,windows,powerpc64,aarch64,sparc64,powerpc,mips64,msp430 thumb,amd64,sparc,alpha,s390,i386,m68k,mips,ia64,cris,vax,avr,arm,little,big,el,le,be,eb}, --context {16,32,64,android,cgc,freebsd,linux,windows,powerpc64,aarch64,sparc64,power}
```

设置shellcode运行的环境（系统/架构/字节顺序/系统位数；默认为linux/i386）：
[‘16’, ‘32’, ‘64’, ‘android’, ‘cgc’, ‘freebsd’, ‘linux’, ‘windows’, ‘powerpc64’, ‘aarch64’, ‘sparc64’, ‘powerpc’, ‘mips64’, ‘msp430’, ‘thumb’, ‘amd64’, ‘sparc’, ‘alpha’, ‘s390’, ‘i386’, ‘m68k’, ‘mips’, ‘ia64’, ‘cris’, ‘vax’, ‘avr’, ‘arm’, ‘little’, ‘big’, ‘el’, ‘le’, ‘be’, ‘eb’]

`--exec <executable>`

要debug的文件。

`--process <process_name>`

要跟踪的程序的名称（例如："bash"）。

`--sysroot <sysroot>`

GDB根目录。

## pwn disablenx

```shell
使用方式: pwn disablenx [-h] elf [elf ...]
```

`elf`

要查看的文件。

`-h, --help`

显示帮助信息并退出。

## pwn disasm

```shell
    使用方式: pwn disasm [-h] [-c arch_or_os] [-a address] [--color] [--no-color]
                      [hex [hex ...]]
```

`hex`

需要转换的十六进制字符串，如果没有输入则从非十六进制的stdin读取。

`-h, --help`

显示帮助信息并退出。

```shell
-c {16,32,64,android,cgc,freebsd,linux,windows,powerpc64,aarch64,sparc64,powerpc,mips64,msp430 thumb,amd64,sparc,alpha,s390,i386,m68k,mips,ia64,cris,vax,avr,arm,little,big,el,le,be,eb}, --context {16,32,64,android,cgc,freebsd,linux,windows,powerpc64,aarch64,sparc64,power}
```

设置shellcode运行的环境（系统/处理器架构/字节序/位宽；默认为linux/i386）：
[‘16’, ‘32’, ‘64’, ‘android’, ‘cgc’, ‘freebsd’, ‘linux’, ‘windows’, ‘powerpc64’, ‘aarch64’, ‘sparc64’, ‘powerpc’, ‘mips64’, ‘msp430’, ‘thumb’, ‘amd64’, ‘sparc’, ‘alpha’, ‘s390’, ‘i386’, ‘m68k’, ‘mips’, ‘ia64’, ‘cris’, ‘vax’, ‘avr’, ‘arm’, ‘little’, ‘big’, ‘el’, ‘le’, ‘be’, ‘eb’]

`-a <address>, --address <address>`

文件的根目录。

`--color`

输出内容着色。

`--no-color`

输出内容不着色。

## pwn elfdiff 

```shell
使用方式: pwn elfdiff [-h] a b
```

`a`

（原文缺失）

`b`

（原文缺失）

`-h, --help`

显示帮助信息并退出。

## pwn elfpatch

```shell
使用方式: pwn elfpatch [-h]
```

`-h, --help`

显示帮助信息并退出。

## pwn errno

```shell
使用方式: pwn errno [-h] error
```

`error`

错误时的信息或者值。

`-h, --help`

显示帮助信息并退出。

## pwn hex

```shell
使用方式: pwn hex [-h] [data [data ...]]
```

`data`

用于转换为十六进制的数据。

`-h, --help`

显示帮助信息并退出。

## pwn phd

```shell
使用方式: pwn phd [-h] [-w WIDTH] [-l [HIGHLIGHT [HIGHLIGHT ...]]] [-s SKIP]
                 [-c COUNT] [-o OFFSET] [--color [{always,never,auto}]]
                 [file]
```

`file`

要转换为十六进制的文件，如果文件丢失则从stdin读取。

`-h, --help`

显示帮助信息并退出。

`-w <width>, --width <width>`

每行的字节数。

`-l <highlight>, --highlight <highlight>`

代码高亮。

`-s <skip>, --skip`

跳过输入的初始字节。

`-c <count>, --count <count>`

只输出指定数量的的字节。

`-o <offset>, --offset <offset>`

该地址开始的偏移地址。

`--color {always,never,auto}`

输出内容着色，当设定为`auto` 时，在终端输出时着色。默认为`auto`。

##pwn pwnstrip

```shell
使用方式: pwn pwnstrip [-h] [-b] [-p FUNCTION] [-o OUTPUT] file
```

`file`

（原文缺失）

`-h ,--help`

显示帮助信息并退出。

`-b, --build-id`

连接的二进制文件版本号。

`-p <function>, --patch <function>`

修复功能。

`-o <output>, ---output <output>`

（原文缺失）

## pwn scramble

```shell
使用方式: pwn scramble [-h] [-f {raw,hex,string,elf}] [-o file] [-c context] [-p]
                      [-v AVOID] [-n] [-z] [-d]
```

`-h ,--help`

显示帮助信息并退出。

`-f {raw,hex,string,elf}, --format {raw,hex,string,elf}`

输出格式（默认输出十六进制到串行端口，除此之外输出原始格式）。

`-o <file>, --output <file>`

输出到指定文件（默认输出到stdout）。

```shell
-c {16,32,64,android,cgc,freebsd,linux,windows,powerpc64,aarch64,sparc64,powerpc,mips64,msp430 thumb,amd64,sparc,alpha,s390,i386,m68k,mips,ia64,cris,vax,avr,arm,little,big,el,le,be,eb}, --context {16,32,64,android,cgc,freebsd,linux,windows,powerpc64,aarch64,sparc64,power}
```

设置shellcode运行的环境（系统/处理器架构/字节序/位宽；默认为linux/i386）：
[‘16’, ‘32’, ‘64’, ‘android’, ‘cgc’, ‘freebsd’, ‘linux’, ‘windows’, ‘powerpc64’, ‘aarch64’, ‘sparc64’, ‘powerpc’, ‘mips64’, ‘msp430’, ‘thumb’, ‘amd64’, ‘sparc’, ‘alpha’, ‘s390’, ‘i386’, ‘m68k’, ‘mips’, ‘ia64’, ‘cris’, ‘vax’, ‘avr’, ‘arm’, ‘little’, ‘big’, ‘el’, ‘le’, ‘be’, ‘eb’]

`-p ,--alphanumeric`

使用alphanumeric编码器编码shellcode。

`-v <avoid>, --avoid<avoid>`

编码shellcode的时候跳过使用列出的字节（用十六进制表示；默认为：000a）。

`-n, --newline`

编码shellcode的时候跳过换行符。

`-z, --zero`

编码shellcode的时候跳过空字节（NULL）。

`-d, --debug`

用GDB来调试shellcode。

## pwn shellcraft

```shell
使用方式: pwn shellcraft [-h] [-?] [-o file] [-f format] [-d] [-b] [-a]
                        [-v AVOID] [-n] [-z] [-r] [--color] [--no-color]
                        [--syscalls] [--address ADDRESS] [-l] [-s]
                        [shellcode] [arg [arg ...]]
```

`shellcode`

你想要得到的shellcode

`arg`

提供给shellcode的实参

`-h, --help`

显示帮助信息并退出

`-o <flie>, --output<file>`

输出到指定文件（默认输出到stdout）。

```shell
-f {r,raw,s,str,string,c,h,hex,a,asm,assembly,p,i,hexii,e,elf,d,escaped,default}, --format {r,raw,s,str,string,c,h,hex,a,asm,assembly,p,i,hexii,e,elf,d,escaped,default}
```

输出格式（默认为16进制）：{e}lf, {r}aw, {s}tring, {c}-style array, {h}ex string, hex{i}i, {a}ssembly code, {p}reprocssed code, escape{d} hex string

`-d, --debug`

使用GDB调试。

`-b, --before`

在代码前插入调试陷阱。

`-a, --after`

在代码后插入调试陷阱。

`-v <avoid>, --avoid<avoid>`

编码shellcode的时候跳过使用列出的字节（用十六进制表示；默认为：000a）。

`-n, --newline`

编码shellcode的时候跳过换行符。

`-z, --zero`

编码shellcode的时候跳过空字节（NULL）。

`-r, --run`

运行并输出。

`--color`

输出内容着色。

`--no-color`

输出内容不着色。

`--syscalls`

列出系统调用

`address <address>`

载入地址

`-l, --list`

列出可用的shellcode，可选择使用过滤器。

`-s, --shared`

生成的ELF文件是可共享的。

## pwn tmplate

```shell
使用方式: pwn template [-h] [--host HOST] [--port PORT] [--user USER]
                      [--pass PASSWORD] [--path PATH] [--quiet]
                      [exe]
```

`exe`

文件绝对路径

`-h, --help`

显示帮助信息并退出

`--host <host>`

远程控制/ssh服务

`--port <port>`

远程端口/ssh端口

`--user <user>`

ssh用户名

`--pass <password>`

ssh密码

`--path <path>`

ssh服务器上的远程文件路径。

`--quiet`

更详细的模板注释。

## pwn unhex

```shell
使用方式: pwn unhex [-h] [hex [hex ...]]
```

`hex`

需要解码的的十六进制字节。

`-h, --help`

显示帮助信息并退出。

## pwn update

`-h, --help`

显示帮助信息并退出。

`install`

自动安装更新。

`pre`

查看预发行版。
