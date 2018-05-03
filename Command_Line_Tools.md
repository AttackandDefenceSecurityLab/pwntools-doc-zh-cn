## 命令行工具

pwntools附带有一些命令行实用程序，封装了某些内部功能。

### pwn

调用Pwntools的命令行指令。

    usage: pwn [-h]
           {asm,checksec,constgrep,cyclic,debug,disasm,disablenx,elfdiff,elfpatch,errno,hex,phd,pwnstrip,scramble,shellcraft,template,unhex,update}
           ...

```-h, --help```

显示帮助信息并退出。

### pwn asm

    usage: pwn asm [-h] [-f {raw,hex,string,elf}] [-o file] [-c context]
           [-v AVOID] [-n] [-z] [-d] [-e ENCODER] [-i INFILE] [-r]
           [line [line ...]]

```line```

需要转换为十六进制的汇编指令。如果没有需要的指令，则使用stdin。

```-h, --help```

显示帮助信息并退出。

```-f {raw,hex,string,elf}, --format {raw,hex,string,elf}```

输出格式（默认输出用于串行端口终端(ttys)的十六进制，否则输出原始数据）。

```-o <flie>, --output<file>```

输出文档（默认为stdout）。

    -c {16,32,64,android,cgc,freebsd,linux,windows,powerpc64,aarch64,sparc64,powerpc,mips64,msp430,thumb,amd64,sparc,alpha,s390,i386,m68k,mips,ia64,cris,vax,avr,arm,little,big,el,le,be,eb}, --context {16,32,64,android,cgc,freebsd,linux,windows,powerpc64,aarch64,sparc64,power}

设置shellcode运行的环境（系统/架构/字节顺序/系统位数；默认为linux/i386）：
[‘16’, ‘32’, ‘64’, ‘android’, ‘cgc’, ‘freebsd’, ‘linux’, ‘windows’, ‘powerpc64’, ‘aarch64’, ‘sparc64’, ‘powerpc’, ‘mips64’, ‘msp430’, ‘thumb’, ‘amd64’, ‘sparc’, ‘alpha’, ‘s390’, ‘i386’, ‘m68k’, ‘mips’, ‘ia64’, ‘cris’, ‘vax’, ‘avr’, ‘arm’, ‘little’, ‘big’, ‘el’, ‘le’, ‘be’, ‘eb’]

```-v <avoid>, --avoid<avoid>```

编码shellcode的时候跳过使用列出的字节（用十六进制表示；默认为：000a）。

```-n, --newline```

编码shellcode的时候跳过换行符。

```-z, --zero```

编码shellcode的时候跳过空字节（NULL）。

```-d, --debug```

用GDB来调试shellcode。

```-e <encoder>, --encoder <encoder>```

使用指定的编码器。

```-i <infile>, --infile <infile>```

输入指定的文档。

```-r, --run```

运行并输出。
### pwn  checksec

    usage: pwn checksec [-h] [--file [elf [elf ...]]] [elf [elf ...]]

```elf```

需要查看的文件。

```-h, --help```

显示帮助信息并退出。

```--file <elf>```

需要查看的文件（为了与checksec.sh兼容）。

### pwn constgrep

    usage: pwn constgrep [-h] [-e constant] [-i] [-m] [-c arch_or_os]
           [regex] [constant]

```regex```

用于查找你想要的常量的正则表达式。

```constant```

需要查找的常量。

```-h, --help```
显示帮助信息并退出。


```-e <constant>, --exact <constant>```

使用匹配来查找常量，而不是使用正则表达式。

```-i, --case-insensitive```

不区分大小写查找。

```-m, --mask-mode```

搜索不包含少于给定值的位数的值，而不是搜索特定常量的值。

    -c {16,32,64,android,cgc,freebsd,linux,windows,powerpc64,aarch64,sparc64,powerpc,mips64,msp430,thumb,amd64,sparc,alpha,s390,i386,m68k,mips,ia64,cris,vax,avr,arm,little,big,el,le,be,eb}, --context {16,32,64,android,cgc,freebsd,linux,windows,powerpc64,aarch64,sparc64,power}

设置运行的环境（系统/架构/字节顺序/系统位数；默认为linux/i386）：
[‘16’, ‘32’, ‘64’, ‘android’, ‘cgc’, ‘freebsd’, ‘linux’, ‘windows’, ‘powerpc64’, ‘aarch64’, ‘sparc64’, ‘powerpc’, ‘mips64’, ‘msp430’, ‘thumb’, ‘amd64’, ‘sparc’, ‘alpha’, ‘s390’, ‘i386’, ‘m68k’, ‘mips’, ‘ia64’, ‘cris’, ‘vax’, ‘avr’, ‘arm’, ‘little’, ‘big’, ‘el’, ‘le’, ‘be’, ‘eb’]

### pwn cyclic\

    usage: pwn cyclic [-h] [-a alphabet] [-n length] [-c context]
           [-l lookup_value]
           [count]

```count```

要打印的字符数

```-h, --help```

显示帮助信息并退出。

```-a <alphabet>, --alphabet <alphabet>```

用于cyclic pattern的字母表（默认为全部小写字母）。

```-n <length>, --length <length>```

独立子序列的大小（默认为4）

    -c {16,32,64,android,cgc,freebsd,linux,windows,powerpc64,aarch64,sparc64,powerpc,mips64,msp430,thumb,amd64,sparc,alpha,s390,i386,m68k,mips,ia64,cris,vax,avr,arm,little,big,el,le,be,eb}, --context {16,32,64,android,cgc,freebsd,linux,windows,powerpc64,aarch64,sparc64,power}

设置运行的环境（系统/架构/字节顺序/系统位数；默认为linux/i386）：
[‘16’, ‘32’, ‘64’, ‘android’, ‘cgc’, ‘freebsd’, ‘linux’, ‘windows’, ‘powerpc64’, ‘aarch64’, ‘sparc64’, ‘powerpc’, ‘mips64’, ‘msp430’, ‘thumb’, ‘amd64’, ‘sparc’, ‘alpha’, ‘s390’, ‘i386’, ‘m68k’, ‘mips’, ‘ia64’, ‘cris’, ‘vax’, ‘avr’, ‘arm’, ‘little’, ‘big’, ‘el’, ‘le’, ‘be’, ‘eb’]

```-l <lookup_value>, -o <lookup_value>, --offset <lookup_value>, --lookup <lookup_value>```

查找参数而不是打印字母表。
