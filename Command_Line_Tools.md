<h2>命令行工具</h2>
pwntools附带有一些命令行实用程序，封装了某些内部功能。
<h3>pwn</h3>
调用Pwntools的命令行指令。
<pre><span class="go">usage: pwn [-h]</span>
<span class="go">           {asm,checksec,constgrep,cyclic,debug,disasm,disablenx,elfdiff,elfpatch,errno,hex,phd,pwnstrip,scramble,shellcraft,template,unhex,update}</span>
<span class="go">           ...</span></pre>
<pre>-h, --help</pre>
显示帮助信息并退出。
<h3>pwn asm</h3>
<pre><span class="go">usage: pwn asm [-h] [-f {raw,hex,string,elf}] [-o file] [-c context]</span>
<span class="go">               [-v AVOID] [-n] [-z] [-d] [-e ENCODER] [-i INFILE] [-r]</span>
<span class="go">               [line [line ...]]</span></pre>
<pre>line</pre>
需要转换为十六进制的汇编指令。如果没有需要的指令，则使用stdin。
<pre>-h, --help</pre>
显示帮助信息并退出。
<pre>-f {raw,hex,string,elf}, --format {raw,hex,string,elf}</pre>
输出格式（默认输出用于串行端口终端(ttys)的十六进制，否则输出原始数据）。
<pre>-o &lt;flie&gt;, --output&lt;file&gt;</pre>
输出文档（默认为stdout）。
<pre>-c {16,32,64,android,cgc,freebsd,linux,windows,powerpc64,aarch64,sparc64,powerpc,mips64,msp430,thumb,amd64,sparc,alpha,s390,i386,m68k,mips,ia64,cris,vax,avr,arm,little,big,el,le,be,eb}, --context {16,32,64,android,cgc,freebsd,linux,windows,powerpc64,aarch64,sparc64,power}</pre>
设置shellcode运行的环境（系统/架构/字节顺序/系统位数；默认为linux/i386）：

[‘16’, ‘32’, ‘64’, ‘android’, ‘cgc’, ‘freebsd’, ‘linux’, ‘windows’, ‘powerpc64’, ‘aarch64’, ‘sparc64’, ‘powerpc’, ‘mips64’, ‘msp430’, ‘thumb’, ‘amd64’, ‘sparc’, ‘alpha’, ‘s390’, ‘i386’, ‘m68k’, ‘mips’, ‘ia64’, ‘cris’, ‘vax’, ‘avr’, ‘arm’, ‘little’, ‘big’, ‘el’, ‘le’, ‘be’, ‘eb’]
<pre>-v &lt;avoid&gt;, --avoid&lt;avoid&gt;</pre>
编码shellcode的时候跳过使用列出的字节（用十六进制表示；默认为：000a）。
<pre>-n, --newline</pre>
编码shellcode的时候跳过换行符。
<pre>-z, --zero</pre>
编码shellcode的时候跳过空字节（NULL）。
<pre>-d, --debug</pre>
用GDB来调试shellcode。
<pre>-e &lt;encoder&gt;, --encoder &lt;encoder&gt;</pre>
使用指定的编码器。
<pre>-i &lt;infile&gt;, --infile &lt;infile&gt;</pre>
输入指定的文档。
<pre>-r, --run</pre>
运行并输出。
<h3>pwn  checksec</h3>
<pre><span class="go">usage: pwn checksec [-h] [--file [elf [elf ...]]] [elf [elf ...]]</span></pre>
<pre>elf</pre>
需要查看的文件。
<pre>-h, --help</pre>
显示帮助信息并退出。
<pre>--file &lt;elf&gt;</pre>
需要查看的文件（为了与checksec.sh兼容）。
<h3>pwn constgrep</h3>
<pre><span class="go">usage: pwn constgrep [-h] [-e constant] [-i] [-m] [-c arch_or_os]</span>
<span class="go">                     [regex] [constant]</span></pre>
<pre>regex</pre>
用于查找你想要的常量的正则表达式。
<pre>constant</pre>
需要查找的常量。
<pre>-h, --help</pre>
显示帮助信息并退出。
<pre>-e &lt;constant&gt;, --exact &lt;constant&gt;</pre>
使用匹配来查找常量，而不是使用正则表达式。
<pre>-i, --case-insensitive</pre>
不区分大小写查找。
<pre>-m, --mask-mode</pre>
搜索不包含少于给定值的位数的值，而不是搜索特定常量的值。
<pre>-c {16,32,64,android,cgc,freebsd,linux,windows,powerpc64,aarch64,sparc64,powerpc,mips64,msp430,thumb,amd64,sparc,alpha,s390,i386,m68k,mips,ia64,cris,vax,avr,arm,little,big,el,le,be,eb}, --context {16,32,64,android,cgc,freebsd,linux,windows,powerpc64,aarch64,sparc64,power}</pre>
设置运行的环境（系统/架构/字节顺序/系统位数；默认为linux/i386）：

[‘16’, ‘32’, ‘64’, ‘android’, ‘cgc’, ‘freebsd’, ‘linux’, ‘windows’, ‘powerpc64’, ‘aarch64’, ‘sparc64’, ‘powerpc’, ‘mips64’, ‘msp430’, ‘thumb’, ‘amd64’, ‘sparc’, ‘alpha’, ‘s390’, ‘i386’, ‘m68k’, ‘mips’, ‘ia64’, ‘cris’, ‘vax’, ‘avr’, ‘arm’, ‘little’, ‘big’, ‘el’, ‘le’, ‘be’, ‘eb’]
<h3>pwn cyclic</h3>
<pre><span class="go">usage: pwn cyclic [-h] [-a alphabet] [-n length] [-c context]</span>
<span class="go">                  [-l lookup_value]</span>
<span class="go">                  [count]</span></pre>
<pre>count</pre>
要打印的字符数
<pre>-h, --help</pre>
显示帮助信息并退出。
<pre>-a &lt;alphabet&gt;, --alphabet &lt;alphabet&gt;</pre>
用于cyclic pattern的字母表（默认为全部小写字母）。
<pre>-n &lt;length&gt;, --length &lt;length&gt;</pre>
独立子序列的大小（默认为4）
<pre>-c {16,32,64,android,cgc,freebsd,linux,windows,powerpc64,aarch64,sparc64,powerpc,mips64,msp430,thumb,amd64,sparc,alpha,s390,i386,m68k,mips,ia64,cris,vax,avr,arm,little,big,el,le,be,eb}, --context {16,32,64,android,cgc,freebsd,linux,windows,powerpc64,aarch64,sparc64,power}</pre>
<pre>-c {16,32,64,android,cgc,freebsd,linux,windows,powerpc64,aarch64,sparc64,powerpc,mips64,msp430,thumb,amd64,sparc,alpha,s390,i386,m68k,mips,ia64,cris,vax,avr,arm,little,big,el,le,be,eb}, --context {16,32,64,android,cgc,freebsd,linux,windows,powerpc64,aarch64,sparc64,power}</pre>
设置运行的环境（系统/架构/字节顺序/系统位数；默认为linux/i386）：

[‘16’, ‘32’, ‘64’, ‘android’, ‘cgc’, ‘freebsd’, ‘linux’, ‘windows’, ‘powerpc64’, ‘aarch64’, ‘sparc64’, ‘powerpc’, ‘mips64’, ‘msp430’, ‘thumb’, ‘amd64’, ‘sparc’, ‘alpha’, ‘s390’, ‘i386’, ‘m68k’, ‘mips’, ‘ia64’, ‘cris’, ‘vax’, ‘avr’, ‘arm’, ‘little’, ‘big’, ‘el’, ‘le’, ‘be’, ‘eb’]
<pre>-l &lt;lookup_value&gt;, -o &lt;lookup_value&gt;, --offset &lt;lookup_value&gt;, --lookup &lt;lookup_value&gt;</pre>
查找参数而不是打印字母表。
