# pwnlib.util.sh_string — Shell Expansion is Hard

这里的例程用于获取由任意shell完整评估的任意NULL结尾的字节序列。包括所有引号，空格和不可打印字符的所有变形。

## 支持的shell
以下的shell已经被评估:

* Ubuntu (dash/sh)
* MacOS (GNU Bash)
* Zsh
* FreeBSD (sh)
* OpenBSD (sh)
* NetBSD (sh)

## Debian Almquist shell (Dash)
Ubuntu 14.04和16.04使用Dash shell，而/bin/sh只是/bin/dash的符号链接。 功能集在调用"sh"而不是"dash"时是有所不同的，而我们专注于"bin/sh"的实现。

在[Ubuntu Man Pages](http://manpages.ubuntu.com/manpages/trusty/man1/dash.1.html)中，除了单引号外的每一个字符,可以用单引号括起来，而且可以用反斜杠来转义未被括起的单引号。

```
Quoting
  Quoting is used to remove the special meaning of certain characters or
  words to the shell, such as operators, whitespace, or keywords.  There
  are three types of quoting: matched single quotes, matched double quotes,
  and backslash.

Backslash
  A backslash preserves the literal meaning of the following character,
  with the exception of ⟨newline⟩.  A backslash preceding a ⟨newline⟩ is
  treated as a line continuation.

Single Quotes
  Enclosing characters in single quotes preserves the literal meaning of
  all the characters (except single quotes, making it impossible to put
  single-quotes in a single-quoted string).

Double Quotes
  Enclosing characters within double quotes preserves the literal meaning
  of all characters except dollarsign ($), backquote (`), and backslash
  (\).  The backslash inside double quotes is historically weird, and
  serves to quote only the following characters:
        $ ` " \ <newline>.
  Otherwise it remains literal.
```

## GNU Bash

Bash shell在很多系统上是默认的，虽然通常不是默认系统shell（即系统调用通常不会调用）。

这说明，Bash shell的表明这问题将会被解决。

从[GNU Bash Manual](https://www.gnu.org/software/bash/manual/bash.html#Quoting)中，除了单引号外的每一个字符,可以用单引号括起来，而且可以用反斜杠来转义未被括起的单引号。

```
3.1.2.1 Escape Character

A non-quoted backslash ‘\’ is the Bash escape character. It preserves the
literal value of the next character that follows, with the exception of
newline. If a ``\newline`` pair appears, and the backslash itself is not
quoted, the ``\newline`` is treated as a line continuation (that is, it
is removed from the input stream and effectively ignored).

3.1.2.2 Single Quotes

Enclosing characters in single quotes (‘'’) preserves the literal value of
each character within the quotes. A single quote may not occur between single
uotes, even when preceded by a backslash.

3.1.2.3 Double Quotes

Enclosing characters in double quotes (‘"’) preserves the literal value of a
ll characters within the quotes, with the exception of ‘$’, ‘`’, ‘\’, and,
when history expansion is enabled, ‘!’. The characters ‘$’ and ‘`’ retain their
pecial meaning within double quotes (see Shell Expansions). The backslash retains
its special meaning only when followed by one of the following characters:
‘$’, ‘`’, ‘"’, ‘\’, or newline. Within double quotes, backslashes that are
followed by one of these characters are removed. Backslashes preceding
characters without a special meaning are left unmodified. A double quote may
be quoted within double quotes by preceding it with a backslash. If enabled,
history expansion will be performed unless an ‘!’ appearing in double quotes
is escaped using a backslash. The backslash preceding the ‘!’ is not removed.

The special parameters ‘*’ and ‘@’ have special meaning when in double quotes
see Shell Parameter Expansion).
```

## Z Shell

Z shell也是一个比较常见的用户shell，尽管它通常不是系统默认shell。

在[Z Shell Manual](http://zsh.sourceforge.net/Doc/Release/Shell-Grammar.html#Quoting)中，除了单引号外的每一个字符,可以用单引号括起来，而且可以用反斜杠来转义未被括起的单引号。


```
A character may be quoted (that is, made to stand for itself) by preceding
it with a ‘\’. ‘\’ followed by a newline is ignored.

A string enclosed between ‘$'’ and ‘'’ is processed the same way as the
string arguments of the print builtin, and the resulting string is considered
o be entirely quoted. A literal ‘'’ character can be included in the string
by using the ‘\'’ escape.

All characters enclosed between a pair of single quotes ('') that is not
preceded by a ‘$’ are quoted. A single quote cannot appear within single
quotes unless the option RC_QUOTES is set, in which case a pair of single
quotes are turned into a single quote. For example,

print ''''
outputs nothing apart from a newline if RC_QUOTES is not set, but one single
quote if it is set.

Inside double quotes (""), parameter and command substitution occur, and
‘\’ quotes the characters ‘\’, ‘`’, ‘"’, and ‘$’.
```

## FreeBSD Shell

完整性包括了与FreeBSD shell的兼容性。

在[FreeBSD man pages](https://www.freebsd.org/cgi/man.cgi?query=sh)中, 除了单引号外的每一个字符,可以用单引号括起来，而且可以用反斜杠来转义未被括起的单引号。

```
Quoting is used to remove the special meaning of certain characters or
words to the shell, such as operators, whitespace, keywords, or alias
names.

There are four types of quoting: matched single quotes, dollar-single
quotes, matched double quotes, and backslash.

Single Quotes
    Enclosing characters in single quotes preserves the literal mean-
    ing of all the characters (except single quotes, making it impos-
    sible to put single-quotes in a single-quoted string).

Dollar-Single Quotes
    Enclosing characters between $' and ' preserves the literal mean-
    ing of all characters except backslashes and single quotes.  A
    backslash introduces a C-style escape sequence:

    ...

Double Quotes
    Enclosing characters within double quotes preserves the literal
    meaning of all characters except dollar sign (`$'), backquote
    (``'), and backslash (`\').  The backslash inside double quotes
    is historically weird.  It remains literal unless it precedes the
    following characters, which it serves to quote:

      $     `     "     \     \n

Backslash
    A backslash preserves the literal meaning of the following char-
    acter, with the exception of the newline character (`\n').  A
    backslash preceding a newline is treated as a line continuation.
```

## OpenBSD Shell

在[OpenBSD Man Pages](http://man.openbsd.org/sh#SHELL_GRAMMAR)中，除了单引号外的每一个字符,可以用单引号括起来，而且可以用反斜杠来转义未被括起的单引号。

```
A backslash (\) can be used to quote any character except a newline.
If a newline follows a backslash the shell removes them both, effectively
making the following line part of the current one.

A group of characters can be enclosed within single quotes (') to quote
every character within the quotes.

A group of characters can be enclosed within double quotes (") to quote
every character within the quotes except a backquote (`) or a dollar
sign ($), both of which retain their special meaning. A backslash (\)
within double quotes retains its special meaning, but only when followed
by a backquote, dollar sign, double quote, or another backslash.
An at sign (@) within double quotes has a special meaning
(see SPECIAL PARAMETERS, below).
```

## NetBSD Shell

NetBSD shell的文档和Dash的文档相同

## Android Shells

Android已经通过了一些shell。

* Mksh是一个Korn shell，与Toolbox的5.0和更早版本一起使用。
* Toybox也是源于Almquist Shell的6.0和更高版本。

值得注意的是，Toolbox实现不符合POSIX标准，因为缺少内置"printf"（如Android 5.0仿真器图像）。

## Toybox Shell

Android 6.0 (可能其他版本也相同) 使用基于`toybox`的shell。

虽然不包含内建`printf`，`toybox`自身包含符合POSIX标准的`printf`二进制文件。

Ash shell应当与`dash`相兼容。 

## BusyBox Shell
[BusyBox’s Wikipedia page](https://en.wikipedia.org/wiki/BusyBox#Features)声明使用ash标准的shell， 因此应该也与`dash`相兼容。

### `pwnlib.util.sh_string.sh_command_with(`*`f, arg0, ..., argN`*`) → command` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/sh_string.py#L476-513)

当`f`是函数时返回通过评估`f(new_arg0, …, new_argN) `生成的命令，否则返回`f % (new_arg0, …, new_argN)`。

如果参数时纯粹的字母数字，那么它们只是简单的传递给函数。如果它们是简单的空格，那么它们将会转义并传递给函数。

如果参数包含尾换行符，那么因为posix shell的限制而难以使用。这种情况下，`f`的输出前会加上一些代码来创建变量。 


#### 例

```shell
>>> sh_command_with(lambda: "echo hello")
'echo hello'
>>> sh_command_with(lambda x: "echo " + x, "hello")
'echo hello'
>>> sh_command_with(lambda x: "/bin/echo " + x, "\\x01")
"/bin/echo '\\x01'"
>>> sh_command_with(lambda x: "/bin/echo " + x, "\\x01\\n")
"/bin/echo '\\x01\\n'"
>>> sh_command_with("/bin/echo %s", "\\x01\\n")
"/bin/echo '\\x01\\n'"
```

### `pwnlib.util.sh_string.sh_prepare(`*`variables, export=False`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/sh_string.py#L427-474)

输出符合posix标准的shell命令，该命令将字典指定的数据放入环境中。

假设自定中的键是有不需要转义的效变量名称。

参数:	
* variables (*dict*) – 要设置的变量。
* export (*bool*) – 变量应导出或仅保存在shell环境中。
* output (*str*) – 有效的设置给定变量的posix shell命令。

假定var是shell中变量的有效名称。

#### 例

```shell
>>> sh_prepare({'X': 'foobar'})
'X=foobar'
>>> r = sh_prepare({'X': 'foobar', 'Y': 'cookies'})
>>> r == 'X=foobar;Y=cookies' or r == 'Y=cookies;X=foobar'
True
>>> sh_prepare({'X': 'foo bar'})
"X='foo bar'"
>>> sh_prepare({'X': "foo'bar"})
"X='foo'\\''bar'"
>>> sh_prepare({'X': "foo\\\\bar"})
"X='foo\\\\bar'"
>>> sh_prepare({'X': "foo\\\\'bar"})
"X='foo\\\\'\\''bar'"
>>> sh_prepare({'X': "foo\\x01'bar"})
"X='foo\\x01'\\''bar'"
>>> sh_prepare({'X': "foo\\x01'bar"}, export = True)
"export X='foo\\x01'\\''bar'"
>>> sh_prepare({'X': "foo\\x01'bar\\n"})
"X='foo\\x01'\\''bar\\n'"
>>> sh_prepare({'X': "foo\\x01'bar\\n"})
"X='foo\\x01'\\''bar\\n'"
>>> sh_prepare({'X': "foo\\x01'bar\\n"}, export = True)
"export X='foo\\x01'\\''bar\\n'"
```

### `wnlib.util.sh_string.sh_string(`*`s`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/sh_string.py#L359-425)

输出`/bin/sh`可以理解的格式的字符串。

如果字符串不包含任何不良字符，则只会简单的返回，可能带引号。如果包含错误字符，它将以大多数系统兼容的方式转义字符串。

>Warning:这与shell的内置的“echo”不一样。它完全按照预期的设置环境变量和参数。除非它是shell内置echo。

>参数:
s(*str*): 转义的字符串。

#### 例

```shell
>>> sh_string('foobar')
'foobar'
>>> sh_string('foo bar')
"'foo bar'"
>>> sh_string("foo'bar")
"'foo'\\''bar'"
>>> sh_string("foo\\\\bar")
"'foo\\\\bar'"
>>> sh_string("foo\\\\'bar")
"'foo\\\\'\\''bar'"
>>> sh_string("foo\\x01'bar")
"'foo\\x01'\\''bar'"
```

### `pwnlib.util.sh_string.test(`*`original`*`)` [源码](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/util/sh_string.py#L279-341)

测试shell解释字符串时的输出。

```shell
>>> test('foobar')
>>> test('foo bar')
>>> test('foo bar\n')
>>> test("foo'bar")
>>> test("foo\\\\bar")
>>> test("foo\\\\'bar")
>>> test("foo\\x01'bar")
>>> test('\n')
>>> test('\xff')
>>> test(os.urandom(16 * 1024).replace('\x00', ''))
```