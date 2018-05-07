
# 关于pwntools
无论您是使用它来编写漏洞，还是作为其他软件项目的一部分，pwntool都能胜任。
历史上pwntools曾被用作编写漏洞利用的一种领域专用语言，在之前的pwntools中，简单地执行`from pwn import *`就能起到各种作用
当重新设计pwntools for 2.0时，我们注意到了两个相反的目标：
- 我们希望有一个“通用”的Python模块结构，以便其他人能够快速熟悉pwntools。
- 我们希望有更多的功能，尤其是通过将终端置于原始模式。
为了达成以上两点，我们决定制作两个不同的模块。`pwnlib`将是我们完美的、简洁的python模块，同时`pwn`可以在进行CTF比赛时使用

# `pwn` —— 为CTF比赛优化的工具箱
如上所述，我们还希望能够在默认情况下获得更多的额外功能。这是这个模块的目的。它执行以下操作：
- 从顶级`pwnlib`导入所有内容以及大量子模块的功能。 这意味着，如果你键入`import pwn`或`from pwn import *`，你将可以访问编写漏洞利用所需的所有东西。
- 调用`pwnlib.term.init()`来让你的终端进入原始模式，使其外观改变并实现功能
- 将`pwnlib.context.log_level`设置为"Info"
- 尝试解析sys.argv中的一些值，并解析它成功解析的值。

# `pwnlib` —— 通用的Python库
这个模块包含我们的“干净的”python代码。通常，我们不认为导入pwnlib或任何子模块应该有任何显著的额外功能（除了例如缓存）。
大多数情况下，您只会获得您导入的模块。例如，当你键入`import pwnlib.util`时，您无法访问`pwnlib.util.packing`
虽然有一些例外（如pwnlib.shellcraft），它并不完全符合简单和干净的目标，但仍可以导入，而不会产生隐式的副作用。
