## `pwnlib.shellcraft`— Shellcode 的生成

有关shellcode的模块。

该模块包含用于生成shellcode的函数。

首先根据（处理器的）体系结构去组织shellcode，之后再交由操作系统处理。

### Submodules

- `pwnlib.shellcraft.aarch64` — Shellcode for AArch64
  - [`pwnlib.shellcraft.aarch64`](https://docs.pwntools.com/en/stable/shellcraft/aarch64.html#module-pwnlib.shellcraft.aarch64)
  - [`pwnlib.shellcraft.aarch64.linux`](https://docs.pwntools.com/en/stable/shellcraft/aarch64.html#module-pwnlib.shellcraft.aarch64.linux)
- `pwnlib.shellcraft.amd64` — Shellcode for AMD64
  - [`pwnlib.shellcraft.amd64`](https://docs.pwntools.com/en/stable/shellcraft/amd64.html#module-pwnlib.shellcraft.amd64)
  - [`pwnlib.shellcraft.amd64.linux`](https://docs.pwntools.com/en/stable/shellcraft/amd64.html#module-pwnlib.shellcraft.amd64.linux)
- `pwnlib.shellcraft.arm` — Shellcode for ARM
  - [`pwnlib.shellcraft.arm`](https://docs.pwntools.com/en/stable/shellcraft/arm.html#module-pwnlib.shellcraft.arm)
  - [`pwnlib.shellcraft.arm.linux`](https://docs.pwntools.com/en/stable/shellcraft/arm.html#module-pwnlib.shellcraft.arm.linux)
- [`pwnlib.shellcraft.common` — Shellcode common to all architecture](https://docs.pwntools.com/en/stable/shellcraft/common.html)
- `pwnlib.shellcraft.i386` — Shellcode for Intel 80386
  - [`pwnlib.shellcraft.i386`](https://docs.pwntools.com/en/stable/shellcraft/i386.html#module-pwnlib.shellcraft.i386)
  - [`pwnlib.shellcraft.i386.linux`](https://docs.pwntools.com/en/stable/shellcraft/i386.html#module-pwnlib.shellcraft.i386.linux)
  - [`pwnlib.shellcraft.i386.freebsd`](https://docs.pwntools.com/en/stable/shellcraft/i386.html#module-pwnlib.shellcraft.i386.freebsd)
- `pwnlib.shellcraft.mips` — Shellcode for MIPS
  - [`pwnlib.shellcraft.mips`](https://docs.pwntools.com/en/stable/shellcraft/mips.html#module-pwnlib.shellcraft.mips)
  - [`pwnlib.shellcraft.mips.linux`](https://docs.pwntools.com/en/stable/shellcraft/mips.html#module-pwnlib.shellcraft.mips.linux)
- [`pwnlib.regsort` — Register sorting](https://docs.pwntools.com/en/stable/shellcraft/regsort.html)
- `pwnlib.shellcraft.thumb` — Shellcode for Thumb Mode
  - [`pwnlib.shellcraft.thumb`](https://docs.pwntools.com/en/stable/shellcraft/thumb.html#module-pwnlib.shellcraft.thumb)
  - [`pwnlib.shellcraft.thumb.linux`](https://docs.pwntools.com/en/stable/shellcraft/thumb.html#module-pwnlib.shellcraft.thumb.linux)
