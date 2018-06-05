## `pwnlib.runner` — Running Shellcode

> **pwnlib.runner.run_assembly**(*a, **kw)[[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/runner.py#L1388-1395)

对所给定的汇编代码进行汇编并执行。

**Returns（返回值）： **一个与进程进行交互的`pwnlib.tubes.process.process`通道。

**示例**

```
>>> p = run_assembly('mov ebx, 3; mov eax, SYS_exit; int 0x80;')
>>> p.wait_for_close()
>>> p.poll()
3
```

```
>>> p = run_assembly('mov r0, #12; mov r7, #1; svc #0', arch='arm')
>>> p.wait_for_close()
>>> p.poll()
12
```



> **pwnlib.runner.run_shellcode**(*a, **kw)[[source\]](https://github.com/Gallopsled/pwntools/blob/67473560c7/pwnlib/runner.py#L1388-1395)

执行给定的汇编后的机器码。

**示例**

```
>>> bytes = asm('mov ebx, 3; mov eax, SYS_exit; int 0x80;')
>>> p = run_shellcode(bytes)
>>> p.wait_for_close()
>>> p.poll()
3
```

```
>>> bytes = asm('mov r0, #12; mov r7, #1; svc #0', arch='arm')
>>> p = run_shellcode(bytes, arch='arm')
>>> p.wait_for_close()
>>> p.poll()
12
```



> **pwnlib.runner.run_assembly_exitcode**(*a, **kw)[[source\]](https://github.com/Gallopsled/pwntools/blob/f4159bdad4/pwnlib/runner.py#L1388-1395)

对给定的汇编代码，将其汇编并执行，直至进程结束。

**Returns（返回值）：**进程的结束标识。

**示例**

```
>>> run_assembly_exitcode('mov ebx, 3; mov eax, SYS_exit; int 0x80;')
3
```



> **pwnlib.runner.run_shellcode_exitcode**(*a, **kw)[[source\]](https://github.com/Gallopsled/pwntools/blob/f4159bdad4/pwnlib/runner.py#L1388-1395)

对给定的汇编后的机器码，将其执行，直至进程结束。

**Returns（返回值）：**进程的结束标识。

**示例**

```
>>> bytes = asm('mov ebx, 3; mov eax, SYS_exit; int 0x80;')
>>> run_shellcode_exitcode(bytes)
3
```

