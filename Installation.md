# 安装
Ubuntu 12.04和14.04对pwntools的支持最佳，但大多数功能都可以在任何类Posix的发行版上运行（Debian，Arch，FreeBSD，OSX等）。

# 先决条件

为了充分利用pwntools，您应该安装以下系统库。

## Binutils
汇编外部体系结构（例如在Mac OS X上组装Sparc shellcode）需要安装`binutils`的交叉编译版本。我们已经使这个过程尽可能顺利。  
在这些例子中，将`$ARCH`替换为您的目标架构（例如，arm，mips64，vax等）。  
在现代8核机器上由源代码构建binutils大约需要60秒。

### Ubuntu
对于Ubuntu 12.04至15.10，您必须先添加[pwntools Personal Package Archive](http://binutils.pwntools.com/)存储库。  
Ubuntu Xenial（16.04）拥有大多数体系结构的官方软件包，不需要这一步。

```shell
$ apt-get install software-properties-common
$ apt-add-repository ppa:pwntools/binutils
$ apt-get update
```
然后，安装您目标架构的Binutils版本

```shell
$ apt-get install binutils-$ARCH-linux-gnu
```

### Mac OS X
Mac OS X同样简单，但需要从源代码构建binutils。不过，我们已经制作了`homebrew`来将本过程用一个命令实现。安装[brew](http://brew.sh/)后，从我们的[binutils](https://github.com/Gallopsled/pwntools-binutils/)仓库中获取相应的方法。

```shell
$ brew install https://raw.githubusercontent.com/Gallopsled/pwntools-binutils/master/osx/binutils-$ARCH.rb
```

### 备用操作系统
如果你想手工构建所有东西，或者不使用任何上述操作系统，构建binutils依然十分简单。

```shell
#!/usr/bin/env bash

V=2.25   # Binutils Version
ARCH=arm # Target architecture

cd /tmp
wget -nc https://ftp.gnu.org/gnu/binutils/binutils-$V.tar.gz
wget -nc https://ftp.gnu.org/gnu/binutils/binutils-$V.tar.gz.sig

gpg --keyserver keys.gnupg.net --recv-keys 4AE55E93
gpg --verify binutils-$V.tar.gz.sig

tar xf binutils-$V.tar.gz

mkdir binutils-build
cd binutils-build

export AR=ar
export AS=as

../binutils-$V/configure \
    --prefix=/usr/local \
    --target=$ARCH-unknown-linux-gnu \
    --disable-static \
    --disable-multilib \
    --disable-werror \
    --disable-nls

MAKE=gmake
hash gmake || MAKE=make

$MAKE -j clean all
sudo $MAKE install
```

## Python开发头
一些pwntools的Python依赖需要本地扩展（例如，Paramiko需要PyCrypto）。  
为了构建这些本地扩展，必须安装Python的开发头文件。

### Ubuntu

```shell
$ apt-get install python-dev
```

### Mac OS X
不需执行任何操作

# 安装发行版本
`pwntools`可以通过一个`pip`包安装

```shell
$ apt-get update
$ apt-get install python2.7 python-pip python-dev git libssl-dev libffi-dev build-essential
$ pip install --upgrade pip
$ pip install --upgrade pwntools
```

# 安装开发版本
如果你想在本地对pwntools的代码进行修改，可以进行以下操作

```shell
$ git clone https://github.com/Gallopsled/pwntools
$ pip install --upgrade --editable ./pwntools
```



