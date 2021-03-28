# GeekOS Project 1
## 安装 Ubuntu 16.04.6 Desktop i386
更新系统，安装依赖
```sh
sudo apt update
sudo apt upgrade
sudo apt install vim libx11-dev
```

## 下载编译安装 bochs
```sh
mkdir ~/bochs
cd ~/bochs
wget https://sourceforge.net/projects/bochs/files/bochs/2.6.11/bochs-2.6.11.tar.gz
tar -zxf bochs-2.6.11.tar.gz
cd bochs-2.6.11
sudo ./configure --enable-debugger --enable-disasm
sudo make
sudo make install
```

## 下载编译安装 nasm
```sh
mkdir ~/nasm
cd ~/nasm
wget https://www.nasm.us/pub/nasm/releasebuilds/0.99.05/nasm-0.99.05.tar.gz
tar -zxf nasm-0.99.05.tar.gz
cd nasm-0.99.05
sudo ./configure
sudo make
sudo make install
```

## Project 1
### 下载 geekos 源码
```sh
mkdir ~/geekos
cd ~/geekos
wget https://sourceforge.net/projects/geekos/files/geekos/geekos-0.3.0/geekos-0.3.0.zip
unzip geekos-0.3.0.zip
cd geekos-0.3.0/src/project1/build
```

### 补充 ELF 解析函数
```sh
vim ../src/geekos/elf.c
```

```c
//利用ELF头部结构体指向可执行文件头部，便于获取相关信息
elfHeader *ehdr = (elfHeader*)exeFileData;
	
//段的个数
exeFormat->numSegments = ehdr->phnum;
	
//代码入口地址
exeFormat->entryAddr = ehdr->entry;

//获取头部表在文件中的位置，便于读取信息
programHeader *phdr = (programHeader*)(exeFileData + ehdr->phoff);

//填充Exe_Segment
unsigned int i;
for(i = 0; i < exeFormat->numSegments; i++, phdr++)
{
	struct Exe_Segment *segment = &exeFormat->segmentList[i];
	//获取该段在文件中的偏移量*
	segment->offsetInFile = phdr->offset;
	//获取该段的数据在文件中的长度
	segment->lengthInFile = phdr->fileSize;
	//获取该段在用户内存中的起始地址
	segment->startAddress = phdr->vaddr;
	//获取该段在内存中的大小
	segment->sizeInMemory = phdr->memSize;
	//获取该段的保护标志位
	segment->protFlags = phdr->flags;
}

return 0;
```

### ~~修改入口函数~~
> **后文已修改，此处跳过此步骤。**
```sh
vim ../src/libc/entry.c
```

~~修改最下面两行内联汇编~~
```c
//__asm__ __volatile__ ("leave");
__asm__ __volatile__ ("add $0x1c, %esp");
__asm__ __volatile__ ("lret");
```

### 修改局部变量显示方式
```sh
vim ../src/geekos/lprog.c
```
搜索 `Spawn_Program` 函数，进行如下修改  
```c
static unsigned long virtSize;

static int Spawn_Program(char *exeFileData, struct Exe_Format *exeFormat)
{
    struct Segment_Descriptor* desc;
    // 注释掉这一局部变量，并提出函数外，改为静态全局变量
    //unsigned long virtSize;
    unsigned short codeSelector, dataSelector;

    // ...
}
```

搜索 `Printrap_Handler` 函数，进行如下修改  
```c
static void Printrap_Handler(struct Interrupt_State* state)
{
    char *msg;

    if (state->eax <= virtSize)
        msg = (char *)virtSpace + state->eax;
    else
        msg = (char *)state->eax;

    Print(msg);

    g_needReschedule = true;
    return;
}
```

### 编译 Project 1  
#### 修改 Makefile
```c
// 自行搜索，并将注释中的部分替换为其下面的内容

// GENERAL_OPTS := -O -Wall $(EXTRA_C_OPTS)
// 这里使用参数 -O0 禁用编译优化，就不用改上面的汇编
GENERAL_OPTS := -O0 -Wall -fno-stack-protector $(EXTRA_C_OPTS)

// CC_GENERAL_OPTS := $(GENERAL_OPTS) -Werror
CC_GENERAL_OPTS := $(GENERAL_OPTS)
```

#### 开始编译
```sh
sudo make depend
sudo make
```

设置编译出来的两个镜像为可读写
```sh
sudo chmod 777 fd.img diskc.img
```

### 运行 GeekOS
#### 编辑 bochs 启动配置
```
megs: 8
boot: a
floppya: 1_44=fd.img, status=inserted
log: ./bochs.out
ata0-master: type=disk, path=diskc.img, mode=flat, cylinders=40, heads=8, spt=63
```
假设启动配置文件保存在 `/home/username/bochs/bochs-2.6.11/bochsrc`

#### 启动 bochs
```sh
bochs -f /home/username/bochs/bochs-2.6.11/bochsrc
```

## Reference
### 表面上的
- http://geekos.sourceforge.net/
- http://geekos.sourceforge.net/docs/geekos-paper.pdf
- https://www.cs.umd.edu/~hollings/cs412/s16/GeekOSoverview.pdf
- http://www.cs.umd.edu/~hollings/cs412/s03/
- http://bochs.sourceforge.net/

### 实际上的
- https://111qqz.com/2016/06/geekos-project-1-%ef%bc%88elf%e6%96%87%e4%bb%b6%e7%9b%b8%e5%85%b3%ef%bc%89/
- https://blog.csdn.net/wu5795175/article/details/8560805
- https://blog.csdn.net/qq_35008279/article/details/78984561
- https://blog.csdn.net/weixin_42605042/article/details/90299638
- https://github.com/abc222/project1