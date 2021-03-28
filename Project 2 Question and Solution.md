# 问题与解决方法
（省略部分编译错误，在 Project 0/ Project 1 里已经解决）
（包括 stach_chk 的未引用、i386 等）
## 出现编译错误
### 描述
编译时出现错误：  
`error: dereferencing pointer to incomplete type 'struct User_Context'`
`unsigned int csSelector = userContext -> csSelector;`  
### 分析问题与解决
提示未定义的指针，也即是 struct User_Context 未定义。这里是未对头文件进行引用。我们只需要引入相关头文件即可：`#include <geekos/user.h>`
## 无法读取磁盘映像文件
### 描述
打开 geekos 时出现如下提示：  
`Message: att0-0: could not open hard drive image file 'diskc.img'`
### 分析问题与解决
该提示指出无法打开映像文件 `diskc.img`，因此我们需要查看相应的映像文件。而查看后发现它缺少必要的权限。通常可以使用 ls 命令观察对应文件的颜色来判断（例如默认显示为绿色）。  
因此我们使用
```bash
sudo chmod 777 diskc.img
```
命令对其进行处理即可。
## 挂载文件系统失败
### 描述
能正常运行 geekos，运行时提示：`Failed to mount /c filesystem`
### 分析问题与解决
这个提示说明挂载文件系统失败，我们首先更改 `bochsrc` 里的相关参数如下：
```ini
#...
boot: a
ata0-master: type=disk, path=diskc.img, mode=flat, cylinders=40, heads=8, spt=63
#...
```
*同时注意将上面引用的 fd.img 也更改权限 777，否则也会导致挂载失败*  
重新启动 geekos，即可正常运行。