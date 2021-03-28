1. 在初次编译 GEEKOS 的时候，报错 "cc1: all warnings being treated as errors"  
解决方法：  
Makefile 中 `CC_GENERAL_OPTS := $(GENERAL_OPTS) -Werror` 改为 `CC_GENERAL_OPTS := $(GENERAL_OPTS)`，来将 warning 忽略
2. 初次编译 GEEKOS 时报错，对 '__stack_chk_fail' 未定义的引用
解决方法：
Makefile 中 `GENERAL_OPTS := -O -Wall $(EXTRA_C_OPTS)` 改为 `GENERAL_OPTS := -O -Wall -fno-stack-protector $(EXTRA_C_OPTS)`，强制关闭栈保护
3. 启动 bochs 后，初次进入 GEEKOS 时报错 "Failed assertion in Init_IDT:g_handlerSizeNoErr == g_handlerSizeErr"
解决方法：
更换旧版本 nasm，如0.99.05
4. 启动 bochs 时，报错 "ata0-0: could not open hard drive image file 'diskc.img'"
解决方法：
修改 "diskc.img" 的权限为可读写，如给予 777 权限