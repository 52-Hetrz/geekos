# GeekOS Project 2
## 项目设计目的
扩充 GeekOS 操作系统内核，使得系统可以支持用户级进程的动态创建与执行
## 基本背景
### GeekOS 进程状态与转换
GeekOS 系统最早创建的内核进程有 `Idle、Reaper` 和 `Main` 三个，它们由 `Init_Scheduler` 函数创建：最先初始化一个核态进程 `mainThread`，并将其作为当前运行进程，函数最后还调用了 `Start_Kernel_Thread` 函数创建了两个系统进程 `Idle` 和 `Reaper`。所以，这三个进程是系统中最早存在的进程。
### GeekOS 的用户态进程
在 GeekOS 中为了区分用户态进程和内核进程，在 `Kernel_Thread` 结构体中设置了一个字段 `userContext`，指向用户态进程上下文。对于内核进程来说，这个指针为空，而用户态进程都拥有自己的用户上下文（User_Context）。因此，在 GeekOS 中要判断一个进程是内核进程还是用户态进程，只要通过 `userContext` 字段是否为空来判断就可以了。
### 用户态进程创建的流程
Spawn() ---> Read_Fully() ---> Parse_ELF_EXcutable() ---> Load_User_Program()  
---> Start_User_Thread() ---> Setup_User_Thread() ---> Attach_User_Context()

#### 部分函数功能说明
##### Spawn 函数
函数的原型如下：
```C
int Spawn(const char *program, const char *command, struct Kernel_Thread **pThread)
```
相关参数如下：
- program：要读入内存缓冲区的可执行文件
- command：用户执行程序执行时的命令行字符串
- pThread：存放刚刚创建进程的指针。  

它的主要功能是：
1. 调用 `Read_Fully` 函数将名为 `program` 的可执行文件全部读入内存缓冲区
2. 调用 `Parse_ELF_Executable` 函数，分析 ELF 格式文件。`Parse_ELF_Executable` 函数功能在 Project1 中已经实现，在这里我们依然会给出自己的实现方案。
3. 调用 `Load_User_Program` 将可执行程序的程序段和数据段等装入内存，初始化 `User_Context` 数据结构。
4. 调用 `Start_User_Thread` 函数创建一个进程并使其进入准备运行队列

##### Load_User_Program 函数
Load_User_Program 函数在 `/src/geekos/userseg.c` 文件中实现，代码需要开发人员完成。其原型如下：
```C
int Load_User_Program(char *exeFileData, ulong_t exeFileLength, struct Exe_Format *exeFormat, const char *command, struct User_Context **pUserContext)
```
相关参数如下：
- exeFileData：保存在内存缓冲中的用户程序可执行文件
- exeFileLength：可执行文件长度
- exeFormat：调用 `Parse_ELF_Executable` 函数得到的可执行文件格式信息
- command：用户输入的命令行，包括可执行文件名称和其他参数
- pUserContext：指向 `User_Context` 的指针，本函数完成用户上下文初始化的对象

其主要功能如下：
1. 根据 `Parse_ELF_Executable` 函数的执行结果 `Exe_Format` 中的 `Exe_Segment` 结构提供的用户程序段信息，用户命令参数及用户态进程栈大小计算用户态进程所需的最大内存空间，即要分配给用户态进程的内存空间。
2. 为用户程序分配内存空间，并初始化。
3. 根据 `Exe_Segment` 提供的用户段信息初始化代码段、数据段以及栈段的段描述符和段选择子。
4. 根据段信息将用户程序中的各段内容复制到分配的用户内存空间。
5. 根据 `Exe_Format` 结构初始化 `User_Context` 结构中的用户态进程代码段入口 `entry` 字段，并根据 `command` 参数初始化用户内存空间中的参数块。
6. 初始化 `User_Context` 结构的用户打开文件列表，并添加标准输入输出文件。
7. 将初始化完毕的 `User_Context` 指针赋予 `*pUserContext`，返回 0 表示成功。
### 用户态进程空间
每个用户态进程都拥有属于自己的内存段空间，如：代码段、数据段、栈段等，每个段有一个段描述符（segment descriptor），并且每个进程有一个段描述符表（Local Descriptor Table），用于保存该进程的所有段描述符。操作系统中还设置一个全局描述符表（GDT，Global Descriptor Table），用于记录了系统中所有进程的ldt描述符。
### 用户态进程创建 LDT 步骤
1. 调用函数 `Allocate_Segment_Descriptor` 新建一个 LDT 描述符
2. 调用函数 `Selector` 新建一个 LDT 选择子
3. 调用函数 `Init_Code_Segment_Descriptor` 初始化一个文本段描述符
4. 调用函数 `Init_Data_Segment_Descriptor` 初始化一个数据段描述符
5. 调用函数 `Selector` 新建一个数据段选择子
6. 调用函数 `Selector` 新建一个文本（可执行代码）段选择子
## 项目实现
### 必需函数实现
#### Spawn
`src/GeekOS/user.c` 文件中的函数 `Spawn`，其功能为生成一个新的用户级进程：
```C
/*
 * Spawn a user process.
 * Params:
 *   program - the full path of the program executable file
 *   command - the command, including name of program and arguments
 *   pThread - reference to Kernel_Thread pointer where a pointer to
 *     the newly created user mode thread (process) should be
 *     stored
 * Returns:
 *   The process id (pid) of the new process, or an error code
 *   if the process couldn't be created.  Note that this function
 *   should return ENOTFOUND if the reason for failure is that
 *   the executable file doesn't exist.
 */
int Spawn(const char *program, const char *command, struct Kernel_Thread **pThread)
{
    /*
     * Hints:
     * - Call Read_Fully() to load the entire executable into a memory buffer
     * - Call Parse_ELF_Executable() to verify that the executable is
     *   valid, and to populate an Exe_Format data structure describing
     *   how the executable should be loaded
     * - Call Load_User_Program() to create a User_Context with the loaded
     *   program
     * - Call Start_User_Thread() with the new User_Context
     *
     * If all goes well, store the pointer to the new thread in
     * pThread and return 0.  Otherwise, return an error code.
     */
	
	// 这里的Spawn功能是生成一个新的用户级进程
	int result;
	char *file_data = NULL;
	ulong_t file_length = 0;
	result = Read_Fully(program, (void **)&file_data, &file_length);
	
	if(result != 0)
	{
		if(file_data != NULL)
		{
			Free(file_data);
		}
			return ENOTFOUND;
	}

	// 分析ELF文件
	struct Exe_Format exe_format;
	result = Parse_ELF_Executable(file_data, file_length, &exe_format);
	if(result != 0)
	{
		if(file_data != NULL)
		{
			Free(file_data);
		}
		return result;
	}

	// 加载用户程序
	struct User_Context *user_context = NULL;
	result = Load_User_Program(file_data, file_length, &exe_format, command, &user_context);
	if (result != 0)
	{
		if(file_data != NULL)
		{
			Free(file_data);
		}

		if(user_context != NULL)
		{
			Destroy_User_Context(user_context);
		}
		return result;
	}
	if (file_data != NULL)
	{
		Free(file_data);
	}
	file_data = NULL;

	// 开始用户进程
	struct Kernel_Thread *thread = NULL;
	thread = Start_User_Thread(user_context, false);
	// 超出内存，创建失败
	if(thread == NULL)
	{
		if(user_context != NULL)
		{
			Destroy_User_Context(user_context);
		}
		return ENOMEM;
	}
	KASSERT(thread -> refCount == 2);
	// 返回核心进程指针
	*pThread = thread;
	return 0;
}
```
#### Switch_To_User_Context
`src/GeekOS/user.c` 文件中的函数 `Switch_To_User_Context`，调度程序在执行一个新的进程前调用其以切换用户地址空间
```C
/*
 * If the given thread has a User_Context,
 * switch to its memory space.
 *
 * Params:
 *   kthread - the thread that is about to execute
 *   state - saved processor registers describing the state when
 *      the thread was interrupted
 */
void Switch_To_User_Context(struct Kernel_Thread* kthread, struct Interrupt_State* state)
{
    /*
     * Hint: Before executing in user mode, you will need to call
     * the Set_Kernel_Stack_Pointer() and Switch_To_Address_Space()
     * functions.
     */

    // 调度程序在执行一个新进程前调用该函数切换用户地址
    
	// 之前最近使用的user_context
	static struct User_Context* s_current_user_context;

	// 指向user_context的指针，并初始化为准备切换的进程
	struct User_Context* user_context = kthread -> userContext;

	KASSERT(!Interrupts_Enabled());

	// user_context 为零代表此进程为核心态，不需要切换地址空间
	if (user_context == 0)
	{
		return;
	}

	if(user_context != s_current_user_context)
	{
		// 为用户态进程时需要切换地址空间
		Switch_To_Address_Space(user_context);
		// 新进程的核心栈指针
		ulong_t esp0 = ((ulong_t)kthread -> stackPage) + PAGE_SIZE;
		// 设置内核堆栈指针
		Set_Kernel_Stack_Pointer(esp0);
		// 保存新的user_context
		s_current_user_context = user_context;
	}
}
```
#### Parse_ELF_Executable
`src/GeekOS/elf.c` 文件中的函数 `Parse_ELF_Executable`。其实现如下：
```C
/**
 * From the data of an ELF executable, determine how its segments
 * need to be loaded into memory.
 * @param exeFileData buffer containing the executable file
 * @param exeFileLength length of the executable file in bytes
 * @param exeFormat structure describing the executable's segments
 *   and entry address; to be filled in
 * @return 0 if successful, < 0 on error
 */
int Parse_ELF_Executable(char *exeFileData, ulong_t exeFileLength,
    struct Exe_Format *exeFormat)
{

	// 利用 ELF 头部结构体指向可执行文件头部
	elfHeader *ehdr = (elfHeader*)exeFileData;
	
	// 段个数
	exeFormat -> numSegments = ehdr -> phnum;
	// 代码入口
	exeFormat -> entryAddr = ehdr -> entry;
	// 获取头部表位置
	programHeader *phdr = (programHeader*)(exeFileData + ehdr -> phoff);
	// 填充 Exe_Segment
	unsigned int i;
	for (i = 0; i < exeFormat -> numSegments; i++, phdr++)
	{
		struct Exe_Segment *segment = &exeFormat -> segmentList[i];

		// 获取文件中偏移量
		segment -> offsetInFile = phdr -> offset;

		// 获取数据在文件中长度
		segment -> lengthInFile = phdr -> fileSize;

		// 获取该段在内存起始地址
		segment -> startAddress = phdr -> vaddr;

		// 获取该段在内存中的大小
		segment -> sizeInMemory = phdr -> memSize;

		// 获取该段的保护标志位
		segment -> protFlags = phdr -> flags;
	}
	return 0;
}
```
#### 高层操作支持函数
`src/GeekOS/userseg.c` 文件中主要是实现一些对 `src/GeekOS/user.c` 高层操作支持的函数：
##### Create_User_Context
该函数用于创建并初始化一个用户上下文结构：
```C
/*
 * Create a new user context of given size
 */
static struct User_Context* Create_User_Context(ulong_t size)
{
	struct User_Context* user_context;
	size = Round_Up_To_Page(size);
	user_context = (struct User_Context *)Malloc(sizeof(struct User_Context));

	// 内存分配成功，则为 user_context 下 memory 分配内存空间
	if (user_context == NULL)
	{
		return NULL;
	}
	user_context -> memory = (char*)Malloc(size);
	if(user_context -> memory == NULL)
	{
		Free(user_context);
		return NULL;
	}
	memset(user_context -> memory, '\0', size);
	user_context -> size = size;

	// 新建一个 LDT 描述符
	user_context -> ldtDescriptor = Allocate_Segment_Descriptor();
	if (user_context -> ldtDescriptor == NULL)
	{
		Free(user_context -> memory);
		return NULL;
	}
	// 初始化段描述符
	Init_LDT_Descriptor(user_context -> ldtDescriptor, user_context -> ldt, NUM_USER_LDT_ENTRIES);
	// 新建一个 LDT 选择子
	user_context -> ldtSelector = Selector(KERNEL_PRIVILEGE, true, Get_Descriptor_Index(user_context -> ldtDescriptor));
	// 新建一个代码段描述符
	Init_Code_Segment_Descriptor(&user_context -> ldt[0],(ulong_t)user_context -> memory, size / PAGE_SIZE, USER_PRIVILEGE);
	// 新建一个数据段描述符
	Init_Data_Segment_Descriptor(&user_context -> ldt[1],(ulong_t)user_context -> memory, size / PAGE_SIZE, USER_PRIVILEGE);
	// 新建数据段和代码段选择子
	user_context -> csSelector = Selector(USER_PRIVILEGE, false, 0);
	user_context -> dsSelector = Selector(USER_PRIVILEGE, false, 1);
	// 清零引用数
	user_context -> refCount = 0;

	return user_context;
}
```
##### Destroy_User_Context
该函数功能为释放用户态进程占用的内存资源
```C
/*
 * Destroy a User_Context object, including all memory
 * and other resources allocated within it.
 */
void Destroy_User_Context(struct User_Context* userContext)
{
    /*
     * Hints:
     * - you need to free the memory allocated for the user process
     * - don't forget to free the segment descriptor allocated
     *   for the process's LDT
     */
	
	KASSERT(userContext -> refCount == 0);
	// 释放 LDT descriptor
	Free_Segment_Descriptor(userContext -> ldtDescriptor);
	// 释放内存空间
	Disable_Interrupts();
	Free(userContext -> memory);
	Free(userContext);
	Enable_Interrupts();
}
```
##### Load_User_Program
该函数功能通过加载可执行文件镜像创建新进程的 `User_Context` 结构
```C
/*
 * Load a user executable into memory by creating a User_Context
 * data structure.
 * Params:
 * exeFileData - a buffer containing the executable to load
 * exeFileLength - number of bytes in exeFileData
 * exeFormat - parsed ELF segment information describing how to
 *   load the executable's text and data segments, and the
 *   code entry point address
 * command - string containing the complete command to be executed:
 *   this should be used to create the argument block for the
 *   process
 * pUserContext - reference to the pointer where the User_Context
 *   should be stored
 *
 * Returns:
 *   0 if successful, or an error code (< 0) if unsuccessful
 */
int Load_User_Program(char *exeFileData, ulong_t exeFileLength,
    struct Exe_Format *exeFormat, const char *command,
    struct User_Context **pUserContext)
{
    /*
     * Hints:
     * - Determine where in memory each executable segment will be placed
     * - Determine size of argument block and where it memory it will
     *   be placed
     * - Copy each executable segment into memory
     * - Format argument block in memory
     * - In the created User_Context object, set code entry point
     *   address, argument block address, and initial kernel stack pointer
     *   address
     */

	// 加载可执行文件镜像创建新进程的 User_Context 结构
	unsigned int i;
	struct User_Context *user_context;

	// 最大的分配内存空间
	ulong_t maxva = 0;
	
	// 计算用户态进程所需要的最大内存空间

	for(i = 0; i < exeFormat -> numSegments; i++)
	{
		struct Exe_Segment *segment = &exeFormat -> segmentList[i];
		ulong_t topva = segment -> startAddress + segment -> sizeInMemory;
		if (topva > maxva)
		{
			maxva = topva;
		}
	}

	// 程序参数数目
	unsigned int num_args;
	// 获取参数块大小
	ulong_t arg_block_size;
	Get_Argument_Block_Size(command, &num_args, &arg_block_size);
	// 用户进程大小 = 参数块总大小 + 进程堆栈大小
	ulong_t size = Round_Up_To_Page(maxva) + DEFAULT_USER_STACK_SIZE;
	// 参数块地址
	ulong_t arg_block_addr = size;
	size += arg_block_size;
	// 按照相应大小创建进程
	user_context = Create_User_Context(size);

	// 如果创建失败，返回错误信息
	if(user_context == NULL)
	{
		return -1;
	}

	// 将用户程序中的各段内容复制到分配的用户内存空间
	for(i = 0; i < exeFormat -> numSegments; i++)
	{
		struct Exe_Segment *segment = &exeFormat ->segmentList[i];
		memcpy(user_context -> memory + segment -> startAddress, exeFileData + segment -> offsetInFile, segment -> lengthInFile);
	}

	// 格式化参数块
	Format_Argument_Block(user_context -> memory + arg_block_addr, num_args, arg_block_addr, command);
	// 初始化数据段、堆栈段与代码段信息
	user_context -> entryAddr = exeFormat -> entryAddr;
	user_context -> argBlockAddr = arg_block_addr;
	user_context -> stackPointerAddr = arg_block_addr;

	// 将初始化完毕的 User_Context 赋值给 *pUserContext
	*pUserContext = user_context;

	return 0;
}
```
##### Copy_From_User 与 Copy_To_User
两个函数功能是在用户地址空间和内核地址空间之间复制数据，在分段存储器管理模式下，只要段有效，调用 `memcpy` 函数就可以实现这两个函数功能
```C
/*
 * Copy data from user memory into a kernel buffer.
 * Params:
 * destInKernel - address of kernel buffer
 * srcInUser - address of user buffer
 * bufSize - number of bytes to copy
 *
 * Returns:
 *   true if successful, false if user buffer is invalid (i.e.,
 *   doesn't correspond to memory the process has a right to
 *   access)
 */
bool Copy_From_User(void* destInKernel, ulong_t srcInUser, ulong_t bufSize)
{
    /*
     * Hints:
     * - the User_Context of the current process can be found
     *   from g_currentThread->userContext
     * - the user address is an index relative to the chunk
     *   of memory you allocated for it
     * - make sure the user buffer lies entirely in memory belonging
     *   to the process
     */
    // Validate_User_Memory(NULL,0,0); /* delete this; keeps gcc happy */

	// 该函数将数据从用户地址空间复制到内核地址空间
	struct User_Context * user_context = g_currentThread -> userContext;

	// 如果访问用户内存非法，直接返回失败
	if(!Validate_User_Memory(user_context, srcInUser, bufSize))
	{
		return false;
	}
	// 复制数据到内核
	memcpy(destInKernel, user_context -> memory + srcInUser, bufSize);
	// 拷贝成功返回 true
	return true;
}
```

```C
/*
 * Copy data from kernel memory into a user buffer.
 * Params:
 * destInUser - address of user buffer
 * srcInKernel - address of kernel buffer
 * bufSize - number of bytes to copy
 *
 * Returns:
 *   true if successful, false if user buffer is invalid (i.e.,
 *   doesn't correspond to memory the process has a right to
 *   access)
 */
bool Copy_To_User(ulong_t destInUser, void* srcInKernel, ulong_t bufSize)
{
    /*
     * Hints: same as for Copy_From_User()
     */
	
	struct User_Context* user_context = g_currentThread -> userContext;
	// 越界返回失败
	if(!Validate_User_Memory(user_context, destInUser, bufSize))
	{
		return false;
	}
	// 从内核拷贝数据到用户空间
	memcpy(user_context -> memory + destInUser, srcInKernel, bufSize);
	// 拷贝成功返回 true
	return true;
}
```
##### Switch_To_Address_Space
函数功能是通过将进程的 LDT 装入到 LDT 寄存器来激活用户的地址空间
```C
/*
 * Switch to user address space belonging to given
 * User_Context object.
 * Params:
 * userContext - the User_Context
 */
void Switch_To_Address_Space(struct User_Context *userContext)
{
    /*
     * Hint: you will need to use the lldt assembly language instruction
     * to load the process's LDT by specifying its LDT selector.
     */

	// 切换到新的局部描述符表 LDT
	ushort_t ldtSelector = userContext -> ldtSelector;
	__asm__ __volatile__(
	"lldt %0"
	:
	:	"a" (ldtSelector)	
	);
}
```
#### kthread.c 中的函数
在这里我们需要修改两个函数，同时需要在 `/project2/src/geekos/kthread.c` 文件中，添加头文件：`#include <geekos/user.h>`
##### Setup_User_Thread
该函数功能是为进程初始化内核栈，栈中为进程首次进入用户态运行时设置处理器状态时要使用的数据
```C
/*
 * Set up the a user mode thread.
 */
void Setup_User_Thread(
    struct Kernel_Thread* kthread, struct User_Context* userContext)
{
    /*
     * Hints:
     * - Call Attach_User_Context() to attach the user context
     *   to the Kernel_Thread
     * - Set up initial thread stack to make it appear that
     *   the thread was interrupted while in user mode
     *   just before the entry point instruction was executed
     * - The esi register should contain the address of
     *   the argument block
     */
    //TODO("Create a new thread to execute in user mode");

	ulong_t eflags = EFLAGS_IF;
	// CS、 DS 选择子
	unsigned int csSelector = userContext -> csSelector;
	unsigned int dsSelector = userContext -> dsSelector;

	// 调用 Attach_User_Context 加载用户上下文
	Attach_User_Context(kthread, userContext);

	// 初始化用户态进程堆栈，使其看起来像是被刚中断运行
	// 分别调用 Push 将下面的数据压入堆栈
	Push(kthread, dsSelector);	// DS 选择子
	Push(kthread, userContext -> stackPointerAddr);	// 中断指针
	Push(kthread, eflags);	// Eflags
	Push(kthread, csSelector);	// CS 选择子
	Push(kthread, userContext -> entryAddr);	// 程序计数器
	Push(kthread, 0);	// 错误代码
	Push(kthread, 0);	// 中断号

	// 初始化通用寄存单元，向 esi 传递参数块地址
	Push(kthread, 0);	// eax
	Push(kthread, 0);	// ebx
	Push(kthread, 0);	// ecx
	Push(kthread, 0);	// edx
	Push(kthread, userContext -> argBlockAddr);	// esi
	Push(kthread, 0);	// edi
	Push(kthread, 0);	// ebp

	// 初始化数据段寄存单元
	Push(kthread, dsSelector);	// ds
	Push(kthread, dsSelector);	// es
	Push(kthread, dsSelector);	// fs
	Push(kthread, dsSelector);	// gs
}

```
##### Start_User_Thread
这是一个高层操作，它使用 `User_Context` 对象开始一个新的进程
```C
/*
 * Start a user-mode thread (i.e., a process), using given user context.
 * Returns pointer to the new thread if successful, null otherwise.
 */
struct Kernel_Thread*
Start_User_Thread(struct User_Context* userContext, bool detached)
{
    /*
     * Hints:
     * - Use Create_Thread() to create a new "raw" thread object
     * - Call Setup_User_Thread() to get the thread ready to
     *   execute in user mode
     * - Call Make_Runnable_Atomic() to schedule the process
     *   for execution
     */

	// 这个函数使用 User_Context 对象开始一个新进程
	
	// 如果传入的用户上下文字段为空，也即是非用户态进程，则返回错误
	if(userContext == NULL)
	{
		return NULL;
	}

	// 建立用户态进程
	struct Kernel_Thread *kthread = Create_Thread(PRIORITY_USER, detached);
	if(kthread == NULL)
	{
		return NULL;
	}

	Setup_User_Thread(kthread, userContext);

	// 将创建的进程加入就绪队列
	Make_Runnable_Atomic(kthread);

	// 新用户态进程创建成功，返回指针
	return kthread;
}
```
#### syscall.c 中的函数
该文件中主要是实现用户程序要求内核进行服务的一些系统调用函数定义，要求实现的函数如下：
- Sys_Exit
- Sys_PrintString
- Sys_GetKey
- Sys_SetAttr
- Sys_GetCursor
- Sys_PutCursor
- Sys_Spawn
- Sys_Wait
- Sys_GetPID

我们的操作均围绕着 `/project2/src/geekos/syscall.c` 文件进行
##### Copy_User_String
该函数用于在 `Sys_PrintString` 中使用
```C
static int Copy_User_String(ulong_t uaddr, ulong_t len, ulong_t maxLen, char **pStr)
{
	int result = 0;
	char *string;
	if(len > maxLen)
	{
		return EINVALID;
	}
	// 分配字符串内存空间
	string = (char*)Malloc(len + 1);
	if (string == 0)
	{
		return ENOMEM;
	}
	// 复制字符串到内核
	if (!Copy_From_User(string, uaddr, len))
	{
		result = EINVALID;
		Free(string);
		return result;
	}
	string[len] = '\0';

	// 拷贝成功
	*pStr = string;

	return result;
}
```
##### Sys_Exit
```C
static int Sys_Exit(struct Interrupt_State* state)
{
	Exit(state -> ebx);
}
```
##### Sys_PrintString
```C
/*
 * Print a string to the console.
 * Params:
 *   state->ebx - user pointer of string to be printed
 *   state->ecx - number of characters to print
 * Returns: 0 if successful, -1 if not
 */
static int Sys_PrintString(struct Interrupt_State* state)
{
	int result;
	uint_t length = state -> ecx;	// 字符串长度
	uchar_t * buf = 0;
	if(length > 0)
	{
		// 复制到系统内核
		if(Copy_User_String(state -> ebx, length, 1023, (char **)&buf)!=0)
		{
			if(buf != NULL)
			{
				Free(buf);
			}
			return result;
		}
		// 输出到控制台
		Put_Buf(buf, length);
	}
	if (buf != NULL)
	{
		Free(buf);
	}
	return result;
}
```
##### Sys_GetKey
```C
/*
 * Get a single key press from the console.
 * Suspends the user process until a key press is available.
 * Params:
 *   state - processor registers from user mode
 * Returns: the key code
 */
static int Sys_GetKey(struct Interrupt_State* state)
{
	// 返回按键码
	// /geekos/keyboard.c Keycode Wait_For_key(void);
	return Wait_For_Key();
}
```
##### Sys_SetAttr
```C
/*
 * Set the current text attributes.
 * Params:
 *   state->ebx - character attributes to use
 * Returns: always returns 0
 */
static int Sys_SetAttr(struct Interrupt_State* state)
{
	// 设置当前文本显示格式
	// /geekos/screen.c void Set_Current_Attr(uchar_t attrib);
	Set_Current_Attr((uchar_t)state -> ebx);
	return 0;
}

```
##### Sys_GetCursor
```C
/*
 * Get the current cursor position.
 * Params:
 *   state->ebx - pointer to user int where row value should be stored
 *   state->ecx - pointer to user int where column value should be stored
 * Returns: 0 if successful, -1 otherwise
 */
static int Sys_GetCursor(struct Interrupt_State* state)
{
	// 获取当前光标位置
	int row, col;
	if (!Copy_To_User(state -> ebx, &row, sizeof(int)) || !Copy_To_User(state -> ecx, &col, sizeof(int)))
	{
						return -1;
	}
	return 0;	
}
```
##### Sys_PutCursor
```C
/*
 * Set the current cursor position.
 * Params:
 *   state->ebx - new row value
 *   state->ecx - new column value
 * Returns: 0 if successful, -1 otherwise
 */
static int Sys_PutCursor(struct Interrupt_State* state)
{
	// 设置光标位置
	return Put_Cursor(state -> ebx, state -> ecx) ? 0 : -1;
}

```
##### Sys_Spawn
```C
/*
 * Create a new user process.
 * Params:
 *   state->ebx - user address of name of executable
 *   state->ecx - length of executable name
 *   state->edx - user address of command string
 *   state->esi - length of command string
 * Returns: pid of process if successful, error code (< 0) otherwise
 */
static int Sys_Spawn(struct Interrupt_State* state)
{
	int result; // 返回值
	char *program = 0;	// 程序名
	char *command = 0;	// 用户命令
	struct Kernel_Thread *process;

	// 复制程序名和命令字符串到用户内存空间
	result = Copy_User_String(state -> ebx, state -> ecx, VFS_MAX_PATH_LEN, &program);
	if(result != 0)
	{
		// 复制名称
		goto fail;
	}
	result = Copy_User_String(state -> edx, state -> esi, 1023, &command);
	if(result != 0)
	{
		// 复制命令
		goto fail;
	}

	// 生成用户进程
	Enable_Interrupts();	// 开中断
	result = Spawn(program, command, &process);	// 得到名称命令就可以生成了
	if(result == 0)
	{
		// 如果成功返回新进程 ID
		KASSERT(process != 0);
		result = process -> pid;
	}
	Disable_Interrupts();	// 关中断

fail:
	if(program != 0)
	{
		Free(program);
	}

	if(command != 0)
	{
		Free(command);
	}
	
	return result;
}
```
##### Sys_Wait
```C
/*
 * Wait for a process to exit.
 * Params:
 *   state->ebx - pid of process to wait for
 * Returns: the exit code of the process,
 *   or error code (< 0) on error
 */
static int Sys_Wait(struct Interrupt_State* state)
{
	int exitCode;
	
	// 查找等待进程
	struct Kernel_Thread *kthread = Lookup_Thread(state -> ebx);
	
	// 如果没有就返回错误代码
	if(kthread == 0)
	{
		return -1;
	}

	// 等待进程结束
	Enable_Interrupts();
	exitCode = Join(kthread);
	Disable_Interrupts();
	return exitCode;
}
```
##### Sys_GetPID
```C
/*
 * Get pid (process id) of current thread.
 * Params:
 *   state - processor registers from user mode
 * Returns: the pid of the current thread
 */
static int Sys_GetPID(struct Interrupt_State* state)
{
	// 返回当前进程 pid
	return g_currentThread -> pid;
}
```
#### main.c 函数改动
我们在 `main.c` 文件中改写生成第一个用户态进程的函数调用：  
`Spawn_Init_Process(void)`
```C
static void Spawn_Init_Process(void)
{
	struct Kernel_Thread *pThread;
	Spawn("/c/shell.exe", "/c/shell.exe", &pThread);
}
```
### 更改 bochsrc 配置文件
和我们之前一样，执行相应的命令生成了对应的 `img` 文件后，我们有如下 bochsrc 文件：
```ini
#################################################################
# Bochs的配置文件
# Configuration file for Bochs
#################################################################

# how much memory the emulated machine will have
megs: 32

# filenameof ROM images
romimage:file=/usr/local/share/bochs/BIOS-bochs-latest
vgaromimage:file=/usr/local/share/bochs/VGABIOS-lgpl-latest

# which disk image will be used 这个是启动软盘
floppya:1_44=fd.img, status=inserted
#后面我们会在运行GeekOS时将它改成fd.img

# choose the boot disk 确定启动方式
boot: a
ata0-master: type=disk, path=diskc.img, mode=flat, cylinders=40, heads=8, spt=63

# where do we send log messages?
log: bochsout.txt

# disable the mouse
mouse: enabled=0

# enable key mapping ,using US layout as default
keyboard:keymap=/usr/local/share/bochs/keymaps/x11-pc-us.map
```
## 结果测试
### 运行输入与期望结果
`bochs` 运行后，输入相关命令，即可执行 `project2/src/user` 下的各个可执行文件。由于 `Spawn_Init_Process(void)` 里填写的是 `shell` 程序，故从 `shell` 开始执行，输入相关命令即可得到不同结果。  
通过终端启动 `bochs` 启动并进入 `GeekOS` 后，我们预期有如下的输入输出：  
（带 $ 的为用户输入）（在这里我们不执行 null，因其是死循环，没有输出）
```bash
Welcome to GeekOS!
$ pid
6
$ b
I am the b program
Arg 0 is b
$ b 1 2 3
I am the b program
Arg 0 is b
Arg 1 is 1
Arg 2 is 2
Arg 3 is 3
$ c
I am the c program
Illegal systemcall -1 by process 9
$ long
Start Long
End Long
$ exit
DONE!
```
### 对 shell.c 中 main 函数的分析
在 `shecll.c` 中的 `main` 函数代码如下：
```C
int main(int argc, char **argv)
{
    int nproc;
    char commandBuf[BUFSIZE+1];
    struct Process procList[MAXPROC];
    char path[BUFSIZE+1] = DEFAULT_PATH;
    char *command;

    /* Set attribute to gray on black. */
    Print("\x1B[37m");

    while (true) {
	/* Print shell prompt (bright cyan on black background) */
	Print("\x1B[1;36m$\x1B[37m ");

	/* Read a line of input */
	Read_Line(commandBuf, sizeof(commandBuf));
	command = Strip_Leading_Whitespace(commandBuf);
	Trim_Newline(command);

	/*
	 * Handle some special commands
	 */
	if (strcmp(command, "exit") == 0) {
	    /* Exit the shell */
	    break;
	} else if (strcmp(command, "pid") == 0) {
	    /* Print the pid of this process */
	    Print("%d\n", Get_PID());
	    continue;
	} else if (strcmp(command, "exitCodes") == 0) {
	    /* Print exit codes of spawned processes. */
	    exitCodes = 1;
	    continue;
	} else if (strncmp(command, "path=", 5) == 0) {
	    /* Set the executable search path */
	    strcpy(path, command + 5);
	    continue;
	} else if (strcmp(command, "") == 0) {
	    /* Blank line. */
	    continue;
	}

	/*
	 * Parse the command string and build array of
	 * Process structs representing a pipeline of commands.
	 */
	nproc = Build_Pipeline(command, procList);
	if (nproc <= 0)
	    continue;

	Spawn_Single_Command(procList, nproc, path);
    }

    Print_String("DONE!\n");
    return 0;
}
```
可以看到它的处理方案是这样的：
- 输入 exit，退出
- 输入 pid，查询内核建立进程数
- 其他的一些预设命令
- 输入设置外命令字符，到指令路径查找相应程序，新建立进程执行，例如：b、c、long、null 等（均在 `project2/src/user` 下）
## 其他
### 进程 PID
进程一开始PID为6，是因为在系统初始化之初已经运行了 5 个进程，因此我们的第一个用户程序的进程 ID 是从 6 开始的。这五个进程分别为： `Idle、Reaper、Init_Floppy、 Init_IDE `和` Main`。`Idle、Reaper` 和 `Main`三个进程，它们由 `Init_Scheduler` 函数创建，是执行进程，空闲进程，进程死掉时回收；`Init_Floppy` 初始化软盘， `Init_IDE` 初始化硬盘。
### b 程序的参数
b 程序带有参数，在创建用户态进程时，除了分配用户态内存堆栈，还给参数专门分配了空间：
```C
// project2/src/geekos/userseg.c
int Load_User_Program(char *exeFileData, ulong_t exeFileLength, struct Exe_Format *exeFormat, const char *command, struct User_Context **pUserContext)
{
// ...
	// 程序参数数目
	unsigned int num_args;
	// 获取参数块大小
	ulong_t arg_block_size;
	Get_Argument_Block_Size(command, &num_args, &arg_block_size);
	// 用户进程大小 = 参数块总大小 + 进程堆栈大小
	ulong_t size = Round_Up_To_Page(maxva) + DEFAULT_USER_STACK_SIZE;
// ...
}
```
进程创建好后，通过 `project2/src/geekos/kthread.c` 中的 `Schedule` 函数执行：
```C
void Schedule(void)
{
    struct Kernel_Thread* runnable;

    /* Make sure interrupts really are disabled */
    KASSERT(!Interrupts_Enabled());

    /* Preemption should not be disabled. */
    KASSERT(!g_preemptionDisabled);

    /* Get next thread to run from the run queue */
    runnable = Get_Next_Runnable();

    /*
     * Activate the new thread, saving the context of the current thread.
     * Eventually, this thread will get re-activated and Switch_To_Thread()
     * will "return", and then Schedule() will return to wherever
     * it was called from.
     */
    Switch_To_Thread(runnable);
}
```
注意最后的 `Switch_To_Thread(runnable)`
## Reference
https://blog.csdn.net/qq_35008279/article/details/79648917  
https://blog.csdn.net/weixin_42605042/article/details/90299638