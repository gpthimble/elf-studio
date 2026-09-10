/* ============================================================================
 * elf-const.js — ELF 规范常量、枚举字典与字段文档
 * 数据来源：System V ABI (gABI), ELF 规范, RISC-V ELF psABI, GNU extensions
 * ==========================================================================*/
'use strict';

const ELFCLASS32 = 1, ELFCLASS64 = 2;
const ELFDATA2LSB = 1, ELFDATA2MSB = 2;

/* --------------------------------------------------------------------------
 * 枚举字典：每个枚举项都带规范取值与原理说明
 * 结构：{ title, abi, desc, mask?, values: [{ v, name, desc }] }
 * ------------------------------------------------------------------------*/
const ENUMS = {
  EI_CLASS: {
    title: 'EI_CLASS — 文件类别 / 地址位宽',
    abi: 'ELF 规范 (gABI 4.1)',
    desc: 'e_ident 的第 5 个字节。决定 ELF 结构体的布局：ELF32 使用 Elf32_Ehdr（地址/偏移 4 字节），ELF64 使用 Elf64_Ehdr（8 字节）。解析器必须先读这一字节，才能知道如何解释后续所有头部。',
    values: [
      { v: 0, name: 'ELFCLASSNONE', desc: '无效类别，文件不是有效 ELF。' },
      { v: 1, name: 'ELFCLASS32', desc: '32 位目标。Elf32_Ehdr 的 e_entry/e_phoff/e_shoff 为 4 字节（Elf32_Addr / Elf32_Off）。' },
      { v: 2, name: 'ELFCLASS64', desc: '64 位目标。Elf64_Ehdr 的对应字段为 8 字节。注意 Elf64 结构体在头上多出 4 字节填充（e_ident 16 字节而非 28 字节的对齐）。' }
    ]
  },
  EI_DATA: {
    title: 'EI_DATA — 数据编码 / 字节序',
    abi: 'ELF 规范 (gABI 4.1)',
    desc: 'e_ident 的第 6 个字节。指定多字节字段的字节序。解析器必须在读取 e_type 之前确定字节序。',
    values: [
      { v: 0, name: 'ELFDATANONE', desc: '无效编码。' },
      { v: 1, name: 'ELFDATA2LSB', desc: '小端序 (Least Significant Byte first)。RISC-V、x86、AArch64(常见) 使用。低地址存放最低有效字节。' },
      { v: 2, name: 'ELFDATA2MSB', desc: '大端序 (Most Significant Byte first)。用于部分 MIPS/PowerPC 目标。' }
    ]
  },
  EI_VERSION: {
    title: 'EI_VERSION — ELF 版本',
    abi: 'ELF 规范 (gABI 4.1)',
    desc: 'e_ident 的第 7 个字节，恒为 EV_CURRENT(1)。与 e_version 字段不同：这一字节描述「e_ident 结构本身」的版本，而 e_version 描述「文件整体」的版本。',
    values: [
      { v: 0, name: 'EV_NONE', desc: '无效版本。' },
      { v: 1, name: 'EV_CURRENT', desc: '当前版本。自 ELF 诞生以来从未改变，因此这一字节几乎总是 1。' }
    ]
  },
  EI_OSABI: {
    title: 'EI_OSABI — 操作系统 / ABI 标识',
    abi: 'gABI + 各 OS/架构注册值',
    desc: 'e_ident 的第 8 个字节，标识该目标文件遵循的操作系统 ABI 约定。它主要影响对 OS 扩展段（如 .note.* ）的语义解释，以及运行时加载器的兼容性判断。',
    values: [
      { v: 0, name: 'ELFOSABI_NONE / SYSV', desc: '无 OS 特定扩展，遵循 System V ABI。Linux 下没有 .note.ABI-tag 时也常写成 0，但多数 Linux 可执行文件会写 3。' },
      { v: 1, name: 'ELFOSABI_HPUX', desc: 'Hewlett-Packard HP-UX。' },
      { v: 2, name: 'ELFOSABI_NETBSD', desc: 'NetBSD。' },
      { v: 3, name: 'ELFOSABI_LINUX / GNU', desc: 'Linux / GNU 扩展。启用 GNU 特有语义，例如 .note.gnu.* 段、STT_GNU_IFUNC 符号类型。' },
      { v: 6, name: 'ELFOSABI_SOLARIS', desc: 'Sun Solaris。' },
      { v: 7, name: 'ELFOSABI_AIX', desc: 'IBM AIX。' },
      { v: 8, name: 'ELFOSABI_IRIX', desc: 'SGI IRIX。' },
      { v: 9, name: 'ELFOSABI_FREEBSD', desc: 'FreeBSD。' },
      { v: 10, name: 'ELFOSABI_TRU64', desc: 'Compaq TRU64 UNIX。' },
      { v: 11, name: 'ELFOSABI_MODESTO', desc: 'Novell Modesto。' },
      { v: 12, name: 'ELFOSABI_OPENBSD', desc: 'OpenBSD。' },
      { v: 13, name: 'ELFOSABI_OPENVMS', desc: 'OpenVMS。' },
      { v: 14, name: 'ELFOSABI_NSK', desc: 'Hewlett-Packard Non-Stop Kernel。' },
      { v: 15, name: 'ELFOSABI_AROS', desc: 'Amiga Research OS。' },
      { v: 16, name: 'ELFOSABI_FENIXOS', desc: 'FenixOS。' },
      { v: 17, name: 'ELFOSABI_CLOUDABI', desc: 'Nuxi CloudABI（能力式沙箱 ABI）。' },
      { v: 18, name: 'ELFOSABI_OPENVOS', desc: 'Stratus Technologies OpenVOS。' },
      { v: 64, name: 'ELFOSABI_ARM_AEABI', desc: 'ARM EABI 扩展。' },
      { v: 97, name: 'ELFOSABI_ARM', desc: 'ARM 传统 ABI。' },
      { v: 255, name: 'ELFOSABI_STANDALONE', desc: '独立（嵌入式）程序，无操作系统。裸机 RISC-V 固件常使用。' }
    ]
  },
  e_type: {
    title: 'e_type — 目标文件类型',
    abi: 'ELF 规范 (gABI 表 4-2)',
    desc: '决定链接器/加载器如何对待这个文件：是可重定位输入、可执行程序、共享库，还是内存转储。这是 ELF 解析中最重要的分支依据之一。',
    values: [
      { v: 0, name: 'ET_NONE', desc: '未知类型。文件头尚未被填充，通常说明文件损坏或不是 ELF。' },
      { v: 1, name: 'ET_REL', desc: '可重定位目标文件（.o）。地址字段为占位值（通常 0），代码中留有重定位项，需要链接器处理。段表是权威数据，程序头表通常不存在。' },
      { v: 2, name: 'ET_EXEC', desc: '可执行文件。e_entry 是绝对虚拟地址，程序头表描述加载映射，可直接被内核 exec 加载。' },
      { v: 3, name: 'ET_DYN', desc: '共享目标（.so / PIE 可执行）。代码按位置无关方式编译，加载时由动态链接器在基址上重定位。现代 Linux 默认的 PIE 可执行文件也是 ET_DYN。' },
      { v: 4, name: 'ET_CORE', desc: '核心转储 (core dump)。段表/程序头描述进程内存镜像，常用于事后调试。' },
      { v: 0xfe00, name: 'ET_LOOS … ET_HIOS (OS 相关)', desc: '0xfe00–0xfeff 保留给操作系统特定的目标类型。' },
      { v: 0xff00, name: 'ET_LOPROC … ET_HIPROC (处理器相关)', desc: '0xff00–0xffff 保留给处理器特定的目标类型。' }
    ]
  },
  e_machine: {
    title: 'e_machine — 目标指令集架构',
    abi: 'ELF 规范 + 各架构注册号',
    desc: '指定该文件所针对的 CPU 架构。反汇编器、链接器都依赖这个字段选择指令编码表。RISC-V 的注册号是 243 (0xF3)。',
    values: [
      { v: 0, name: 'EM_NONE', desc: '未指定架构。' },
      { v: 2, name: 'EM_SPARC', desc: 'Sun SPARC。' },
      { v: 3, name: 'EM_386', desc: 'Intel 80386 (x86 32 位)。' },
      { v: 4, name: 'EM_68K', desc: 'Motorola 68000。' },
      { v: 8, name: 'EM_MIPS', desc: 'MIPS R3000。' },
      { v: 20, name: 'EM_PPC', desc: 'PowerPC 32 位。' },
      { v: 21, name: 'EM_PPC64', desc: 'PowerPC 64 位。' },
      { v: 22, name: 'EM_S390', desc: 'IBM S/390 大型机。' },
      { v: 40, name: 'EM_ARM', desc: 'ARM 32 位（含 Thumb）。' },
      { v: 42, name: 'EM_SH', desc: 'SuperH (日立 SH)。' },
      { v: 50, name: 'EM_IA_64', desc: 'Intel Itanium。' },
      { v: 62, name: 'EM_X86_64', desc: 'AMD x86-64 / EM64T。' },
      { v: 83, name: 'EM_AVR', desc: 'Atmel AVR 8 位 MCU。' },
      { v: 92, name: 'EM_OPENRISC', desc: 'OpenRISC 1000。' },
      { v: 94, name: 'EM_AM33', desc: 'Mitsubishi AM33。' },
      { v: 106, name: 'EM_BLACKFIN', desc: 'ADI Blackfin。' },
      { v: 113, name: 'EM_ALTERA_NIOS2', desc: 'Altera Nios II。' },
      { v: 164, name: 'EM_ALPHA', desc: 'Digital Alpha。' },
      { v: 183, name: 'EM_AARCH64', desc: 'ARM 64 位 (AArch64)。' },
      { v: 186, name: 'EM_CSKY', desc: 'C-SKY 国产嵌入式架构。' },
      { v: 189, name: 'EM_MICROBLAZE', desc: 'Xilinx MicroBlaze 软核。' },
      { v: 190, name: 'EM_CUDA', desc: 'NVIDIA CUDA GPU 二进制。' },
      { v: 243, name: 'EM_RISCV', desc: 'RISC-V。指令长度可变（16 位压缩指令 C 扩展 + 32 位基础指令），因此反汇编必须逐条判断长度，不能简单按 4 字节切分。' },
      { v: 247, name: 'EM_BPF', desc: 'Linux eBPF。' },
      { v: 258, name: 'EM_LOONGARCH', desc: 'LoongArch 国产架构。' }
    ]
  },
  e_version: {
    title: 'e_version — 文件版本',
    abi: 'ELF 规范 (gABI 4.2)',
    desc: '标识目标文件的总体版本。',
    values: [
      { v: 0, name: 'EV_NONE', desc: '无效版本。' },
      { v: 1, name: 'EV_CURRENT', desc: '当前版本。所有现代工具链都产生 1。' }
    ]
  },
  sh_type: {
    title: 'sh_type — 段（Section）类型',
    abi: 'ELF 规范 (gABI 表 4-4)',
    desc: '决定节区内容如何解释以及链接器如何处理它。PROGBITS 是普通数据；NOBITS 表示占有内存但不占文件空间（.bss）；SYMTAB/STRTAB 等是元数据表。',
    values: [
      { v: 0, name: 'SHT_NULL', desc: '无效段头，下标 0 固定为此类型，其所有字段为 0。程序用它表示「无关联段」。' },
      { v: 1, name: 'SHT_PROGBITS', desc: '程序定义的数据：机器码、字符串字面量、只读常量等。具体含义由段名约定。' },
      { v: 2, name: 'SHT_SYMTAB', desc: '完整符号表（静态符号表）。link 指向字符串表段，info 指示第一个全局符号的索引。' },
      { v: 3, name: 'SHT_STRTAB', desc: '字符串表。以 \\0 分隔的字节串集合，供符号名、段名等以偏移方式引用。' },
      { v: 4, name: 'SHT_RELA', desc: '带显式加数的重定位表（Elf32_Rela/Elf64_Rela）。RISC-V 与 x86-64 都使用此形式。' },
      { v: 5, name: 'SHT_HASH', desc: '符号哈希表，供动态链接器快速查符号。' },
      { v: 6, name: 'SHT_DYNAMIC', desc: '动态链接信息（.dynamic），是一串 Elf32_Dyn/Elf64_Dyn 条目，详见 DT_* 枚举。' },
      { v: 7, name: 'SHT_NOTE', desc: '附注信息，由「名字 + 类型 + 描述」三元组构成，用于 .note.gnu.build-id、ABI 标签等。' },
      { v: 8, name: 'SHT_NOBITS', desc: '在文件中不占空间、但加载后占用内存的段（典型：.bss）。因此 sh_offset 仅表示「假如有数据会放在哪」，此时该偏移不能用于读取文件字节。' },
      { v: 9, name: 'SHT_REL', desc: '不带加数的重定位表（Elf32_Rel）。' },
      { v: 10, name: 'SHT_SHLIB', desc: '保留类型。' },
      { v: 11, name: 'SHT_DYNSYM', desc: '动态符号表（.dynsym），只包含运行期可见的符号，必须保持可被 ELF 加载器引用。' },
      { v: 14, name: 'SHT_INIT_ARRAY', desc: '构造函数指针数组，在 main 之前逐个调用（.init_array）。' },
      { v: 15, name: 'SHT_FINI_ARRAY', desc: '析构函数指针数组（.fini_array）。' },
      { v: 16, name: 'SHT_PREINIT_ARRAY', desc: '可执行文件中最早执行的构造数组（.preinit_array）。' },
      { v: 17, name: 'SHT_GROUP', desc: '段组，把若干段绑定在一起（COMDAT 去重），常与 SHT_SYMTAB_SHNDX 联用。' },
      { v: 18, name: 'SHT_SYMTAB_SHNDX', desc: '扩展段索引表。当段索引超过 SHN_LORESERVE 时，符号的 st_shndx 存 SHN_XINDEX 并在此表查真实值。' },
      { v: 19, name: 'SHT_RELR', desc: '压缩重定位表（RELR），用位图形式表达相对重定位，体积远小于传统 RELA。' },
      { v: 0x6ffffff6, name: 'SHT_GNU_HASH', desc: 'GNU 扩展哈希表。使用布隆过滤器提升动态符号查找速度。' },
      { v: 0x6ffffffd, name: 'SHT_GNU_VERDEF', desc: '符号版本定义 (.gnu.version_d)。' },
      { v: 0x6ffffffe, name: 'SHT_GNU_VERNEED', desc: '符号版本需求 (.gnu.version_r)。' },
      { v: 0x6fffffff, name: 'SHT_GNU_VERSYM', desc: '符号版本索引 (.gnu.version)。' },
      { v: 0x70000000, name: 'SHT_LOPROC … SHT_HIPROC', desc: '处理器特定段类型区间（0x70000000–0x7fffffff）。例如 .riscv.attributes 使用 0x70000003。' },
      { v: 0x70000003, name: 'SHT_RISCV_ATTRIBUTES', desc: 'RISC-V 属性段的实际取值（落在 SHT_LOPROC 处理器特定区间内）。内容记录该目标文件要求/提供的 ISA 扩展字符串，链接器据此判断互操作性。' },
      { v: 0x80000000, name: 'SHT_LOUSER … SHT_HIUSER', desc: '应用程序可自由使用的段类型区间。' }
    ]
  },
  sh_flags: {
    title: 'sh_flags — 段属性标志位',
    abi: 'ELF 规范 (gABI 表 4-5)',
    desc: '位掩码。每一位独立含义，可组合出现，因此解析时应当逐位测试而不是整数值匹配。',
    mask: true,
    values: [
      { v: 0x1, name: 'SHF_WRITE', desc: '该段在进程内存中可写（→ .data、.bss）。' },
      { v: 0x2, name: 'SHF_ALLOC', desc: '该段在进程运行时占用内存，会被加载器映射。未置位的段（如 .comment、.debug_*、符号表）只存在于文件里。' },
      { v: 0x4, name: 'SHF_EXECINSTR', desc: '该段包含可执行机器码（→ .text）。反汇编器据此挑选候选段。' },
      { v: 0x10, name: 'SHF_MERGE', desc: '段内数据元素可被合并去重（典型：字符串字面量、常量表）。entsize 给出元素大小。' },
      { v: 0x20, name: 'SHF_STRINGS', desc: '段内是 \\0 结尾的字符串序列，配合 MERGE 使用。' },
      { v: 0x40, name: 'SHF_INFO_LINK', desc: 'sh_info 字段被解释为段索引（而非其它含义）。' },
      { v: 0x80, name: 'SHF_LINK_ORDER', desc: '段之间存在链接顺序约束，sh_link 指出相关段。' },
      { v: 0x100, name: 'SHF_OS_NONCONFORMING', desc: '含 OS 特定的非常规语义，不遵循标准链接规则。' },
      { v: 0x200, name: 'SHF_GROUP', desc: '该段是一个段组成员，通常只被链接器读取。' },
      { v: 0x400, name: 'SHF_TLS', desc: '线程局部存储段（→ .tdata、.tbss）。' },
      { v: 0x800, name: 'SHF_COMPRESSED', desc: '段内容以 zlib 压缩。段头后跟一个 Elf64_Chdr 描述压缩算法与原始大小。' },
      { v: 0x0ff00000, name: 'SHF_MASKOS', desc: '操作系统特定标志位掩码区间。' },
      { v: 0x40000000, name: 'SHF_ORDERED', desc: 'Solaris 扩展：链接器按 sh_link 顺序排列段。' },
      { v: 0xf0000000, name: 'SHF_MASKPROC', desc: '处理器特定标志位掩码区间。' }
    ]
  },
  p_type: {
    title: 'p_type — 程序段（Segment）类型',
    abi: 'ELF 规范 (gABI 表 5-1)',
    desc: '程序头表描述「运行时期的内存映像」。内核加载器只关心 PT_LOAD；动态链接器关心 PT_DYNAMIC / PT_INTERP；调试器关心 PT_NOTE。',
    values: [
      { v: 0, name: 'PT_NULL', desc: '未使用的表项，应被忽略。' },
      { v: 1, name: 'PT_LOAD', desc: '可加载段。把文件 offset..offset+filesz 映射到虚拟地址 p_vaddr，并把 memsz-filesz 部分清零（→ .bss）。p_flags 决定映射权限。' },
      { v: 2, name: 'PT_DYNAMIC', desc: '动态链接信息段，内容为 .dynamic。只有存在此段，文件才需要/允许动态链接器介入。' },
      { v: 3, name: 'PT_INTERP', desc: '解释器路径（如 /lib/ld-linux-riscv64-lp64d.so.1），以 \\0 结尾的字符串。内核据此决定启动哪个动态链接器。' },
      { v: 4, name: 'PT_NOTE', desc: '附注信息段（ABI 标签、build-id、core 寄存器状态等）。' },
      { v: 5, name: 'PT_SHLIB', desc: '保留类型，未定义语义。' },
      { v: 6, name: 'PT_PHDR', desc: '程序头表自身在内存中的位置。用于加载器自举，常见于 PIE。' },
      { v: 7, name: 'PT_TLS', desc: '线程局部存储模板段。' },
      { v: 0x60000000, name: 'PT_LOOS … PT_HIOS', desc: '操作系统特定区间。' },
      { v: 0x6474e550, name: 'PT_GNU_EH_FRAME', desc: 'GNU 异常处理帧信息 (.eh_frame_hdr)，供 C++ 异常展开与栈回溯使用。' },
      { v: 0x6474e551, name: 'PT_GNU_STACK', desc: '标记栈是否可执行。现代内核据此拒绝执行栈（NX）。' },
      { v: 0x6474e552, name: 'PT_GNU_RELRO', desc: 'Read-Only After Relocation：动态重定位完成后，把该区域内存改为只读，是 GOT 覆盖攻击的主要缓解手段。' },
      { v: 0x6474e553, name: 'PT_GNU_PROPERTY', desc: 'GNU 属性段 (.note.gnu.property)，用于传递 CET 等硬件特性需求。' },
      { v: 0x70000000, name: 'PT_LOPROC … PT_HIPROC', desc: '处理器特定区间（0x70000000–0x7fffffff）。' }
    ]
  },
  p_flags: {
    title: 'p_flags — 程序段内存权限',
    abi: 'ELF 规范 (gABI 表 5-2)',
    desc: '位掩码，描述加载后页表项的权限位（对应 mmap 的 PROT_*）。',
    mask: true,
    values: [
      { v: 0x1, name: 'PF_X', desc: '可执行 (PROT_EXEC)。' },
      { v: 0x2, name: 'PF_W', desc: '可写 (PROT_WRITE)。' },
      { v: 0x4, name: 'PF_R', desc: '可读 (PROT_READ)。' },
      { v: 0xf0000000, name: 'PF_MASKOS', desc: 'OS 特定标志位区间。' },
      { v: 0x0ff00000, name: 'PF_MASKPROC', desc: '处理器特定标志位区间。' }
    ]
  },
  st_info: {
    title: 'st_info — 符号绑定与类型（打包字节）',
    abi: 'ELF 规范 (gABI 表 4-6 / 4-7)',
    desc: '只有 1 个字节，却要同时表达两件事，于是 gABI 把它一分为二：高 4 位是绑定属性 bind（符号的作用域），低 4 位是类型 type（符号指代什么）。' +
      '解析时必须先做位运算拆分——直接把这个字节当成一个整数去查表是最常见的误读。',
    parts: [
      { name: 'st_bind', bits: 'bit 7–4', enum: 'st_bind', desc: '右移 4 位：(st_info >> 4) & 0xF' },
      { name: 'st_type', bits: 'bit 3–0', enum: 'st_type', desc: '取低 4 位：st_info & 0xF' }
    ],
    values: []
  },
  st_bind: {
    title: 'st_bind — 符号绑定属性（st_info 高 4 位）',
    abi: 'ELF 规范 (gABI 表 4-6)',
    desc: '描述符号的「链接可见性」：只有 LOCAL 与 GLOBAL/WEAK 的区别会直接影响链接结果。',
    values: [
      { v: 0, name: 'STB_LOCAL', desc: '局部符号，仅在定义它的目标文件内可见（如 static 函数、.L 标签）。链接器不会用它去满足其它文件的引用。' },
      { v: 1, name: 'STB_GLOBAL', desc: '全局符号，可被其它目标文件引用并解析。' },
      { v: 2, name: 'STB_WEAK', desc: '弱符号。存在同名强符号时被覆盖；未定义也不报错，而是解析为 0。' },
      { v: 10, name: 'STB_GNU_UNIQUE', desc: 'GNU 扩展：唯一符号，保证整个进程中只有一个实例（用于 C++ 模板静态成员、内联函数的局部静态变量）。' },
      { v: 12, name: 'STB_HIOS (OS 特定区间上界)', desc: '0xa–0xc 为操作系统特定绑定属性。' },
      { v: 13, name: 'STB_LOPROC … STB_HIPROC', desc: '0xd–0xf 保留给处理器特定用途。' }
    ]
  },
  st_type: {
    title: 'st_type — 符号类型（st_info 低 4 位）',
    abi: 'ELF 规范 (gABI 表 4-7)',
    desc: '描述符号指代的对象种类。反汇编与反编译工具主要靠 STT_FUNC 找出函数入口，靠 STT_OBJECT 找出数据对象。',
    values: [
      { v: 0, name: 'STT_NOTYPE', desc: '类型未指定，通常是汇编器产生的普通标签。' },
      { v: 1, name: 'STT_OBJECT', desc: '数据对象：变量、数组、结构体。' },
      { v: 2, name: 'STT_FUNC', desc: '函数或可执行代码目标。本工具会为这类符号生成可跳转的反汇编入口。' },
      { v: 3, name: 'STT_SECTION', desc: '与某个段关联的符号，值为段基址，重定位中引用段时使用。' },
      { v: 4, name: 'STT_FILE', desc: '源文件名（通常是 .c 文件），绑定必为 LOCAL、段索引为 SHN_ABS。' },
      { v: 5, name: 'STT_COMMON', desc: '未初始化的公共数据块，语义类似 SHN_COMMON。' },
      { v: 6, name: 'STT_TLS', desc: '线程局部存储对象。st_value 是 TLS 块内偏移而非虚拟地址。' },
      { v: 10, name: 'STT_GNU_IFUNC', desc: 'GNU 扩展：间接函数。st_value 指向一个「返回真实函数地址」的解析器，用于运行期按 CPU 特性选择最优实现（如 memcpy 的 SIMD 版本）。' }
    ]
  },
  st_other: {
    title: 'st_other — 符号可见性',
    abi: 'ELF 规范 (gABI 表 4-8)',
    desc: '低 2 位为可见性 (visibility)，其余位保留。可见性影响动态链接器能否在其它模块中解析该符号。',
    values: [
      { v: 0, name: 'STV_DEFAULT', desc: '默认：符号在定义模块之外可见，可被抢占/插入。' },
      { v: 1, name: 'STV_INTERNAL', desc: '内部：处理器特定的隐藏语义，等同 HIDDEN 但更严格。' },
      { v: 2, name: 'STV_HIDDEN', desc: '隐藏：符号不导出到动态符号表，其它模块不可见（对应 __attribute__((visibility("hidden")))）。' },
      { v: 3, name: 'STV_PROTECTED', desc: '保护：在本模块内引用必定绑定到本模块定义，但外部仍可见，可减少 GOT 间接跳转。' }
    ]
  },
  st_shndx: {
    title: 'st_shndx — 符号所属段索引（特殊值）',
    abi: 'ELF 规范 (gABI 表 4-9)',
    desc: '通常是一个从 0 开始的段表下标。若干特殊值带有附加语义。',
    values: [
      { v: 0, name: 'SHN_UNDEF', desc: '未定义符号。本文件引用但未在本文件定义，需要在链接期或运行期由其它模块提供。' },
      { v: 0xfff1, name: 'SHN_ABS', desc: '绝对值符号。st_value 是常量而非地址，重定位时不参与基址计算（例如 STT_FILE 符号）。' },
      { v: 0xfff2, name: 'SHN_COMMON', desc: '公共块（Fortran COMMON / C 的 -fcommon 未初始化全局变量）。分配由链接器完成，st_value 给出对齐要求。' },
      { v: 0xffff, name: 'SHN_XINDEX', desc: '真实段索引超过 0xFFFF，实际值存放在 SHT_SYMTAB_SHNDX 段中对应位置。' },
      { v: 0xff00, name: 'SHN_LORESERVE … SHN_HIRESERVE', desc: '0xff00–0xffff 为保留值区间，普通段索引不可使用。' }
    ]
  },
  riscv_e_flags: {
    title: 'e_flags — RISC-V 处理器特定标志',
    abi: 'RISC-V ELF psABI',
    desc: 'RISC-V 把「压缩指令支持」「浮点 ABI」「嵌入式变体」等信息编码在 e_flags 中。链接器检查这些位以判断目标文件能否互相链接。',
    mask: true,
    values: [
      { v: 0x0001, name: 'EF_RISCV_RVC', desc: '目标文件包含压缩（16 位）指令，即使用了 C 扩展。链接时必须确保最终目标也启用 C 扩展。反汇编器据此判断可以按 16 位切分。' },
      { v: 0x0002, name: 'EF_RISCV_FLOAT_ABI_SOFT', desc: '软浮点 ABI：浮点参数通过整数寄存器传递。' },
      { v: 0x0004, name: 'EF_RISCV_FLOAT_ABI_DOUBLE', desc: '双精度硬浮点 ABI (lp64d / ilp32d)。' },
      { v: 0x0006, name: 'EF_RISCV_FLOAT_ABI_QUAD', desc: '四精度硬浮点 ABI。' },
      { v: 0x0008, name: 'EF_RISCV_RVE', desc: '嵌入式变体 RV32E：只有 16 个整数寄存器（x0–x15）。' },
      { v: 0x0010, name: 'EF_RISCV_TSO', desc: '目标使用 Total Store Ordering 内存模型（Ztso 扩展）。' },
      { v: 0x0020, name: 'EF_RISCV_TAGGED_ADDR_ABI', desc: '启用标记地址 ABI（用于内存安全扩展）。' },
      { v: 0x0100, name: 'EF_RISCV_RVC_ISA_SPEC 2.0', desc: '压缩指令扩展规范版本 2.0。' },
      { v: 0x0200, name: 'EF_RISCV_RVC_ISA_SPEC 2.1', desc: '压缩指令扩展规范版本 2.1。' },
      { v: 0x0300, name: 'EF_RISCV_RVC_ISA_SPEC 2.2', desc: '压缩指令扩展规范版本 2.2（当前主流，GCC/LLVM 默认）。' }
    ]
  },
  DT_tag: {
    title: 'DT_* — 动态表条目类型',
    abi: 'ELF 规范 (gABI 表 5-9) 与 GNU 扩展',
    desc: '.dynamic 段是一串「标签 + 值」对，由动态链接器在运行期读取，描述依赖库、重定位表位置、符号表位置、初始化函数等。',
    values: [
      { v: 0, name: 'DT_NULL', desc: '动态表结束标记，必须存在。' },
      { v: 1, name: 'DT_NEEDED', desc: '依赖的共享库名，值是 .dynstr 中的偏移。' },
      { v: 2, name: 'DT_PLTRELSZ', desc: 'PLT 重定位表总字节数。' },
      { v: 3, name: 'DT_PLTGOT', desc: '.got.plt 的地址。' },
      { v: 4, name: 'DT_HASH', desc: '符号哈希表地址。' },
      { v: 5, name: 'DT_STRTAB', desc: '动态字符串表 (.dynstr) 地址。' },
      { v: 6, name: 'DT_SYMTAB', desc: '动态符号表 (.dynsym) 地址。' },
      { v: 7, name: 'DT_RELA', desc: '重定位表地址。' },
      { v: 8, name: 'DT_RELASZ', desc: '重定位表字节数。' },
      { v: 9, name: 'DT_RELAENT', desc: '单个重定位项大小（RISC-V/x86-64 为 24 字节）。' },
      { v: 10, name: 'DT_STRSZ', desc: '字符串表大小。' },
      { v: 11, name: 'DT_SYMENT', desc: '符号项大小。' },
      { v: 12, name: 'DT_INIT', desc: '初始化函数地址。' },
      { v: 13, name: 'DT_FINI', desc: '终结函数地址。' },
      { v: 14, name: 'DT_SONAME', desc: '本共享库的名字。' },
      { v: 15, name: 'DT_RPATH', desc: '库搜索路径（已废弃，被 RUNPATH 取代）。' },
      { v: 16, name: 'DT_SYMBOLIC', desc: '优先在自身模块内查找符号。' },
      { v: 17, name: 'DT_REL', desc: '不带加数的重定位表地址。' },
      { v: 18, name: 'DT_RELSZ', desc: 'DT_REL 表大小。' },
      { v: 19, name: 'DT_RELENT', desc: 'DT_REL 项大小。' },
      { v: 20, name: 'DT_PLTREL', desc: 'PLT 重定位使用的是 REL 还是 RELA。' },
      { v: 21, name: 'DT_DEBUG', desc: '调试信息地址，由动态链接器填写。' },
      { v: 22, name: 'DT_TEXTREL', desc: '存在对只读段的文本重定位，需要临时放开写权限。' },
      { v: 23, name: 'DT_JMPREL', desc: 'PLT 重定位表地址。' },
      { v: 24, name: 'DT_BIND_NOW', desc: '立即绑定所有符号，不做惰性解析。' },
      { v: 25, name: 'DT_INIT_ARRAY', desc: '构造数组地址。' },
      { v: 26, name: 'DT_FINI_ARRAY', desc: '析构数组地址。' },
      { v: 27, name: 'DT_INIT_ARRAYSZ', desc: '构造数组大小。' },
      { v: 28, name: 'DT_FINI_ARRAYSZ', desc: '析构数组大小。' },
      { v: 29, name: 'DT_RUNPATH', desc: '运行期库搜索路径。' },
      { v: 30, name: 'DT_FLAGS', desc: '标志位集合。' },
      { v: 0x6ffffef5, name: 'DT_GNU_HASH', desc: 'GNU 哈希表地址。' },
      { v: 0x6ffffff0, name: 'DT_VERSYM', desc: '符号版本索引表地址。' },
      { v: 0x6ffffff9, name: 'DT_RELACOUNT', desc: '开头有多少个 RELATIVE 重定位，可批量处理。' },
      { v: 0x6ffffffa, name: 'DT_RELCOUNT', desc: 'REL 版本的相对重定位计数。' },
      { v: 0x6ffffffb, name: 'DT_FLAGS_1', desc: '扩展标志位（PIE、NOW 等）。' },
      { v: 0x6ffffffc, name: 'DT_VERDEF', desc: '版本定义表地址。' },
      { v: 0x6ffffffe, name: 'DT_VERNEED', desc: '版本需求表地址。' },
      { v: 0x6fffffff, name: 'DT_VERNEEDNUM', desc: '版本需求条目数量。' }
    ]
  },
  R_RISCV: {
    title: 'R_RISCV_* — RISC-V 重定位类型',
    abi: 'RISC-V ELF psABI 表 3',
    desc: 'RISC-V 的一条指令由两条重定位配合修补：HI20 负责装载目标地址的高 20 位，LO12 负责低 12 位。这解决了立即数在 32 位定长指令中无法直接容纳完整地址的问题。',
    values: [
      { v: 0, name: 'R_RISCV_NONE', desc: '无操作。' },
      { v: 1, name: 'R_RISCV_32', desc: '写入一个 32 位绝对地址（需要动态重定位）。' },
      { v: 2, name: 'R_RISCV_64', desc: '写入一个 64 位绝对地址（需要动态重定位）。' },
      { v: 3, name: 'R_RISCV_RELATIVE', desc: '写入 load_base + addend，位置无关代码的基址重定位。' },
      { v: 4, name: 'R_RISCV_COPY', desc: '运行期从共享库复制符号数据到本模块。' },
      { v: 5, name: 'R_RISCV_JUMP_SLOT', desc: 'PLT/GOT 跳转槽，绑定后写入目标函数真实地址。' },
      { v: 6, name: 'R_RISCV_TLS_DTPMOD32', desc: '32 位 TLS 模块 ID。' },
      { v: 7, name: 'R_RISCV_TLS_DTPMOD64', desc: '64 位 TLS 模块 ID。' },
      { v: 8, name: 'R_RISCV_TLS_DTPREL32', desc: '32 位 TLS 块内偏移。' },
      { v: 9, name: 'R_RISCV_TLS_DTPREL64', desc: '64 位 TLS 块内偏移。' },
      { v: 10, name: 'R_RISCV_TLS_TPREL32', desc: '32 位线程指针相对偏移。' },
      { v: 11, name: 'R_RISCV_TLS_TPREL64', desc: '64 位线程指针相对偏移。' },
      { v: 12, name: 'R_RISCV_TLSDESC', desc: 'TLS 描述符重定位。' },
      { v: 16, name: 'R_RISCV_BRANCH', desc: '条件分支指令的 12 位 PC 相对偏移（如 beq/bne）。' },
      { v: 17, name: 'R_RISCV_JAL', desc: 'jal 指令的 20 位 PC 相对偏移。' },
      { v: 18, name: 'R_RISCV_CALL', desc: '将 lui+jalr 组合视作一次调用并修补，配合 LO12 使用。' },
      { v: 19, name: 'R_RISCV_CALL_PLT', desc: '指向 PLT 的调用重定位。' },
      { v: 20, name: 'R_RISCV_GOT_HI20', desc: 'GOT 表项的 AUIPC 高位地址。' },
      { v: 21, name: 'R_RISCV_TLS_GOT_HI20', desc: 'TLS GOT 高位地址。' },
      { v: 22, name: 'R_RISCV_TLS_GD_HI20', desc: 'TLS 通用动态模型高位地址。' },
      { v: 23, name: 'R_RISCV_PCREL_HI20', desc: 'PC 相对高 20 位（auipc 指令）。' },
      { v: 24, name: 'R_RISCV_PCREL_LO12_I', desc: 'PC 相对低 12 位，I 型指令（addi/lw）。' },
      { v: 25, name: 'R_RISCV_PCREL_LO12_S', desc: 'PC 相对低 12 位，S 型指令（sw）。' },
      { v: 26, name: 'R_RISCV_HI20', desc: '绝对地址高 20 位（lui 指令）。' },
      { v: 27, name: 'R_RISCV_LO12_I', desc: '绝对地址低 12 位，I 型。' },
      { v: 28, name: 'R_RISCV_LO12_S', desc: '绝对地址低 12 位，S 型。' },
      { v: 29, name: 'R_RISCV_TPREL_HI20', desc: '线程指针相对高 20 位。' },
      { v: 30, name: 'R_RISCV_TPREL_LO12_I', desc: '线程指针相对低 12 位（I 型）。' },
      { v: 31, name: 'R_RISCV_TPREL_LO12_S', desc: '线程指针相对低 12 位（S 型）。' },
      { v: 32, name: 'R_RISCV_TPREL_ADD', desc: 'TLS 地址加法修正。' },
      { v: 33, name: 'R_RISCV_ADD8', desc: '字节级加运算（调试信息常用）。' },
      { v: 34, name: 'R_RISCV_ADD16', desc: '16 位加运算。' },
      { v: 35, name: 'R_RISCV_ADD32', desc: '32 位加运算。' },
      { v: 36, name: 'R_RISCV_ADD64', desc: '64 位加运算。' },
      { v: 37, name: 'R_RISCV_SUB8', desc: '字节级减运算。' },
      { v: 38, name: 'R_RISCV_SUB16', desc: '16 位减运算。' },
      { v: 39, name: 'R_RISCV_SUB32', desc: '32 位减运算。' },
      { v: 40, name: 'R_RISCV_SUB64', desc: '64 位减运算。' },
      { v: 43, name: 'R_RISCV_ALIGN', desc: '对齐填充重定位：链接器可能调整指令数量以满足对齐，从而改变后续地址。' },
      { v: 44, name: 'R_RISCV_RVC_BRANCH', desc: '压缩格式条件分支偏移。' },
      { v: 45, name: 'R_RISCV_RVC_JUMP', desc: '压缩格式跳转偏移（c.j）。' },
      { v: 51, name: 'R_RISCV_RELAX', desc: '标记该重定位可被松弛优化（如把 auipc+addi 序列缩短）。' },
      { v: 52, name: 'R_RISCV_SUB6', desc: '6 位减运算。' },
      { v: 53, name: 'R_RISCV_SET6', desc: '6 位赋值。' },
      { v: 54, name: 'R_RISCV_SET8', desc: '字节赋值。' },
      { v: 55, name: 'R_RISCV_SET16', desc: '16 位赋值。' },
      { v: 56, name: 'R_RISCV_SET32', desc: '32 位赋值。' },
      { v: 57, name: 'R_RISCV_32_PCREL', desc: '32 位 PC 相对重定位。' }
    ]
  },
  R_X86_64: {
    title: 'R_X86_64_* — x86-64 重定位类型',
    abi: 'x86-64 psABI 表 4.10',
    desc: 'x86-64 的重定位类型。常见于 .rela.text（静态链接）与 .rela.dyn（动态链接）。',
    values: [
      { v: 0, name: 'R_X86_64_NONE', desc: '无操作。' },
      { v: 1, name: 'R_X86_64_64', desc: '写入 64 位绝对地址。' },
      { v: 2, name: 'R_X86_64_PC32', desc: '32 位 PC 相对偏移，最常见于 call/jmp 的立即数修补。' },
      { v: 4, name: 'R_X86_64_PLT32', desc: '32 位 PLT 相对偏移，用于调用外部函数。' },
      { v: 5, name: 'R_X86_64_COPY', desc: '运行期复制符号数据。' },
      { v: 6, name: 'R_X86_64_GLOB_DAT', desc: 'GOT 中的全局数据地址。' },
      { v: 7, name: 'R_X86_64_JUMP_SLOT', desc: 'PLT 跳转槽地址。' },
      { v: 8, name: 'R_X86_64_RELATIVE', desc: 'load_base + addend，位置无关基址重定位。' },
      { v: 9, name: 'R_X86_64_GOTPCREL', desc: 'GOT 表项的 PC 相对地址。' },
      { v: 10, name: 'R_X86_64_32', desc: '32 位绝对地址（零扩展）。' },
      { v: 11, name: 'R_X86_64_32S', desc: '32 位绝对地址（符号扩展）。' },
      { v: 16, name: 'R_X86_64_DTPMOD64', desc: 'TLS 模块 ID。' },
      { v: 17, name: 'R_X86_64_DTPOFF64', desc: 'TLS 块内偏移。' },
      { v: 18, name: 'R_X86_64_TPOFF64', desc: '线程指针相对偏移。' },
      { v: 37, name: 'R_X86_64_IRELATIVE', desc: '间接重定位，调用解析函数得到真实地址。' }
    ]
  }
};

/* --------------------------------------------------------------------------
 * ELF 头部字段布局与文档（既用于静态显示，也用于 Hex 字节 → 字段名映射）
 * ------------------------------------------------------------------------*/
const EHDR_FIELDS = {
  32: [
    { name: 'e_ident[EI_MAG0]', off: 0, size: 1, desc: '魔数第 1 字节，固定为 0x7F。' },
    { name: 'e_ident[EI_MAG1]', off: 1, size: 1, desc: "魔数第 2 字节，固定为 'E' (0x45)。" },
    { name: 'e_ident[EI_MAG2]', off: 2, size: 1, desc: "魔数第 3 字节，固定为 'L' (0x4C)。" },
    { name: 'e_ident[EI_MAG3]', off: 3, size: 1, desc: "魔数第 4 字节，固定为 'F' (0x46)。四字节合起来是 0x7F 'E' 'L' 'F'，用于快速识别文件格式。" },
    { name: 'e_ident[EI_CLASS]', off: 4, size: 1, enum: 'EI_CLASS', desc: '文件类别：32 位 / 64 位。' },
    { name: 'e_ident[EI_DATA]', off: 5, size: 1, enum: 'EI_DATA', desc: '数据编码：小端 / 大端。' },
    { name: 'e_ident[EI_VERSION]', off: 6, size: 1, enum: 'EI_VERSION', desc: 'ELF 头版本，恒为 1。' },
    { name: 'e_ident[EI_OSABI]', off: 7, size: 1, enum: 'EI_OSABI', desc: '目标操作系统 ABI。' },
    { name: 'e_ident[EI_ABIVERSION]', off: 8, size: 1, desc: 'ABI 版本号，配合 EI_OSABI 使用。' },
    { name: 'e_ident[EI_PAD]', off: 9, size: 7, desc: '填充字节，保留供将来使用，通常全为 0。' },
    { name: 'e_type', off: 16, size: 2, enum: 'e_type', desc: '目标文件类型：ET_REL / ET_EXEC / ET_DYN / ET_CORE。' },
    { name: 'e_machine', off: 18, size: 2, enum: 'e_machine', desc: '目标架构。RISC-V 为 243。' },
    { name: 'e_version', off: 20, size: 4, enum: 'e_version', desc: '文件版本，恒为 1。' },
    { name: 'e_entry', off: 24, size: 4, desc: '程序入口的虚拟地址。对 ET_EXEC 是绝对地址；对 ET_DYN/PIE 是相对基址的偏移，加载时加上 load base。' },
    { name: 'e_phoff', off: 28, size: 4, desc: '程序头表在文件中的偏移。0 表示没有程序头表（典型 ET_REL）。' },
    { name: 'e_shoff', off: 32, size: 4, desc: '段头表在文件中的偏移。0 表示没有段表。' },
    { name: 'e_flags', off: 36, size: 4, enum: 'riscv_e_flags', desc: '处理器特定标志（含义依赖 e_machine）。' },
    { name: 'e_ehsize', off: 40, size: 2, desc: 'ELF 头本身的大小，32 位文件为 52 字节。' },
    { name: 'e_phentsize', off: 42, size: 2, desc: '单个程序头的大小，32 位文件为 32 字节。' },
    { name: 'e_phnum', off: 44, size: 2, desc: '程序头数量。若为 0xFFFF 需查段 0 的 sh_info。' },
    { name: 'e_shentsize', off: 46, size: 2, desc: '单个段头的大小，32 位文件为 40 字节。' },
    { name: 'e_shnum', off: 48, size: 2, desc: '段头数量。若为 0 且 e_shoff 非 0，真实值在段 0 的 sh_size 中。' },
    { name: 'e_shstrndx', off: 50, size: 2, desc: '段名字符串表 (.shstrtab) 所在的段索引。若为 SHN_XINDEX(0xFFFF)，真实值在段 0 的 sh_link 中。' }
  ],
  64: [
    { name: 'e_ident[EI_MAG0]', off: 0, size: 1, desc: '魔数第 1 字节，固定为 0x7F。' },
    { name: 'e_ident[EI_MAG1]', off: 1, size: 1, desc: "魔数第 2 字节 'E'。" },
    { name: 'e_ident[EI_MAG2]', off: 2, size: 1, desc: "魔数第 3 字节 'L'。" },
    { name: 'e_ident[EI_MAG3]', off: 3, size: 1, desc: "魔数第 4 字节 'F'。0x7F454C46 使 file(1) 与加载器可以秒级判定格式。" },
    { name: 'e_ident[EI_CLASS]', off: 4, size: 1, enum: 'EI_CLASS', desc: '文件类别（此处为 ELFCLASS64）。' },
    { name: 'e_ident[EI_DATA]', off: 5, size: 1, enum: 'EI_DATA', desc: '数据编码。RISC-V 通常为小端。' },
    { name: 'e_ident[EI_VERSION]', off: 6, size: 1, enum: 'EI_VERSION', desc: 'ELF 头版本。' },
    { name: 'e_ident[EI_OSABI]', off: 7, size: 1, enum: 'EI_OSABI', desc: 'OS/ABI 标识。' },
    { name: 'e_ident[EI_ABIVERSION]', off: 8, size: 1, desc: 'ABI 版本号。' },
    { name: 'e_ident[EI_PAD]', off: 9, size: 7, desc: '填充，保留字节。' },
    { name: 'e_type', off: 16, size: 2, enum: 'e_type', desc: '目标文件类型。' },
    { name: 'e_machine', off: 18, size: 2, enum: 'e_machine', desc: '目标架构。' },
    { name: 'e_version', off: 20, size: 4, enum: 'e_version', desc: '文件版本。' },
    { name: 'e_entry', off: 24, size: 8, desc: '入口虚拟地址。64 位 ELF 中该字段被放到 8 字节对齐位置（紧随 e_version 之后）。' },
    { name: 'e_phoff', off: 32, size: 8, desc: '程序头表文件偏移。' },
    { name: 'e_shoff', off: 40, size: 8, desc: '段头表文件偏移。' },
    { name: 'e_flags', off: 48, size: 4, enum: 'riscv_e_flags', desc: '处理器特定标志。' },
    { name: 'e_ehsize', off: 52, size: 2, desc: 'ELF 头大小，64 位文件为 64 字节。' },
    { name: 'e_phentsize', off: 54, size: 2, desc: '单个程序头大小，64 位文件为 56 字节。' },
    { name: 'e_phnum', off: 56, size: 2, desc: '程序头数量。' },
    { name: 'e_shentsize', off: 58, size: 2, desc: '单个段头大小，64 位文件为 64 字节。' },
    { name: 'e_shnum', off: 60, size: 2, desc: '段头数量。' },
    { name: 'e_shstrndx', off: 62, size: 2, desc: '段名表索引。' }
  ]
};

/* 程序头字段布局 */
const PHDR_FIELDS = {
  32: [
    { name: 'p_type', off: 0, size: 4, enum: 'p_type', desc: '段类型。' },
    { name: 'p_offset', off: 4, size: 4, desc: '段内容在文件中的偏移。' },
    { name: 'p_vaddr', off: 8, size: 4, desc: '段的虚拟地址。' },
    { name: 'p_paddr', off: 12, size: 4, desc: '段的物理地址（通常等于虚拟地址，仅在无 MMU 的裸机环境有意义）。' },
    { name: 'p_filesz', off: 16, size: 4, desc: '段在文件中的字节数。' },
    { name: 'p_memsz', off: 20, size: 4, desc: '段在内存中的字节数。memsz > filesz 的部分由加载器填 0（→ .bss）。' },
    { name: 'p_flags', off: 24, size: 4, enum: 'p_flags', desc: '内存权限标志 R/W/X。' },
    { name: 'p_align', off: 28, size: 4, desc: '对齐要求。p_vaddr 与 p_offset 必须模 p_align 同余（页对齐时即为 0x1000 的倍数）。' }
  ],
  64: [
    { name: 'p_type', off: 0, size: 4, enum: 'p_type', desc: '段类型。' },
    { name: 'p_flags', off: 4, size: 4, enum: 'p_flags', desc: '内存权限（注意：64 位程序头里 flags 紧跟 type，与 32 位不同）。' },
    { name: 'p_offset', off: 8, size: 8, desc: '段内容文件偏移。' },
    { name: 'p_vaddr', off: 16, size: 8, desc: '段虚拟地址。' },
    { name: 'p_paddr', off: 24, size: 8, desc: '段物理地址。' },
    { name: 'p_filesz', off: 32, size: 8, desc: '文件中的字节数。' },
    { name: 'p_memsz', off: 40, size: 8, desc: '内存中的字节数。' },
    { name: 'p_align', off: 48, size: 8, desc: '对齐约束。' }
  ]
};

/* 段头字段布局 */
const SHDR_FIELDS = {
  32: [
    { name: 'sh_name', off: 0, size: 4, desc: '段名在 .shstrtab 中的字节偏移。解析段名时需要「段名表段」的 sh_offset + 此偏移。' },
    { name: 'sh_type', off: 4, size: 4, enum: 'sh_type', desc: '段类型。' },
    { name: 'sh_flags', off: 8, size: 4, enum: 'sh_flags', desc: '段属性位掩码。' },
    { name: 'sh_addr', off: 12, size: 4, desc: '若段被加载，这是其内存首地址；否则为 0。' },
    { name: 'sh_offset', off: 16, size: 4, desc: '段内容在文件中的偏移。SHT_NOBITS 时该值无实际数据意义。' },
    { name: 'sh_size', off: 20, size: 4, desc: '段的字节数。' },
    { name: 'sh_link', off: 24, size: 4, desc: '到另一个段头的链接（含义随 sh_type 变化，如符号表 → 字符串表）。' },
    { name: 'sh_info', off: 28, size: 4, desc: '附加信息（如符号表中第一个全局符号的索引）。' },
    { name: 'sh_addralign', off: 32, size: 4, desc: '地址对齐要求，必须是 2 的幂；0/1 表示无约束。' },
    { name: 'sh_entsize', off: 36, size: 4, desc: '若段是固定大小表项数组（符号表、重定位表），这是一个表项的大小。' }
  ],
  64: [
    { name: 'sh_name', off: 0, size: 4, desc: '段名在 .shstrtab 中的偏移。' },
    { name: 'sh_type', off: 4, size: 4, enum: 'sh_type', desc: '段类型。' },
    { name: 'sh_flags', off: 8, size: 8, enum: 'sh_flags', desc: '段属性（64 位宽）。' },
    { name: 'sh_addr', off: 16, size: 8, desc: '段内存地址。' },
    { name: 'sh_offset', off: 24, size: 8, desc: '段内容文件偏移。' },
    { name: 'sh_size', off: 32, size: 8, desc: '段大小。' },
    { name: 'sh_link', off: 40, size: 4, desc: '链接到的段索引。' },
    { name: 'sh_info', off: 44, size: 4, desc: '附加信息。' },
    { name: 'sh_addralign', off: 48, size: 8, desc: '对齐要求。' },
    { name: 'sh_entsize', off: 56, size: 8, desc: '表项大小。' }
  ]
};

/* 符号表项字段布局 */
const SYM_FIELDS = {
  32: [
    { name: 'st_name', off: 0, size: 4, desc: '符号名在对应字符串表中的偏移。' },
    { name: 'st_value', off: 4, size: 4, desc: '符号值：函数/变量地址或偏移。' },
    { name: 'st_size', off: 8, size: 4, desc: '符号大小。函数符号给出函数体字节数，是反汇编切分函数边界的最佳依据。' },
    { name: 'st_info', off: 12, size: 1, enum: 'st_info', desc: '绑定+类型打包字段。' },
    { name: 'st_other', off: 13, size: 1, enum: 'st_other', desc: '可见性。' },
    { name: 'st_shndx', off: 14, size: 2, enum: 'st_shndx', desc: '所属段索引。' }
  ],
  64: [
    { name: 'st_name', off: 0, size: 4, desc: '符号名偏移。' },
    { name: 'st_info', off: 4, size: 1, enum: 'st_info', desc: '绑定+类型。' },
    { name: 'st_other', off: 5, size: 1, enum: 'st_other', desc: '可见性。' },
    { name: 'st_shndx', off: 6, size: 2, enum: 'st_shndx', desc: '段索引。' },
    { name: 'st_value', off: 8, size: 8, desc: '符号值。' },
    { name: 'st_size', off: 16, size: 8, desc: '符号大小。' }
  ]
};

/* 重定位表项字段布局 */
const RELA_FIELDS = {
  32: [
    { name: 'r_offset', off: 0, size: 4, desc: '需要被修补的位置的虚拟地址。' },
    { name: 'r_info', off: 4, size: 4, desc: '打包字段：高 24 位是符号索引，低 8 位是重定位类型。' }
  ],
  64: [
    { name: 'r_offset', off: 0, size: 8, desc: '修补位置的虚拟地址。' },
    { name: 'r_info', off: 8, size: 8, desc: '打包字段：高 32 位是符号索引，低 32 位是重定位类型。' }
  ]
};

const NOTE_FIELD_DOC =
  'Elf{32,64}_Nhdr 由 3 个字段组成：namesz（名字长度）、descsz（描述长度）、type（附注类型），' +
  '随后是「名字（补齐到 4 字节）+ 描述（补齐到 4 字节）」。典型的 type=3 表示 GNU build-id，' +
  '是一段用于精确识别二进制版本（供调试符号服务器匹配）的哈希值。';

/* --------------------------------------------------------------------------
 * 常见段名 → 用途说明字典
 * ------------------------------------------------------------------------*/
const SECTION_PURPOSE = {
  '.text': '可执行机器码。程序的实际指令流，通常属性为 AX（可分配 + 可执行）。反汇编视图的主战场。',
  '.init': '进程初始化代码，由动态链接器在加载可执行文件后、调用 main 之前运行。',
  '.fini': '进程终止代码，在 main 返回或 exit() 之后执行。',
  '.plt': 'Procedure Linkage Table，过程链接表。每 16 字节左右一个桩，首次调用跳转到动态链接器解析符号，之后通过 GOT 直接跳转。',
  '.got': 'Global Offset Table，全局偏移表。存放外部符号地址的间接跳转表；配合 RELRO 在重定位后可变成只读。',
  '.got.plt': 'GOT 中属于 PLT 的跳转槽部分，惰性绑定会在这里写入解析后的函数地址。',
  '.rodata': '只读数据：字符串字面量、常量表、跳转表。属性 A（可分配）但不可写、不可执行。',
  '.data': '已初始化的全局/静态变量。属性 WA，运行期可写。',
  '.bss': '未初始化或初始化为 0 的全局变量。SHT_NOBITS：文件里不占空间，只在内存中占位并清零。',
  '.tdata': '线程局部存储的已初始化数据。',
  '.tbss': '线程局部存储的零初始化数据（SHT_NOBITS）。',
  '.comment': '编译器版本注释，通常是 GCC/Clang 的版本字符串。不加载到内存。',
  '.note.gnu.build-id': 'GNU 构建 ID 附注，唯一标识本次链接产物的哈希，用于匹配调试符号。',
  '.note.ABI-tag': '声明该二进制期望的 Linux 内核 ABI 版本。',
  '.interp': '记录动态链接器路径的字符串。',
  '.dynamic': '.dynamic 段的实体内容：一串「标签-值」对，见 DT_* 枚举。',
  '.symtab': '静态符号表，包含所有符号（含局部符号与调试用的行号符号）。strip 后消失。',
  '.strtab': '.symtab 的符号名字符串表。',
  '.shstrtab': '段名表，存放所有段的名字字符串。',
  '.dynsym': '动态符号表，只保留运行期需要的符号，必须与 .dynstr 一起被加载。',
  '.dynstr': '动态字符串表，存放 .dynsym 的名字与 DT_NEEDED 的库名。',
  '.rela.text': '针对 .text 的重定位表（带加数）。告诉链接器把哪条指令的立即数改成什么值。',
  '.rela.dyn': '动态重定位表，处理 GOT/数据中的地址，运行期由动态链接器执行。',
  '.rela.plt': 'PLT 相关的重定位表，用于函数调用的惰性绑定。',
  '.eh_frame': 'DWARF 异常处理帧信息，支持 C++ 异常展开与栈回溯。',
  '.eh_frame_hdr': '异常处理帧信息的二分查找索引，加速回溯。',
  '.debug_info': 'DWARF 调试信息主体：类型、变量、函数、作用域描述。',
  '.debug_line': 'DWARF 行号程序：把机器码地址映射回源码行，是调试器单步的基础。',
  '.debug_str': 'DWARF 字符串池。',
  '.debug_abbrev': 'DWARF 缩写表，配合 .debug_info 压缩描述体积。',
  '.riscv.attributes': "RISC-V 属性段，记录该目标文件所要求/提供的 ISA 扩展字符串，例如 'rv64i2p1_m2p0_a2p1_c2p0'。链接器据此校验扩展兼容性。",
  '.riscv.attribute': 'RISC-V 属性段（别名形式）。',
  '.gnu.attributes': 'GNU 属性段，记录架构相关能力标志。',
  '.gnu.version': '符号版本索引表，与 .dynsym 一一对应。',
  '.gnu.version_r': '符号版本需求表（依赖的库提供的版本）。',
  '.gnu.version_d': '符号版本定义表（本库导出的版本）。',
  '.gnu.hash': 'GNU 扩展哈希表，用布隆过滤器加速动态符号查找。',
  '.hash': 'System V 哈希表，旧式动态符号查找结构。',
  '.sdata': '小数据段，可通过 gp 寄存器用单条指令访问，优化紧凑代码体积。',
  '.sbss': '小 BSS 段。',
  '.note.GNU-stack': '标记栈不可执行（安全加固）。'
};

/* e_ident 的魔数 */
const ELF_MAGIC = [0x7f, 0x45, 0x4c, 0x46]; // \x7f E L F

/* 段颜色分类的展示名 */
const KIND_LABEL = {
  ehdr: 'ELF 头',
  phdr: '程序头表',
  shdr: '段头表',
  text: '代码 (.text)',
  rodata: '只读数据',
  data: '数据段',
  bss: 'BSS (无文件内容)',
  symtab: '符号表',
  strtab: '字符串表',
  dynsym: '动态符号表',
  dynstr: '动态字符串表',
  rela: '重定位表',
  dynamic: '动态链接信息',
  note: '附注 (Note)',
  debug: '调试信息',
  plt: 'PLT/GOT',
  comment: '编译器注释',
  attr: '属性段',
  other: '其它已加载内容',
  gap: '文件空隙 / 未映射',
  shstrtab: '段名表'
};

const ARCH_ALIASES = {
  243: 'riscv', 62: 'x86-64', 3: 'x86', 40: 'arm', 183: 'aarch64',
  8: 'mips', 20: 'ppc', 21: 'ppc64', 22: 's390', 2: 'sparc', 258: 'loongarch', 247: 'bpf'
};
