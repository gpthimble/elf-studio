**中文** | [English](README.md)

# ELF Studio

在浏览器里查看 ELF 文件结构的工具，重点支持 RISC-V。

- 在线使用：<https://gpthimble.github.io/elf-studio/>
- 仓库：<https://github.com/gpthimble/elf-studio>

解析全部在浏览器本地完成，文件不会上传到服务器。

## 使用方式

| 方式 | 做法 |
| --- | --- |
| 在线 | 打开 <https://gpthimble.github.io/elf-studio/> |
| 离线 | 下载 [`elf-studio.html`](https://github.com/gpthimble/elf-studio/raw/main/elf-studio.html) 后双击打开 |
| 本地构建 | `python3 build.py`（生成 `elf-studio.html` 与 `index.html`） |

页面可以拖入自己的 ELF 文件，也可以点「加载内置示例」查看一个 RISC-V 可执行文件。

## 功能

### Hex 视图

- 按 ELF 物理结构逐字节着色：ELF 头、程序头表、段头表、`.text`、`.rodata`、`.data`、`.bss`、符号表、字符串表、重定位表、`.dynamic`、Note、调试段、PLT/GOT、属性段以及文件空隙。
- 每行左侧有结构色条，段落起点标出结构名；分区表完整覆盖文件，不重叠也不遗漏。
- 只渲染可视行，行数很多的文件也能正常滚动。

### 字段与字节

- 悬停任意字节，底部显示文件偏移、虚拟地址（含来源段或程序头）、字节值、结构分区、字段名与字段说明；枚举字段同时给出解码结果。
- 单击或拖选可以固定探针内容，按 `Esc` 取消固定。
- 悬停字段行、符号行或反汇编行时，高亮整段字节而不是单个字节。
- 顶部「跳转」框接受偏移、虚拟地址、段名或符号名。
- 探针上有逐位、逐字段的导航按钮，键盘对应 `←/→`（一个字节）、`↑/↓`（一整行）、`PageUp/PageDown`、`Home/End`、`[` `]`（上一个/下一个结构字段）。探针会显示当前偏移与字段进度。

### 枚举与字段说明

- 19 组枚举、300 多条取值，标注规范出处、取值与说明，覆盖 `EI_*`、`e_type`、`e_machine`、`p_type`、`p_flags`、`sh_type`、`sh_flags`、`st_bind`、`st_type`、`st_other`、`st_shndx`、`DT_*`、`R_RISCV_*`、`R_X86_64_*`、RISC-V `e_flags` 等。
- 点击字段行弹出该字段的全部可选取值，当前取值高亮；`st_info` 这类打包字段会拆成 `st_bind` 与 `st_type` 两张子表。
- 字典页按字段在文件中的偏移顺序排列，每一项带当前值、所在结构与出现次数，可定位到对应字节。
- 附 `Elf32/64_Ehdr、Phdr、Shdr、Sym、Rela` 的字段布局速查表。

### 反汇编

- 对带 `SHF_EXECINSTR` 的段做线性扫描。RISC-V 覆盖 RV32/RV64 的 I/M/A/F/D、压缩指令 C、Zicsr/Zifencei 以及常用 Zba/Zbb/Zbs/Zbc，识别 `li/mv/ret/jr/j/nop/beqz/bnez/csrr` 等伪指令，跳转与分支目标命中符号表时标出函数名。
- 点击指令行会同步定位左侧 Hex；指令行右侧的「位域」按钮就地展开该指令的编码拆解：按规范切开的字段色块、位号、每个字段的二进制与含义，用来说明助记符是由哪些位决定的。
- 由 `lui`/`auipc` 与 12 位立即数合成的地址会标注出它落在哪个符号上，形式与 objdump 一致：`addi sp, sp, 512  # 0x80005200 <topofstack>`。
- x86-64 使用简化解码器，覆盖常见整数与 SSE 指令，未覆盖的编码以 `.byte` 列出，指令长度仍然可靠。

### 符号表

- 解析 `.symtab` 与 `.dynsym`，列出名称、`st_value`、`st_size`、绑定、类型、可见性、所属段，以及符号表项偏移与内容偏移两列；支持搜索与按类型、绑定、所属表过滤。
- 每行有「表项 / 内容 / 解析 / 反汇编」四个动作，分别跳到符号表项字节、段内内容、解析面板与反编译视图。
- 解析面板把表项按字段着色分组并画出引用关系：`st_name` 指向字符串表中的名字，`st_shndx` 指向段头与段内容，`st_value` 指向内容偏移，`st_size` 给出字节区间。
- 引用关系来自两处。重定位表适用于尚未链接完的目标文件；对于已经链接完成、地址早已写进指令、重定位项消失的文件，工具会扫描反汇编与数据段来按地址反查：跳转与分支目标、`lui`/`auipc` 与紧随其后的 12 位立即数合成的地址、以及数据段中等于该地址的指针。每条引用都注明来自哪条指令或哪个位置，点击即可跳转。

### 重定位

- 段总览列出这段重定位涉及哪些符号、各被引用多少次，以及它们是未定义的外部符号还是定义在某个段里。
- 单项面板把 `r_offset` / `r_info` / `r_addend` 按字段着色分组，并把 `r_info` 拆成符号索引与类型两段（ELF64 为高 32 位与低 32 位，ELF32 为高 24 位与低 8 位），给出还原算式与全部可选取值列表。
- 被修补的位置显示段内偏移、文件偏移与所在段，并用色块标出被修改的指令及其被改动的位域：`R_RISCV_CALL/CALL_PLT` 标出 `auipc` 与 `jalr` 两条，`HI20`、`LO12_I`、`LO12_S`、`JAL`、`BRANCH` 等各按自己的规则标注。数据段重定位显示将被写入的字节。
- `R_RISCV_RELAX`、`R_RISCV_ALIGN` 这类不写数据的条目按修饰项呈现：说明它修饰的是紧邻其上的那条重定位，并高亮被修饰重定位覆盖的、可被松弛的指令序列。

### 段内容

- `.text` 列出指令预览；`.symtab` 给出表项解码表；`.strtab` 列出字符串；`.rela.*` 列出重定位项；`.dynamic` 列出标签与取值；`.note.*` 与 `.riscv.attributes` 就地解析。
- `.rodata`、`.data` 等提供内容解码面板，可在字符串、32 位字、64 位字、指针候选四种视图间切换；字视图给出十六进制、十进制与浮点解读，落在已映射段内的值会解析成「段名 + 偏移」，能对应到函数时同时给出符号名。
- `SHT_NOBITS` 类型的段（`.bss` 等）在文件中不占字节，它的 `sh_offset` 只是占位值，因此这类段会明确标注出来，点击时跳到段头表项而不是一个没有意义的位置；其中的符号没有内容偏移，地址也不会被映射回文件字节。

### 其它

- 概览页显示结构分布条与配色图例，点击色块或图例可跳转到对应区间。
- 解析异常（魔数不符、类别或字节序非法、偏移越界等）会给出具体提示。
- 支持 ELF32/ELF64、小端与大端、ET_REL/ET_EXEC/ET_DYN/ET_CORE。

## 截图

| 概览 | 反汇编 |
| --- | --- |
| ![概览](preview-overview.png) | ![反汇编](preview-disasm.png) |

| 字段取值弹出面板 | 字节序与位图 |
| --- | --- |
| ![字段](preview-fields.png) | ![字节序](preview-byteswap.png) |

| 段内容与指令编码 | 字典 |
| --- | --- |
| ![段内容](preview-instruction-encoding.png) | ![字典](preview-dictionary.png) |

## 验证

测试用 Deno 直接运行浏览器脚本，配合 Python 生成的二进制夹具：

```sh
sh test/run_all.sh                          # 生成夹具、跑测试、语法检查、打包
python3 test/make_fixture.py
deno run --allow-read test/run_tests.js     # 1932 项断言
deno run --allow-read test/syntax_check.js  # 语法与 DOM 引用检查
```

正确性来自三种互相独立的对照：

1. RISC-V 解码器对照规范编码向量。`test/tests.js` 列出手工核对的编码，例如 `00100513` 是 `li a0,1`、`8082` 是 `ret`、`ff010113` 是 `addi sp,sp,-16`、`f1402573` 是 `csrr a0,mhartid`，逐条比对解码输出。
2. ELF 解析器对照按规范拼装的夹具。`test/make_fixture.py` 逐字节构造 ELF32/ELF64 文件，测试校验头部字段、段名解析、符号属性、偏移与虚拟地址映射、分区是否完整覆盖文件等。同一段 `.text` 由 Python 编码、由 JS 解码，两侧独立实现。
3. x86 解码器对照真实编译器产物。用 `clang -target x86_64-unknown-linux-gnu -c` 编译出目标文件，用 `llvm-objdump` 记录每条指令的地址，测试逐条比对指令边界是否一致。

测试还会扫描全部说明文案（重定位说明、枚举说明、字段文档、段用途词典），禁止「同上」「同前」这类依赖上下文的措辞，并要求每条说明达到最低完整度。

夹具：`hello-riscv32.elf`、`hello-riscv64.elf`（手工构造的小程序）、`big-riscv64.elf`（47 个段、406 个符号、39 条重定位、200 个函数）、`reloc-riscv64.o`（含 `R_RISCV_CALL_PLT` 与紧随其后的 `R_RISCV_RELAX`）、`sumtest.elf`（已链接完成、没有重定位项，符号引用只能按地址反查）、`x86-64-sample.o`（clang 产物）。

## 项目结构

```
elf-studio.html          构建产物：单文件应用
index.html               同一份内容的副本，供 GitHub Pages 以根路径访问
build.py                 把 src/ 打包成单文件
push_to_github.sh        建仓库、推送、开启 Pages 的辅助脚本
src/
  shell.html             HTML 骨架
  style.css              样式，结构配色也定义在这里
  util.js                工具函数
  elf-const.js           ELF 常量、枚举字典、字段文档、段用途词典
  elf-enums.js           枚举取值解码
  elf-parse.js           ELF 解析器
  disasm-riscv.js        RISC-V 反汇编与指令位域拆解
  disasm-x86.js          x86 / x86-64 反汇编（常用子集）
  disasm-dispatch.js     按架构分派反汇编
  hexview.js             多色块 Hex 视图
  app-core.js            状态、文件加载、联动、字节探针、概览
  app-panels.js          各结构面板
  app-symbols.js         符号表项解析与引用关系
  app-refscan.js         按地址反查引用
  app-relocs.js          重定位解析与引用链路
  app-encoding.js        指令编码对照面板
  app-disasm.js          反汇编视图
test/
  make_fixture.py        生成测试夹具
  tests.js               断言
  run_tests.js           测试运行器
  syntax_check.js        语法与 DOM 引用检查
  run_all.sh             一键跑完全部验证并重新构建
```

## 实现说明

`parseELF()` 一次遍历产出三部分数据：结构体（头部、段、符号、重定位、Note、属性）、颜色分区表 `regions`、字节标注表 `annotations`（把 `e_machine`、`p_offset`、`sh_flags` 这类字段映射到 `[start, end)` 字节区间）。探针查询标注表就能确定某个字节属于哪个字段。

段表与程序头可能互相重叠（例如 `PT_LOAD` 覆盖了 `.text` 与文件填充），因此给各类结构设定优先级后做一次扫描线裁决：优先级高的分区在自身起点处截断优先级低的分区，保证覆盖完整，最具体的结构优先显示。

Hex 视图用固定行高、绝对定位与 `translateY` 实现虚拟滚动，逐字节着色查一张与文件等长的 `Uint8Array`，选中与高亮只改可视节点的 class，不重建 DOM。

RISC-V 是变长编码，解码先看低 2 位判断 16 位还是 32 位；立即数按规范的位域编号抽取，B/J/S 型散落的位域在测试里有专门覆盖。若文件未声明 `EF_RISCV_RVC`，16 位指令会按数据展示并给出提示，也可以在设置里强制开启解析。

## 已知限制

- x86/x86-64 解码器只覆盖常见整数指令与部分 SSE，指令长度可靠，浮点、AVX 等复杂编码可能显示为 `.byte`。
- 不支持 ARM、AArch64、MIPS 的指令解码（结构与 Hex 仍可查看）。
- 不解析 DWARF 语义，`.debug_info`、`.debug_line` 只按段展示；反汇编是线性扫描，不构建控制流图，代码段里混排的数据可能被当作指令。
- 未解析 `.gnu.hash`、SysV `.hash` 的桶内容与符号版本表的语义。
- 文件很大（超过约 100 MB）时浏览器内存会比较吃紧。
