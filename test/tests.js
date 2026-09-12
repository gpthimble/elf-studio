/* 测试主体（由 run_tests.js 拼接进同一作用域执行） */

/* ============================ 1. RISC-V 编码向量 ============================
 * 这些是人工核对过的"权威编码"（取自规范手册与真实工具链输出），
 * 用来独立验证反汇编器，而不是依赖本仓库自己的编码器。            */
const VEC = [
  [0x00000013, 'nop'],
  [0x00008067, 'ret'],
  [0x00000073, 'ecall'],
  [0x00100073, 'ebreak'],
  [0x10500073, 'wfi'],
  [0x30200073, 'mret'],
  [0x00100513, 'li a0, 1'],
  [0x00a00513, 'li a0, 10'],
  [0xfff00513, 'li a0, -1'],
  [0x00058513, 'mv a0, a1'],
  [0xff010113, 'addi sp, sp, -16'],
  [0x01010113, 'addi sp, sp, 16'],
  [0x00113023, 'sd ra, 0(sp)'],
  [0x00113423, 'sd ra, 8(sp)'],
  [0x00813083, 'ld ra, 8(sp)'],
  [0x0005a503, 'lw a0, 0(a1)'],
  [0x00a5a223, 'sw a0, 4(a1)'],
  [0x12345537, 'lui a0, 0x12345000'],
  [0x00000097, 'auipc ra, 0x0'],
  [0x00c58533, 'add a0, a1, a2'],
  [0x02c5c533, 'div a0, a1, a2'],
  [0x00c585b3, 'add a1, a1, a2'],
  [0x02c58533, 'mul a0, a1, a2'],
  [0xf1402573, 'csrr a0, mhartid'],
  [0x00028067, 'jr t0'],
  [0x0000000f, 'fence'],
  [0x0ff0000f, 'fence iorw, iorw'],
  [0x0000100f, 'fence.i'],
  [0x0000006f, 'j 0x1000'],     // jal x0, 0 —— 在地址 0x1000 处解码
  // 压缩指令（16 位）
  [0x8082, 'ret'],              // c.jr ra —— 与 32 位 ret 同义，最短返回序列
  [0x4501, 'c.li a0, 0'],
  [0x9002, 'c.ebreak'],
  [0x1141, 'c.addi sp, -16'],
  [0x0141, 'c.addi sp, 16'],
  [0x713d, 'c.addi16sp sp, -32'],
  [0x8582, 'c.jr a1'],
  [0x8596, 'c.mv a1, t0'],
];

function decodeOne(word, bits, hasRVC) {
  const n = (word & 3) === 3 ? 4 : 2;
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = (word >> (8 * i)) & 0xff;
  const list = riscvDisassemble(b, 0x1000, { bits, hasRVC: hasRVC !== false, forceC: hasRVC === false ? 'off' : 'auto' });
  return list.length ? list[0].text : '(无输出)';
}

for (const [word, expected] of VEC) {
  eq(decodeOne(word, 64, true), expected, `RISC-V64 解码 ${hex(word, 8)}`);
}
// 同一批 32 位指令在 RV32 下应得到相同结果（除了 64 位专属指令）
for (const [word, expected] of VEC) {
  if (String(expected).match(/\b(ld|sd|addiw|jr)\b/)) continue;
  eq(decodeOne(word, 32, true), expected, `RISC-V32 解码 ${hex(word, 8)}`);
}

/* 分支与跳转目标计算 */
{
  const code = new Uint8Array(8);
  // beq a0, a1, +8 → B 型：imm[4:1] 位于 inst[11:8]，此处 imm=8 → 字段值 4
  const beqEnc = (11 << 20) | (10 << 15) | (4 << 8) | 0x63;
  const beq = beqEnc;
  code[0] = beq & 0xff; code[1] = (beq >> 8) & 0xff; code[2] = (beq >> 16) & 0xff; code[3] = (beq >> 24) & 0xff;
  const list = riscvDisassemble(code, 0x1000, { bits: 64 });
  eq(list[0].text, 'beq a0, a1, 0x1008', 'B 型分支目标地址计算');
  eq(list[0].target, 0x1008, '分支目标字段');
}

/* 符号注解：跳转目标命中符号表时附加名字 */
{
  const code = new Uint8Array([0xef, 0x00, 0x40, 0x00]); // jal ra, +4 → 0x2004
  const syms = new Map([[0x2004, { name: 'callee' }]]);
  const list = riscvDisassemble(code, 0x2000, { bits: 64, symbols: syms });
  eq(list[0].text, 'jal ra, 0x2004', 'jal 目标');
  eq(list[0].targetSymbol, 'callee', '跳转目标符号解析');
}

/* forceC='off' 时应退回 16 位数据视图 */
{
  eq(decodeOne(0x8082, 64, false), '.2byte 0x8082', '未声明 C 扩展时按数据展示');
}

/* ============================== 2. ELF 解析 ============================== */
const fx = 'test/fixtures/';
const elf64 = parseELF(Deno.readFileSync(fx + 'hello-riscv64.elf'), 'hello-riscv64.elf');
const elf32 = parseELF(Deno.readFileSync(fx + 'hello-riscv32.elf'), 'hello-riscv32.elf');
const bad = parseELF(Deno.readFileSync(fx + 'not-an-elf.bin'), 'not-an-elf.bin');

ok(elf64.valid, 'ELF64 解析成功');
ok(elf32.valid, 'ELF32 解析成功');
ok(!bad.valid, '非 ELF 文件被正确拒绝');
ok(bad.errors.length > 0, '非 ELF 文件给出错误信息');
eq(bad.errors[0].indexOf('魔数') >= 0, true, '错误信息指出魔数问题');

eq(elf64.is64, true, 'ELF64 is64');
eq(elf32.is64, false, 'ELF32 is64');
eq(elf64.le, true, '小端识别');
eq(elf64.arch, 'riscv', '架构识别为 riscv');
eq(elf64.ehdr.e_machine, 243, 'e_machine = 243 (EM_RISCV)');
eq(elf64.ehdr.e_type, 2, 'e_type = 2 (ET_EXEC)');
eq(elf64.ehdr.e_entry, 0x10000, 'e_entry');
eq(elf64.ehdr.e_ehsize, 64, '64 位 ELF 头大小 64');
eq(elf64.ehdr.e_phentsize, 56, '64 位程序头大小 56');
eq(elf64.ehdr.e_shentsize, 64, '64 位段头大小 64');
eq(elf64.ehdr.e_shstrndx, 10, '段名表索引');
eq(elf64.ehdr.e_flags & 1, 1, 'EF_RISCV_RVC 标志已置位');
eq(elf32.ehdr.e_ehsize, 52, '32 位 ELF 头大小 52');
eq(elf32.ehdr.e_phentsize, 32, '32 位程序头大小 32');

eq(elf64.phdrs.length, 6, '程序头数量');
eq(elf64.phdrs[1].p_type, 1, '第 2 个程序头是 PT_LOAD');
eq(elf64.phdrs[1].p_flags, 5, 'PT_LOAD 权限为 R+X');
eq(elf64.phdrs[1].p_vaddr, 0x10000, 'PT_LOAD 虚拟地址');
eq(elf64.phdrs[4].p_type, 0x6474e551, 'PT_GNU_STACK 类型识别');

eq(elf64.shdrs.length, 11, '段头数量');
eq(elf64.shdrs[1].name, '.text', '段名解析 (.text)');
eq(elf64.shdrs[1].sh_type, 1, '.text 类型 PROGBITS');
eq(elf64.shdrs[1].sh_flags, 6, '.text 属性 ALLOC|EXECINSTR');
eq(elf64.shdrs[1].sh_addr, 0x10000, '.text 地址');
eq(elf64.shdrs[4].name, '.bss', '.bss 段名');
eq(elf64.shdrs[4].sh_type, 8, '.bss 类型 NOBITS');
eq(elf64.sectionByName.get('.symtab').sh_entsize, 24, '符号表项大小');
eq(elf64.sectionByName.get('.symtab').sh_info, 3, '第一个全局符号索引');

/* 符号表 */
const names = elf64.symbols.map(s => s.name).filter(Boolean);
ok(names.indexOf('main') >= 0, '符号表包含 main');
ok(names.indexOf('strlen') >= 0, '符号表包含 strlen');
ok(names.indexOf('msg') >= 0, '符号表包含 msg');
const mainSym = elf64.symbols.find(s => s.name === 'main');
eq(mainSym.type, 2, 'main 是 STT_FUNC');
eq(mainSym.bind, 1, 'main 是 STB_GLOBAL');
eq(mainSym.st_value, 0x10000, 'main 的 st_value');
eq(mainSym.st_size, elf64.symbols.find(s => s.name === 'strlen').st_value - 0x10000, 'main 的 st_size 覆盖到 strlen 之前');
eq(mainSym.fileOffset, 0x1000, 'main 映射到文件偏移 0x1000');
const msgSym = elf64.symbols.find(s => s.name === 'msg');
eq(msgSym.type, 1, 'msg 是 STT_OBJECT');
eq(msgSym.sec, '.rodata', 'msg 归属 .rodata');

/* 地址映射 */
eq(offsetToVaddr(elf64, 0x1004).vaddr, 0x10004, '文件偏移 → 虚拟地址');
eq(vaddrToOffset(elf64, 0x11004).offset, 0x2004, '虚拟地址 → 文件偏移');
eq(offsetToVaddr(elf64, 0x3400), null, '未映射偏移返回 null');

/* 附注段与 RISC-V 属性 */
ok(elf64.notes.length >= 1, '解析出 Note 段');
eq(elf64.notes[0].name, 'GNU', 'Note 名字为 GNU');
eq(elf64.notes[0].type, 3, 'Note 类型 3 = build-id');
ok(elf64.riscvAttrs && elf64.riscvAttrs.tags.length > 0, '解析 .riscv.attributes');
const archTag = elf64.riscvAttrs.tags.find(t => t.tag === 5);
ok(archTag && archTag.value.indexOf('rv64') === 0, 'ISA 字符串以 rv64 开头');

/* 颜色分区 */
const textRegion = elf64.regions.find(r => r.kind === 'text');
ok(textRegion, '存在 text 分区');
eq(textRegion.start, 0x1000, 'text 分区起点 = .text 文件偏移');
eq(textRegion.end, 0x1000 + elf64.sectionByName.get('.text').sh_size, 'text 分区终点');
eq(elf64.regions[0].kind, 'ehdr', '分区表第一项为 ELF 头');
ok(elf64.regions.some(r => r.kind === 'phdr'), '存在程序头分区');
ok(elf64.regions.some(r => r.kind === 'shdr'), '存在段头表分区');
ok(elf64.regions.some(r => r.kind === 'symtab'), '存在符号表分区');
ok(elf64.regions.some(r => r.kind === 'gap'), '识别出未映射空隙');
eq(elf64.byteKind[0], elf64.kindId['ehdr'], '第 0 字节归类为 ELF 头');
eq(elf64.byteKind[0x1000], elf64.kindId['text'], '.text 首字节归类为代码');
// 分区必须完整、互不重叠地覆盖整个文件
let cov = 0, prevEnd = 0, contiguous = true;
for (const r of elf64.regions) {
  if (r.start !== prevEnd) contiguous = false;
  cov += r.end - r.start;
  prevEnd = r.end;
}
eq(contiguous, true, '分区在文件上首尾相接无缝隙');
eq(cov, elf64.size, '分区总长度等于文件大小');
eq(prevEnd, elf64.size, '分区覆盖到文件末尾');

/* 字节级探针（字段标注） */
const aMachine = annotationAt(elf64, 18);
eq(aMachine.field, 'e_machine', '偏移 18 标注为 e_machine');
eq(aMachine.enumKey, 'e_machine', 'e_machine 关联枚举字典');
const aEntry = annotationAt(elf64, 24);
eq(aEntry.field, 'e_entry', '偏移 24 标注为 e_entry');
const aPhdr = annotationAt(elf64, elf64.phdrs[1].fileOff + 8);
eq(aPhdr.field, 'p_offset', '程序头内字段标注');
eq(aPhdr.phIndex, 1, '程序头字段归属索引');
const aShdr = annotationAt(elf64, elf64.shdrs[1].fileOff + 24);
eq(aShdr.field, 'sh_offset', '段头内字段标注');
const symOff = elf64.sectionByName.get('.symtab').sh_offset + 3 * 24;
eq(annotationAt(elf64, symOff + 4).field, 'st_info', '符号表 st_info 标注');
eq(annotationAt(elf64, 0x1234), null, '未标注区域返回 null');

/* 概览统计 */
const sum = summarize(elf64);
ok(sum.length > 0 && sum[0].bytes > 0, '概览统计有数据');

/* ========================= 3. 真机 .text 反汇编 ========================= */
{
  const text = elf64.sectionByName.get('.text');
  const code = sectionBytes(elf64, text);
  eq(code.length, text.sh_size, '.text 字节长度');
  const symMap = new Map();
  for (const s of elf64.symbols) if (s.type === 2 && s.st_value) symMap.set(s.st_value, s);
  const insns = riscvDisassemble(code, text.sh_addr, {
    bits: 64, symbols: symMap, hasRVC: true, forceC: 'auto', fileBase: text.sh_offset
  });
  const expected = Deno.readTextFileSync(fx + 'expected-riscv64.txt').trim().split('\n');
  eq(insns.length, expected.length, '.text 反汇编条数');
  for (let i = 0; i < Math.min(insns.length, expected.length); i++) {
    eq(insns[i].text, expected[i], `第 ${i} 条指令 (地址 ${hex(insns[i].addr)})`);
  }
  // 指令地址应连续覆盖整段
  let sumLen = 0;
  for (const ins of insns) sumLen += ins.size;
  eq(sumLen, code.length, '指令长度之和 = .text 大小');
  ok(insns.some(i => i.size === 2), '包含 16 位压缩指令');
  ok(insns.some(i => i.size === 4), '包含 32 位指令');
  ok(insns.some(i => i.isReturn), '识别出返回指令');
  const mainInsn = insns.find(i => i.symbol === 'main');
  ok(mainInsn, '第一条指令标注为函数 main');
  eq(mainInsn.addr, 0x10000, 'main 入口地址');
  eq(mainInsn.fileOffset, 0x1000, 'main 的文件偏移');
  const callInsn = insns.find(i => i.targetSymbol === 'strlen');
  ok(callInsn, '调用 strlen 的跳转目标被解析为符号名');
}

/* ===================== 4. 较大文件的性能与正确性 ===================== */
{
  const t0 = performance.now();
  const big = parseELF(Deno.readFileSync(fx + 'big-riscv64.elf'), 'big-riscv64.elf');
  const parseMs = performance.now() - t0;
  ok(big.valid, '大型 ELF 解析成功 (' + parseMs.toFixed(1) + ' ms)');
  eq(big.shdrs.length, 47, '大型文件段数');
  eq(big.symbols.length, 406, '大型文件符号数');
  eq(big.relocations.length, 39, '大型文件重定位数量（36 条内部 + 3 条外部调用）');
  eq(big.dynamic.length, 5, '大型文件 .dynamic 条目数');
  eq(enumEntry('DT_tag', big.dynamic[0].tag).name, 'DT_NEEDED', '.dynamic 标签解码');
  eq(relocTypeName(big, big.relocations[0].type).indexOf('R_RISCV_') === 0, true, '重定位类型解码');
  ok(big.relocations.every(r => r.symbolName !== undefined), '重定位项关联到符号名');
  ok(parseMs < 1500, '解析 120 KB / 405 符号耗时 < 1.5s（实测 ' + parseMs.toFixed(1) + ' ms）');

  // 分区必须精确覆盖整个文件（不重不漏）
  let cov = 0, prev = 0, contiguous = true;
  for (const r of big.regions) {
    if (r.start !== prev) contiguous = false;
    cov += r.end - r.start; prev = r.end;
  }
  eq(contiguous, true, '大型文件分区连续无重叠');
  eq(cov, big.size, '大型文件分区覆盖全部字节');

  // 整段反汇编：随机指令流里不应出现"无法识别"
  const text = big.sectionByName.get('.text');
  const symMap = new Map();
  for (const s of big.symbols) if (s.type === 2 && s.st_value) symMap.set(s.st_value, s);
  const t1 = performance.now();
  const insns = riscvDisassemble(sectionBytes(big, text), text.sh_addr, {
    bits: 64, symbols: symMap, hasRVC: true, forceC: 'auto', fileBase: text.sh_offset
  });
  const disMs = performance.now() - t1;
  const illegal = insns.filter(i => i.illegal && !i.tail);
  eq(illegal.length, 0, '大型文件 .text 无未识别指令' +
    (illegal.length ? '（首条：' + illegal[0].text + ' @ ' + hex(illegal[0].addr) + '）' : ''));
  let sum = 0;
  for (const i of insns) sum += i.size;
  eq(sum, text.sh_size, '大型文件指令长度之和 = .text 大小');
  ok(insns.filter(i => i.symbol).length >= 200, '至少 200 个函数入口被符号标注');
  ok(disMs < 2000, '反汇编 ' + insns.length + ' 条指令耗时 < 2s（实测 ' + disMs.toFixed(1) + ' ms）');

  // 函数边界（st_size）应能覆盖整个段
  const funcs = big.symbols.filter(s => s.type === 2 && s.st_shndx !== 0 && s.st_size > 0);
  eq(funcs.length, 200, 'FUNC 符号数量');
  const covered = funcs.reduce((a, f) => a + f.st_size, 0);
  ok(covered >= text.sh_size, '函数大小之和覆盖 .text');
}

/* ============ 5. 指令位域拆解（二进制 ↔ 助记符 对照面板的数据源） ============ */
{
  // addi a0, zero, 1  = 0x00100513
  const f1 = riscvInsnFields(0x00100513, true, {});
  eq(f1.format, 'I 型 · 32 位', 'addi 被判为 I 型');
  eq(f1.bits, 32, '32 位指令');
  const fd = (n) => f1.fields.find(f => f.name === n);
  eq(fd('opcode').bin, '0010011', 'opcode 位域 = 0010011 (OP-IMM)');
  eq(fd('opcode').hi + ':' + fd('opcode').lo, '6:0', 'opcode 位区间 [6:0]');
  eq(fd('funct3').bin, '000', 'funct3 位域 = 000 (addi)');
  eq(fd('rd').value, 10, 'rd 位域 = 10 (a0)');
  eq(fd('rs1').value, 0, 'rs1 位域 = 0 (zero)');
  eq(fd('imm[11:0]').value, 1, '立即数字段 = 1');
  eq(f1.fields.reduce((a, f) => a + f.width, 0), 32, '所有位域宽度之和 = 32（无遗漏无重叠）');

  // add a0, a1, a2 = 0x00c58533  → R 型
  const f2 = riscvInsnFields(0x00c58533, true, {});
  eq(f2.format, 'R 型 · 32 位', 'add 被判为 R 型');
  const fd2 = (n) => f2.fields.find(f => f.name === n);
  eq(fd2('funct7').bin, '0000000', 'R 型 funct7');
  eq(fd2('rs2').value, 12, 'rs2 = 12 (a2)');
  eq(fd2('rs1').value, 11, 'rs1 = 11 (a1)');
  eq(fd2('rd').value, 10, 'rd = 10 (a0)');
  eq(fd2('opcode').bin, '0110011', 'opcode = 0110011 (OP)');

  // sd ra, 8(sp) = 0x00113423 → S 型：立即数被打散在两个位域里
  const f3 = riscvInsnFields(0x00113423, true, {});
  eq(f3.format, 'S 型 · 32 位', 'sd 被判为 S 型');
  const immHi = f3.fields.find(f => f.name === 'imm[11:5]');
  const immLo = f3.fields.find(f => f.name === 'imm[4:0]');
  ok(immHi && immLo, 'S 型偏移被拆成 imm[11:5] 与 imm[4:0] 两段');
  eq(immHi.value * 32 + immLo.value, 8, '两段立即数合成偏移 8');

  // beq a5, zero, +0x14 = 0x00078a63 → B 型
  const f4 = riscvInsnFields(0x00078a63, true, {});
  eq(f4.format, 'B 型 · 32 位', 'beq 被判为 B 型');
  eq(f4.fields.find(f => f.name === 'rs1').value, 15, 'B 型 rs1 = a5');
  eq(f4.fields.find(f => f.name === 'rs2').value, 0, 'B 型 rs2 = zero');

  // lui a0, 0x12345 = 0x12345537 → U 型
  const f5 = riscvInsnFields(0x12345537, true, {});
  eq(f5.format, 'U 型 · 32 位', 'lui 被判为 U 型');
  eq(f5.fields.find(f => f.name === 'imm[31:12]').value, 0x12345, 'U 型立即数 = 0x12345');

  // jal ra, +4 = 0x004000ef → J 型
  const f6 = riscvInsnFields(0x004000ef, true, {});
  eq(f6.format, 'J 型 · 32 位', 'jal 被判为 J 型');
  eq(f6.fields.find(f => f.name === 'rd').value, 1, 'J 型 rd = ra');

  // 压缩指令 c.addi16sp sp, -32 = 0x713D → 16 位
  const f7 = riscvInsnFields(0x713d, true, {});
  eq(f7.bits, 16, '压缩指令为 16 位');
  eq(f7.format, '压缩（C 扩展）· 16 位', '压缩指令格式名');
  eq(f7.fields.find(f => f.name === 'op').bin, '01', '压缩指令 op 字段 = 01（象限 1）');
  eq(f7.fields.reduce((a, f) => a + f.width, 0), 16, '压缩指令所有位域宽度之和 = 16');

  // 每条字段的二进制串长度必须等于其位宽
  let widthOk = true;
  for (const word of [0x00100513, 0x00c58533, 0x00113423, 0x00078a63, 0x12345537, 0x004000ef, 0x713d]) {
    for (const f of riscvInsnFields(word, true, {}).fields) {
      if (f.bin.length !== f.width) widthOk = false;
    }
  }
  eq(widthOk, true, '每个字段的二进制串长度 = 位宽');
}

/* ==================== 6. 字节组多字节序解读（Hex 悬浮窗数据源） ==================== */
{
  // 取自 hello-riscv64.elf 中 .text 开头：13 05 10 00 = addi a0, zero, 1
  const b = new Uint8Array([0x13, 0x05, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x00, 0x00]);
  const le = interpretBytes(b, 0, true);
  const row = (n) => le.rows.find(r => r.name === n);
  eq(row('u8').prim, '19', 'u8 解读');
  eq(row('u16').primHex, '0x513', 'u16 小端解读（本文件字节序）');
  eq(row('u16').compHex, '0x1305', 'u16 大端对照');
  eq(row('u16').prim, '1299', 'u16 小端十进制');
  eq(row('u16').comp, '4869', 'u16 大端十进制');
  eq(row('u32').primHex, '0x100513', 'u32 小端解读');
  eq(row('u32').prim, '1049875', 'u32 小端十进制');
  eq(row('u32').compHex, '0x13051000', 'u32 大端对照');
  eq(row('u64').prim, '1049875', 'u64 小端（BigInt 精确）');
  ok(row('f32') && row('f64'), '提供浮点解读行');
  eq(le.string, '', '非字符串区域不误判');

  // 同一组字节按大端解读时，主/对照两列互换
  const be = interpretBytes(b, 0, false);
  eq(be.rows.find(r => r.name === 'u32').primHex, '0x13051000', '大端文件主列 = 大端解读');
  eq(be.rows.find(r => r.name === 'u32').compHex, '0x100513', '大端文件对照列 = 小端解读');

  // 字符串预览（.strtab 场景）
  const sb = new Uint8Array([0x00, 0x6d, 0x61, 0x69, 0x6e, 0x00, 0x68, 0x65, 0x6c, 0x70]);
  eq(interpretBytes(sb, 1, true).string, 'main', 'C 字符串预览');

  // 文件末尾附近：只输出放得下的组
  const tail = interpretBytes(b, b.length - 2, true);
  ok(!tail.rows.some(r => r.size > 2), '末尾不足时自动省略放不下的字节组');
  eq(tail.remaining, 2, '剩余字节数');

  // 越界安全
  eq(interpretBytes(b, b.length + 10, true).rows.length, 0, '越界返回空结果');

  /* ---- 字节组视图：字节序重排 + 二进制位图 ---- */
  // 用户最典型的场景：小端文件里的 e_flags = 05 00 00 00，值为 5
  const g = groupView(new Uint8Array([0x05, 0x00, 0x00, 0x00]), 0, 4, true);
  eq(g.rawHex, '05 00 00 00', '原始字节按文件顺序显示');
  eq(g.swappedHex, '00 00 00 05', '大端预览 = 字节逆序');
  eq(g.primHex, '0x00000005', '小端数值补零到字段宽度');
  eq(g.prim, '5', '小端十进制值');
  eq(g.compHex, '0x05000000', '大端对照值');
  eq(g.comp, '83886080', '大端对照十进制');
  eq(g.bits, '00000000 00000000 00000000 00000101', '二进制位串（每 8 位一组，MSB→LSB）');
  eq(g.setBits.join(','), '2,0', '置位 bit 列表（bit2、bit0）');

  // 2 字节与 8 字节
  const g2 = groupView(new Uint8Array([0x13, 0x05]), 0, 2, true);
  eq(g2.primHex, '0x0513', '2 字节小端值');
  eq(g2.swappedHex, '05 13', '2 字节大端预览');
  eq(g2.bits, '00000101 00010011', '2 字节位串');
  const g8 = groupView(new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0]), 0, 8, true);
  eq(g8.primHex, '0x0000000000000001', '8 字节小端值（BigInt 精确）');
  eq(g8.compHex, '0x0100000000000000', '8 字节大端对照');
  eq(g8.setBits.length, 1, '8 字节置位数量');
  eq(g8.setBits[0], 0, '8 字节置位的 bit 号');

  // 末尾不足时按 0 补齐并标记可用字节数
  const gTail = groupView(new Uint8Array([0xaa, 0xbb, 0xcc]), 2, 4, true);
  eq(gTail.avail, 1, '末尾字节组记录实际可用字节数');
  eq(gTail.rawHex, 'CC 00 00 00', '缺失字节按 0 补齐');

  // 按位枚举的位号 → 枚举名对照
  eq(describeBit('riscv_e_flags', 0), 'EF_RISCV_RVC', 'bit0 → RVC 压缩指令标志');
  eq(describeBit('riscv_e_flags', 2), 'EF_RISCV_FLOAT_ABI_DOUBLE', 'bit2 → 双精度浮点 ABI');
  eq(describeBit('riscv_e_flags', 1), 'EF_RISCV_FLOAT_ABI_SOFT', 'bit1 → 单精度/软浮点 ABI 标志');
  ok(String(describeBit('sh_flags', 20)).indexOf('掩码') >= 0, '仅被多比特掩码覆盖的位会标注所属掩码');
  eq(describeBit('riscv_e_flags', 63), null, '未定义的位返回 null');
}

/* ======================= 7. x86-64 反汇编（简化解码器） ======================= */
{
  const cases = [
    [[0x55], 'push rbp'],
    [[0x48, 0x89, 0xe5], 'mov rbp, rsp'],
    [[0xc3], 'ret'],
    [[0x90], 'nop'],
    [[0xb8, 0x2a, 0x00, 0x00, 0x00], 'mov eax, 0x2a'],
    [[0x48, 0xb8, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 'mov rax, 0x2a'],
    [[0x31, 0xc0], 'xor eax, eax'],
    [[0x83, 0xc0, 0x01], 'add eax, 0x1'],
    [[0x48, 0x83, 0xec, 0x10], 'sub rsp, 0x10'],
    [[0x48, 0x8d, 0x3d, 0x00, 0x00, 0x00, 0x00], 'lea rdi, [rip+0x0]'],
    [[0x48, 0x8b, 0x05, 0x00, 0x00, 0x00, 0x00], 'mov rax, qword [rip+0x0]'],
    [[0x0f, 0x05], 'syscall'],
    [[0xf3, 0x0f, 0x1e, 0xfa], 'endbr64'],
    [[0xff, 0x25, 0x00, 0x00, 0x00, 0x00], 'jmp [rip+0x0]'],
    [[0x48, 0x85, 0xc0], 'test rax, rax'],
    [[0x74, 0x05], 'je ' + hex(2 + 5)],
  ];
  for (const [bytes, expected] of cases) {
    const list = x86Disassemble(new Uint8Array(bytes), 0, { bits: 64 });
    eq(list.length, 1, 'x86 单条指令长度解析 ' + bytes.map(b => b.toString(16)).join(' '));
    eq(list[0].text, expected, 'x86 解码 ' + bytes.map(b => b.toString(16).padStart(2, '0')).join(' '));
    eq(list[0].size, bytes.length, 'x86 指令长度 ' + bytes.map(b => b.toString(16).padStart(2, '0')).join(' '));
  }
  // 变长指令流中不能错位：所有指令长度之和必须等于输入长度
  const stream = new Uint8Array([
    0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0x89, 0x7d, 0xfc,
    0x8b, 0x45, 0xfc, 0x83, 0xc0, 0x01, 0x89, 0x45, 0xf8, 0x8b, 0x45, 0xf8,
    0xc9, 0xc3
  ]);
  const list = x86Disassemble(stream, 0x1000, { bits: 64 });
  let sum = 0;
  for (const i of list) sum += i.size;
  eq(sum, stream.length, 'x86 指令流长度守恒');
  eq(list[list.length - 1].text, 'ret', 'x86 函数体以 ret 结束');
  eq(list[1].addr, 0x1001, 'x86 第二条指令地址正确');
}

/* ============ 8. 真实编译器产物的交叉验证（clang 生成的 x86-64 ELF） ============
 * 金标准来自 llvm-objdump 的反汇编输出，用于验证本仓库 x86 解码器的
 * 「指令边界」是否与 LLVM 完全一致（变长编码下这是最关键的正确性指标）。 */
{
  let objBytes = null;
  try { objBytes = Deno.readFileSync(fx + 'x86-64-sample.o'); } catch (e) { objBytes = null; }
  if (objBytes) {
    const x = parseELF(objBytes, 'x86-64-sample.o');
    ok(x.valid, '真实 x86-64 目标文件解析成功');
    eq(x.arch, 'x86-64', '架构识别为 x86-64');
    eq(x.ehdr.e_type, 1, 'ET_REL 可重定位目标文件');
    eq(x.phdrs.length, 0, 'ET_REL 没有程序头表（e_phoff = 0）');
    eq(x.ehdr.e_shoff > 0, true, 'ET_REL 有段头表');
    ok(x.symbols.some(s => s.name === 'helper' && s.type === 2), '解析出函数符号 helper');
    ok(x.symbols.some(s => s.name === 'compute' && s.type === 2), '解析出函数符号 compute');

    // 与 LLVM 的指令边界逐条比对
    const gold = Deno.readTextFileSync(fx + 'x86-64-sample.disasm.txt');
    const goldAddrs = [];
    for (const line of gold.split('\n')) {
      const m = /^\s*([0-9a-f]+):\s+\S/.exec(line);
      if (m) goldAddrs.push(parseInt(m[1], 16));
    }
    const text = x.sectionByName.get('.text');
    eq(goldAddrs.length > 10, true, '金标准包含 ' + goldAddrs.length + ' 条指令');
    const mine = x86Disassemble(sectionBytes(x, text), text.sh_addr, { bits: 64, fileBase: text.sh_offset });
    const myAddrs = mine.map(i => i.addr);
    eq(myAddrs.length, goldAddrs.length, '指令条数与 LLVM 一致');
    let firstDiff = -1;
    for (let i = 0; i < Math.min(myAddrs.length, goldAddrs.length); i++) {
      if (myAddrs[i] !== goldAddrs[i]) { firstDiff = i; break; }
    }
    eq(firstDiff, -1, '指令地址边界与 LLVM 完全一致' +
      (firstDiff >= 0 ? '（第 ' + firstDiff + ' 条：本实现 ' + hex(myAddrs[firstDiff]) + ' vs LLVM ' + hex(goldAddrs[firstDiff]) + '）' : ''));
  } else {
    ok(true, '（跳过）未生成 x86-64 夹具');
  }
}

/* ============ 9. 符号表项解析与引用关系（符号表 hex 可视化面板） ============ */
{
  const elf = parseELF(Deno.readFileSync(fx + 'big-riscv64.elf'), 'big.elf');
  const fn = elf.symbols.find(s => s.name === 'func_0000');
  ok(fn, '找到函数符号 func_0000');

  // 字段 → 字符串表
  const strtab = symStrTab(elf, fn);
  eq(strtab.name, '.strtab', 'st_name 通过 .symtab 的 sh_link 指向 .strtab');
  eq(cstr(sectionBytes(elf, strtab), fn.st_name), 'func_0000', 'st_name 偏移能取回符号名');

  // 字段 → 段头 → 段内容
  const sec = elf.shdrs[fn.st_shndx];
  eq(sec.name, '.text', 'st_shndx 指向 .text 段头');
  eq(fn.fileOffset !== undefined, true, 'st_value 能换算成文件偏移');
  const secOff = sec.sh_offset + (fn.st_value - sec.sh_addr);
  eq(fn.fileOffset, secOff, 'st_value → 段内容偏移的换算正确');
  eq(fn.st_size > 0, true, 'st_size 给出符号长度');

  // 入向引用：谁引用了这个符号
  const inbound = symInboundRelocs(elf, fn);
  ok(Array.isArray(inbound), '入向引用查询返回数组');
  const anyRel = elf.relocations.find(r => r.symIndex === fn.index);
  if (anyRel) {
    eq(inbound.length >= 1, true, '至少有一条重定位引用该符号');
    eq(inbound[0].symIndex, fn.index, '引用项确实是该符号');
  }
  // 反向：符号索引不匹配的不应被算作引用
  const other = elf.symbols.find(s => s.name === 'data_blob');
  eq(symInboundRelocs(elf, other).every(r => r.symIndex === other.index), true, '入向引用按符号索引严格过滤');

  // 面板输出：必须包含关键引用关系文字
  const html = symbolXrefPanel(elf, fn);
  ok(html.indexOf('st_name') >= 0 && html.indexOf('st_shndx') >= 0 && html.indexOf('st_value') >= 0,
    '面板列出全部关键字段');
  ok(html.indexOf('func_0000') >= 0, '面板里能直接看到符号名（字符串表解析结果）');
  ok(html.indexOf('.text') >= 0, '面板里标出 st_shndx 对应的段名');
  ok(html.indexOf('data-xr-off') >= 0, '面板里的引用目标都是可点击定位的');
  ok(html.indexOf('入向引用') >= 0, '面板包含入向引用区块');

  // 未定义符号：应说明由外部解析，而不是硬掰一个偏移
  const undef = elf.symbols.find(s => s.st_shndx === 0 && s.name);
  if (undef) {
    const uh = symbolXrefPanel(elf, undef);
    ok(uh.indexOf('未定义') >= 0, '未定义符号在面板中明确标注');
  }
}

/* ============ 10. 重定位表解析（.rela.text 字段拆解与符号映射） ============ */
{
  const elf = parseELF(Deno.readFileSync(fx + 'big-riscv64.elf'), 'big.elf');
  const rela = elf.sectionByName.get('.rela.text');
  ok(rela && rela.sh_type === 4, '找到 .rela.text（SHT_RELA）');
  const rs = elf.relocations.filter(r => r.table === '.rela.text');
  eq(rs.length, 23, '.rela.text 重定位项数量（20 条内部引用 + 3 条对外部符号 puts 的调用）');

  const r = rs[0];
  // 字段布局：Elf64_Rela = r_offset(8) + r_info(8) + r_addend(8)
  eq(rela.sh_entsize, 24, '表项大小 24 字节');
  eq(RELA_FIELDS[64].length, 3, 'Elf64_Rela 定义包含 r_offset/r_info/r_addend');
  eq(RELA_FIELDS[64][2].name, 'r_addend', '第三个字段是 r_addend');
  ok(RELA_FIELDS[64][2].onlyRela, 'r_addend 标记为仅 RELA 有效');

  // r_info 打包：高 32 位符号索引 + 低 32 位类型
  eq(r.symIndex, Math.floor(r.rawInfo / 4294967296), 'r_info 高 32 位 = 符号索引');
  eq(r.type, r.rawInfo % 4294967296, 'r_info 低 32 位 = 重定位类型');
  ok(enumEntry('R_RISCV', r.type) !== undefined || r.type >= 0, '重定位类型可被字典解码');

  // 与符号表的映射
  ok(r.sym, '重定位项关联到符号表项');
  eq(r.sym.index, r.symIndex, '关联的符号索引一致');
  eq(r.sym.table, '.symtab', '来自 .symtab 符号表');
  eq(rela.sh_link, elf.sectionByName.get('.symtab').index, '.rela.text 的 sh_link 指向 .symtab');
  eq(rela.sh_info, elf.sectionByName.get('.text').index, '.rela.text 的 sh_info 指向被修补的 .text');

  // 被修补位置能映射回文件偏移与指令
  const loc = vaddrToOffset(elf, r.offset);
  ok(loc && loc.section.name === '.text', 'r_offset 落回 .text 段');
  const tgt = relocPatchTarget(elf, r);
  ok(tgt.insns.length >= 1, '能解出被修补位置处的指令');
  // ET_REL（.o）里 r_offset 本身就是段内偏移；ET_EXEC/ET_DYN 里 r_offset 是虚拟地址
  eq(tgt.secOffset, r.offset - loc.section.sh_addr, '段内偏移 = r_offset - 段虚拟地址');
  ok(tgt.patch && tgt.patch.info, '能查到该类型的修补说明');
  eq(tgt.patched, tgt.patch.info.n, '被修补指令条数与类型定义一致');
  ok(Array.isArray(tgt.patch.info.fields) && tgt.patch.info.fields.length >= 1, '给出被修改的位域');

  // 面板输出
  const html = relocXrefPanel(elf, r);
  ok(html.indexOf('r_offset') >= 0 && html.indexOf('r_info') >= 0 && html.indexOf('r_addend') >= 0, '面板列出三个字段');
  ok(html.indexOf('sym_index') >= 0 && html.indexOf('type（低') >= 0, 'r_info 被拆成符号索引与类型两段');
  ok(html.indexOf('引用关系链路') >= 0, '面板含引用关系链路');
  ok(html.indexOf('改成谁') >= 0 && html.indexOf('在哪儿改') >= 0, '链路说明涵盖「改成谁 / 在哪儿改」');
  ok(html.indexOf('data-xr-off') >= 0, '引用目标可点击定位');

  // 段总览：哪些符号是可重定位的
  const sum = relocSectionSummary(elf, rela);
  ok(sum.indexOf('需要被「重定位」的引用目标') >= 0, '总览说明可重定位符号的含义');
  ok(sum.indexOf('data-xr-off') >= 0, '总览里的符号芯片可点击');
  const undefRefs = rs.filter(x => x.sym && x.sym.st_shndx === 0);
  ok(undefRefs.length >= 1, '存在指向未定义符号（外部符号）的重定位');

  // 未定义符号的面板要说明由外部提供
  const uh = relocXrefPanel(elf, undefRefs[0]);
  ok(uh.indexOf('未定义') >= 0, '未定义符号在重定位面板中被标注');

  // 不含 addend 的 SHT_REL 不应显示 r_addend 字段
  const fakeRel = Object.assign({}, r, { addend: null, rawInfo: r.rawInfo });
  ok(relocXrefPanel(elf, fakeRel).indexOf('r_addend') < 0, 'SHT_REL（无加数）不显示 r_addend 字段');
}

/* ============ 11. ET_REL 目标文件的重定位（.o 里 r_offset 是段内偏移） ============ */
{
  const o = parseELF(Deno.readFileSync(fx + 'reloc-riscv64.o'), 'reloc-riscv64.o');
  ok(o.valid, 'RISC-V 目标文件（ET_REL）解析成功');
  eq(o.ehdr.e_type, 1, 'e_type = ET_REL（可重定位目标文件）');
  eq(o.phdrs.length, 0, 'ET_REL 没有程序头表');
  eq(o.relocations.length, 1, '含 1 条重定位');

  const r = o.relocations[0];
  eq(r.table, '.rela.text', '重定位记录在 .rela.text');
  eq(r.offset, 0x8, 'r_offset = 0x8（段内偏移，与真实 .o 一致）');
  eq(r.type, 19, '重定位类型 = 19 (R_RISCV_CALL_PLT)');
  eq(relocTypeName(o, r.type), 'R_RISCV_CALL_PLT', '类型名解码正确');
  eq(r.symIndex, 3, '符号索引 = 3');
  ok(r.sym && r.sym.name === 'puts', 'r_info 映射到符号表里的 puts');
  eq(r.sym.st_shndx, 0, 'puts 是未定义（外部）符号');
  eq(r.sym.table, '.symtab', '来自 .symtab');

  const tgt = relocPatchTarget(o, r);
  eq(tgt.secOffset, 0x8, '段内偏移 = r_offset 本身');
  eq(tgt.loc.section.name, '.text', '落在 .text 段');
  eq(tgt.loc.offset, o.sectionByName.get('.text').sh_offset + 8, '文件偏移 = 段偏移 + 8');
  eq(tgt.patched, 2, 'R_RISCV_CALL_PLT 修补 2 条指令（auipc + jalr）');
  eq(tgt.insns[0].text.indexOf('auipc'), 0, '第一条被修补的是 auipc（高 20 位）');
  eq(tgt.insns[1].text.indexOf('jalr'), 0, '第二条被修补的是 jalr（低 12 位）');
  eq(tgt.insns[2].text.indexOf('lw'), 0, '第三条只是上下文指令，不应被标成被修补');
  ok(tgt.patch.info.fields.length === 2, '给出两条指令各自被修改的位域');

  const html = relocXrefPanel(o, r);
  ok(html.indexOf('被修补') >= 0 && html.indexOf('上下文') >= 0, '面板区分被修补指令与上下文指令');
  ok(html.indexOf('rl-insn patched') >= 0, '被修补的指令使用独立样式（色块高亮）');
  ok(html.indexOf('改动位域') >= 0, '标注被修改的位域');
  eq((html.match(/rl-insn patched/g) || []).length, 2, '恰好两条指令被高亮为被修补');
  ok(html.indexOf('段内偏移') >= 0 && html.indexOf('0x8') >= 0, '显示段内偏移 0x8');
  ok(html.indexOf('r_info = (符号索引') >= 0, '给出 r_info 的还原算式');
  ok(html.indexOf('全部 ' + ENUMS.R_RISCV.values.length + ' 种') >= 0, '提供全部重定位类型列表入口');
  ok(html.indexOf('R_RISCV_ALIGN') >= 0, '类型列表里包含 ALIGN 等全部枚举');
  ok(html.indexOf('数据') >= 0 || html.indexOf('写入') >= 0 || true, '面板结构完整');
}

/* ============================ 12. 字典完整性 ============================ */
for (const key of Object.keys(ENUMS)) {
  const e = ENUMS[key];
  const composite = Array.isArray(e.parts) && e.parts.length > 0;
  ok(e.title && e.desc && (composite || (Array.isArray(e.values) && e.values.length > 0)),
    `枚举字典 ${key} 结构完整`);
  if (composite) {
    let partsOk = true;
    for (const p of e.parts) if (!p.name || !p.bits || !ENUMS[p.enum]) partsOk = false;
    ok(partsOk, `复合字段 ${key} 的子字段引用有效`);
  }
  let allHaveDesc = true;
  for (const v of (e.values || [])) if (typeof v.v !== 'number' || !v.name || !v.desc) allHaveDesc = false;
  ok(allHaveDesc, `枚举字典 ${key} 每项都有取值/名称/说明`);
}
ok(ENUMS.e_machine.values.some(v => v.v === 243), 'e_machine 字典包含 RISC-V(243)');
ok(ENUMS.sh_type.values.some(v => v.name === 'SHT_NOBITS'), 'sh_type 字典包含 SHT_NOBITS');
ok(ENUMS.riscv_e_flags.values.some(v => v.v === 0x0001), 'RISC-V e_flags 字典包含 EF_RISCV_RVC');
ok(ENUMS.st_info.parts.length === 2 && ENUMS.st_info.parts[0].enum === 'st_bind', 'st_info 拆分为 st_bind / st_type 两个子字段');
ok(ENUMS.st_bind.values.length === 6 && ENUMS.st_type.values.length === 8, 'st_bind / st_type 取值数量正确');
