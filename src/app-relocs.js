/* ============================================================================
 * app-relocs.js — 重定位表（.rela.text 等）可视化解析面板
 *
 * 一条重定位项说清三件事：在哪儿改（r_offset）、按什么规则改（r_info 的类型）、
 * 改成谁（r_info 里的符号索引 → 符号表项 → 符号名 → 符号指向的内容）。
 * 本面板把这条链路画出来，并把 r_info 的位域拆成「符号索引 + 重定位类型」两段。
 * ==========================================================================*/
'use strict';

const RELOC_FIELD_COLORS = {
  r_offset: '#4dabf7', r_info: '#ffa94d', r_addend: '#22b8cf',
  'sym_index': '#f783ac', 'type': '#ffd06b'
};

function relocFieldColor(n) { return RELOC_FIELD_COLORS[n] || '#8d9bb0'; }

/** 重定位项字段（含 r_info 的位域拆分） */
function relocFieldGroups(elf, r) {
  const bits = elf.is64 ? 64 : 32;
  const groups = [];
  for (const f of RELA_FIELDS[bits]) {
    if (f.onlyRela && r.addend === null) continue;
    const raw = [];
    for (let i = 0; i < f.size; i++) raw.push(elf.bytes[r.fileOff + f.off + i]);
    const val = f.name === 'r_offset' ? r.offset : f.name === 'r_info' ? r.rawInfo : r.addend;
    groups.push({ name: f.name, size: f.size, raw: raw, value: val, desc: f.desc });
    if (f.name === 'r_info') {                            // 拆出打包字段的两半
      const half = f.size / 2;
      const typeBits = bits === 64 ? 32 : 8;
      groups.push({
        name: 'sym_index', size: half, bitsNote: 'r_info 高 ' + typeBits + ' 位',
        raw: raw.slice(bits === 64 ? 4 : 1), value: r.symIndex,
        desc: '指向符号表中的第 ' + r.symIndex + ' 项（这就是「改成谁」）'
      });
      groups.push({
        name: 'type', size: half, bitsNote: 'r_info 低 ' + typeBits + ' 位',
        raw: raw.slice(0, bits === 64 ? 4 : 1), value: r.type,
        desc: '重定位类型 ' + relocTypeName(elf, r.type) + '（这就是「按什么规则改」）'
      });
    }
  }
  return groups;
}

/* ---------------------------------------------------------------------------
 * 各类重定位「到底改哪条指令的哪些位」——这是 RISC-V 重定位的核心知识点：
 * 定长指令装不下完整地址，于是拆成 HI20/LO12 之类的组合，由链接器分别回填。
 * ------------------------------------------------------------------------- */
/* 每条说明都必须「自包含」：单独点开任意一条都能读懂，
   不允许出现「同上 / 同样 / 如前」这类必须依赖上一条才能理解的措辞。 */
const RV_RELOC_PATCH = {
  R_RISCV_CALL: {
    n: 2, fields: ['imm[31:12]（auipc 高 20 位）', 'imm[11:0]（jalr 低 12 位）'],
    note: '把 auipc + jalr 这一对指令改写成一次完整的函数调用：auipc 填入「目标地址 − 当前指令地址」的高 20 位，' +
      '紧跟的 jalr 填入低 12 位并跳到该地址。两个立即数合起来才构成完整调用目标。'
  },
  R_RISCV_CALL_PLT: {
    n: 2, fields: ['imm[31:12]（auipc 高 20 位）', 'imm[11:0]（jalr 低 12 位）'],
    note: '把 auipc + jalr 这对指令改写成一次函数调用（auipc 填高 20 位、jalr 填低 12 位并跳转），但跳转目的地不是函数本体而是 PLT 桩：' +
      '当被调用函数定义在别的模块、需要动态链接器参与解析时，链接器先把调用指向 .plt 中的一小段桩代码，' +
      '桩再按需解析出真实地址并跳过去。因此这种重定位在依赖外部库的程序里最常出现。'
  },
  R_RISCV_PCREL_HI20: {
    n: 1, fields: ['imm[31:12]（auipc 高 20 位）'],
    note: '改写 auipc 指令的 imm[31:12]：写入「目标地址 − 当前指令地址」的高 20 位。' +
      '低 12 位要靠随后配对出现的 R_RISCV_PCREL_LO12_I/S 补上，两条重定位合起来才是一个完整的 PC 相对地址。'
  },
  R_RISCV_HI20: {
    n: 1, fields: ['imm[31:12]（lui 高 20 位）'],
    note: '改写 lui 指令的 imm[31:12]：写入目标符号绝对地址的高 20 位。' +
      '低 12 位由配对的 R_RISCV_LO12_I/S 补齐，用于访问地址固定的全局变量或常量。'
  },
  R_RISCV_GOT_HI20: {
    n: 1, fields: ['imm[31:12]（auipc 高 20 位）'],
    note: '改写 auipc 指令的 imm[31:12]：写入该符号在 GOT（全局偏移表）中表项地址的高 20 位。' +
      '配合低 12 位算出表项地址后，程序先从 GOT 表项里取出符号真实地址，再间接访问——' +
      '这是位置无关代码（PIE / 共享库）引用外部符号的标准做法。'
  },
  R_RISCV_TLS_GOT_HI20: {
    n: 1, fields: ['imm[31:12]（auipc 高 20 位）'],
    note: '改写 auipc 指令的 imm[31:12]：写入线程局部变量在 GOT 中表项地址的高 20 位。' +
      '这是 TLS 的 initial-exec 访问模型：程序从 GOT 表项取出「相对线程指针的偏移」，再据此定位变量。'
  },
  R_RISCV_TLS_GD_HI20: {
    n: 1, fields: ['imm[31:12]（auipc 高 20 位）'],
    note: '改写 auipc 指令的 imm[31:12]：写入 TLS 索引的高 20 位。' +
      '这是 TLS 的通用动态模型：程序先用该索引调用 __tls_get_addr，由运行期库算出当前线程中变量的地址，' +
      '因此可以在运行期才加载的共享库里访问线程局部变量。'
  },
  R_RISCV_LO12_I: {
    n: 1, fields: ['imm[11:0]（I 型立即数）'],
    note: '改写 I 型指令（addi / lw / ld / jalr / csrr 等）的 imm[11:0]：写入目标地址的低 12 位。' +
      '它总是与一条提供高 20 位的重定位配对使用，两者合起来构成完整地址。'
  },
  R_RISCV_PCREL_LO12_I: {
    n: 1, fields: ['imm[11:0]（I 型立即数）'],
    note: '改写 I 型指令的 imm[11:0]：写入「目标地址 − auipc 所在地址」的低 12 位。' +
      '链接器靠这条重定位引用的标签找到与它配对的那条 PCREL_HI20，从而把高低位凑成同一个目标地址。'
  },
  R_RISCV_TPREL_LO12_I: {
    n: 1, fields: ['imm[11:0]（I 型立即数）'],
    note: '改写 I 型指令的 imm[11:0]：写入「目标地址 − 线程指针 tp」的低 12 位。' +
      '它与提供高位的 TPREL_HI20 配对，用于按线程指针直接访问线程局部变量。'
  },
  R_RISCV_LO12_S: {
    n: 1, fields: ['imm[11:5]', 'imm[4:0]'],
    note: '改写 S 型存储指令（sw / sd / fsw / fsd）的低 12 位偏移：该偏移在 S 型编码里被拆成 imm[11:5] 与 imm[4:0] 两段，' +
      '链接器按位域分别回填。它与提供高 20 位的重定位配对，构成完整目标地址。'
  },
  R_RISCV_PCREL_LO12_S: {
    n: 1, fields: ['imm[11:5]', 'imm[4:0]'],
    note: '改写 S 型存储指令的两段低 12 位偏移（imm[11:5] 与 imm[4:0]）：写入「目标地址 − auipc 所在地址」的低 12 位，' +
      '与同组的 R_RISCV_PCREL_HI20 配对，用于向 PC 相对位置写数据。'
  },
  R_RISCV_TPREL_LO12_S: {
    n: 1, fields: ['imm[11:5]', 'imm[4:0]'],
    note: '改写 S 型存储指令的两段低 12 位偏移（imm[11:5] 与 imm[4:0]）：写入「目标地址 − 线程指针 tp」的低 12 位，' +
      '与同组的 TPREL_HI20 配对，用于写入线程局部变量。'
  },
  R_RISCV_JAL: {
    n: 1, fields: ['imm[20|10:1|11|19:12]'],
    note: '改写 jal 指令的 20 位跳转偏移：该偏移在 J 型编码里被拆散到 imm[20|10:1|11|19:12] 四处，' +
      '链接器按位域分别回填「目标地址 − 当前指令地址」，使跳转落到目标上。'
  },
  R_RISCV_RVC_JUMP: {
    n: 1, fields: ['CJ 编码的跳转偏移位域'],
    note: '改写压缩指令 c.j / c.jal 的跳转偏移（CJ 格式把偏移散落在多个位域中）：' +
      '压缩格式能表示的偏移范围远小于 32 位的 jal，因此只适用于近距离跳转。'
  },
  R_RISCV_BRANCH: {
    n: 1, fields: ['imm[12|10:5]', 'imm[4:1|11]'],
    note: '改写条件分支指令（beq / bne / blt / bge / bltu / bgeu）的 12 位跳转偏移：' +
      '该偏移在 B 型编码里被拆成 imm[12|10:5] 与 imm[4:1|11] 两段，链接器按位域分别回填。'
  },
  R_RISCV_RVC_BRANCH: {
    n: 1, fields: ['CB 编码的偏移位域'],
    note: '改写压缩条件分支指令 c.beqz / c.bnez 的偏移字段（CB 格式，偏移位域是散开的）：' +
      '它能表达的跳转范围比标准 B 型分支更小，仅适合短距离分支。'
  },
  R_RISCV_ALIGN: {
    n: 0,
    note: '这一条不写入任何数据：它标记「链接器可能需要在此处插入或删除若干填充字节以满足对齐要求」。' +
      '一旦填充长度改变，该位置之后所有指令的地址都会整体前移或后移，因此链接器必须同时修正其后所有重定位。'
  },
  R_RISCV_RELAX: {
    n: 0,
    note: '这一条不写入任何数据：它标记紧邻其上的那条重定位所覆盖的指令序列「可以被收缩」。' +
      '链接器若确认目标地址落在更短指令的可达范围内，就把这段序列换成等价但更短的指令' +
      '（例如把 8 字节的 auipc + jalr 调用换成 4 字节的 jal），并相应修正其后所有地址。'
  },
  R_RISCV_ADD8: { n: 0, data: true, note: '把符号地址与 addend 相加后的结果，按 1 字节宽度加到目标位置原有数据上（多用于 DWARF 调试信息里表达标签之间的距离）。' },
  R_RISCV_ADD16: { n: 0, data: true, note: '把符号地址与 addend 相加后的结果，按 2 字节宽度加到目标位置原有数据上。' },
  R_RISCV_ADD32: { n: 0, data: true, note: '把符号地址与 addend 相加后的结果，按 4 字节宽度加到目标位置原有数据上。' },
  R_RISCV_ADD64: { n: 0, data: true, note: '把符号地址与 addend 相加后的结果，按 8 字节宽度加到目标位置原有数据上。' },
  R_RISCV_SUB8: { n: 0, data: true, note: '把符号地址与 addend 相加后的结果，按 1 字节宽度从目标位置原有数据中减去（常用于表达两个标签之间的距离）。' },
  R_RISCV_SUB16: { n: 0, data: true, note: '把符号地址与 addend 相加后的结果，按 2 字节宽度从目标位置原有数据中减去。' },
  R_RISCV_SUB32: { n: 0, data: true, note: '把符号地址与 addend 相加后的结果，按 4 字节宽度从目标位置原有数据中减去。' },
  R_RISCV_SUB64: { n: 0, data: true, note: '把符号地址与 addend 相加后的结果，按 8 字节宽度从目标位置原有数据中减去。' },
  R_RISCV_RELATIVE: {
    n: 0, data: true,
    note: '不需要符号（r_info 的符号索引为 0）：把「加载基址 + addend」写入目标位置。' +
      '动态链接器据此把程序/共享库里预先写死的占位值改成运行期真实地址，是位置无关代码最基础的重定位。'
  },
  R_RISCV_32: { n: 0, data: true, note: '把符号地址加上 addend 的结果，按 32 位宽度以绝对值形式写入目标位置（不做 PC 相对计算，通常用于数据指针表）。' },
  R_RISCV_64: { n: 0, data: true, note: '把符号地址加上 addend 的结果，按 64 位宽度以绝对值形式写入目标位置（不做 PC 相对计算，通常用于数据指针表）。' },
  R_RISCV_JUMP_SLOT: {
    n: 0, data: true,
    note: '写入目标函数的真实地址，落点是 GOT 中的跳转槽：PLT 桩第一次被调用时由动态链接器填好这里，之后的调用就直接命中真实地址，不再解析。'
  },
  R_RISCV_TLS_DTPMOD32: { n: 0, data: true, note: '写入该线程局部变量所属模块的 TLS 模块 ID（32 位），它是 __tls_get_addr 所需 TLS 索引的一半。' },
  R_RISCV_TLS_DTPMOD64: { n: 0, data: true, note: '写入该线程局部变量所属模块的 TLS 模块 ID（64 位），它是 __tls_get_addr 所需 TLS 索引的一半。' },
  R_RISCV_TLS_DTPREL32: { n: 0, data: true, note: '写入该线程局部变量在其 TLS 块内的偏移（32 位），它是 __tls_get_addr 所需 TLS 索引的另一半。' },
  R_RISCV_TLS_DTPREL64: { n: 0, data: true, note: '写入该线程局部变量在其 TLS 块内的偏移（64 位），它是 __tls_get_addr 所需 TLS 索引的另一半。' },
  R_RISCV_TLS_TPREL32: { n: 0, data: true, note: '写入该线程局部变量相对线程指针 tp 的偏移（32 位），用于按线程指针直接寻址的访问方式。' },
  R_RISCV_TLS_TPREL64: { n: 0, data: true, note: '写入该线程局部变量相对线程指针 tp 的偏移（64 位），用于按线程指针直接寻址的访问方式。' }
};

/** 该重定位类型的修补说明 */
function relocPatchInfo(elf, r) {
  const name = relocTypeName(elf, r.type);
  return { name: name, info: RV_RELOC_PATCH[name] || null };
}

/**
 * 同一个重定位表里紧邻在当前项之前的那一条（重定位表是有序的）。
 * R_RISCV_RELAX / R_RISCV_ALIGN 这类「修饰项」按 ABI 约定修饰的就是紧邻其上的那条。
 */
function prevRelocInTable(elf, r) {
  const list = elf.relocations.filter(function (x) { return x.table === r.table; });
  const pos = list.findIndex(function (x) { return x.index === r.index; });
  return pos > 0 ? list[pos - 1] : null;
}

/** 该类型是不是「修饰项」（本身不写数据、不引用符号，只修饰上一条重定位） */
function isRelocModifier(elf, r) {
  const info = relocPatchInfo(elf, r).info;
  if (!info) return false;
  return info.n === 0 && !info.data;
}

/**
 * 被修补位置：返回段内偏移、文件偏移、以及被修改的那几条指令 / 那几个字节
 * 区分「被修补的指令」与「后续上下文指令」，并给出被修改的位域。
 */
function relocPatchTarget(elf, r) {
  const loc = vaddrToOffset(elf, r.offset);
  const out = { loc: loc, patch: relocPatchInfo(elf, r), insns: [], patched: 0, data: null };
  if (!loc || !loc.section) return out;
  const sec = loc.section;
  out.secOffset = r.offset - sec.sh_addr;             // ET_REL 下这就是 r_offset 本身的含义
  const bytes = sectionBytes(elf, sec);
  const pos = loc.offset - sec.sh_offset;
  if (pos < 0 || pos >= bytes.length) return out;
  const isCode = (sec.sh_flags & 0x4) !== 0;

  if (isCode && elf.arch === 'riscv') {
    try {
      out.insns = riscvDisassemble(bytes.subarray(pos), r.offset, {
        bits: elf.is64 ? 64 : 32, symbols: new Map(),
        hasRVC: (elf.ehdr.e_flags & 1) === 1, forceC: 'auto',
        fileBase: loc.offset, maxBytes: 16
      }).slice(0, 3);
    } catch (e) { out.insns = []; }
    // 已知类型：明确标出前 N 条是被修补的；未知类型：不臆断，只作上下文
    const want = out.patch.info ? out.patch.info.n : -1;
    if (want >= 0) out.patched = Math.min(want, out.insns.length);
    else out.unknownPatch = true;
  } else {
    // 数据位置：显示将被写入的那几个字节
    const size = elf.is64 ? 8 : 4;
    const raw = [];
    for (let i = 0; i < size && pos + i < bytes.length; i++) raw.push(bytes[pos + i]);
    out.data = { size: size, raw: raw };
  }
  return out;
}

/** 该重定位类型在本架构下的全部可选取值 */
function relocTypeEnumKey(elf) {
  return elf.arch === 'riscv' ? 'R_RISCV' : (elf.arch === 'x86-64' ? 'R_X86_64' : null);
}

/** 单个重定位项的解析面板 */
function relocXrefPanel(elf, r) {
  if (!r) return '';
  const entsz = elf.is64 ? (r.addend === null ? 16 : 24) : (r.addend === null ? 8 : 12);
  const sym = r.sym || null;                 // 解析阶段已按 sh_link 关联好符号表项
  const groups = relocFieldGroups(elf, r);
  const tgt = relocPatchTarget(elf, r);
  const loc = tgt.loc;
  const insns = tgt.insns;
  const patchInfo = tgt.patch.info;
  const typeName = relocTypeName(elf, r.type);
  const typeEntry = enumEntry(elf.arch === 'riscv' ? 'R_RISCV' : 'R_X86_64', r.type);
  const modifier = isRelocModifier(elf, r);            // RELAX / ALIGN：修饰上一条的标记项
  const prevR = modifier ? prevRelocInTable(elf, r) : null;
  const nullSym = r.symIndex === 0;                    // 索引 0 = 空符号（STN_UNDEF）

  // ---- 表项字节，按字段着色 ----
  const byteCells = groups.map(function (g) {
    return '<span class="xs-field" style="--fc:' + relocFieldColor(g.name) + '" title="' +
      esc(g.name + (g.bitsNote ? '（' + g.bitsNote + '）' : '（' + g.size + ' 字节）')) + '">' +
      '<i>' + esc(g.name) + '</i>' +
      '<b class="mono">' + g.raw.map(byteHex).join(' ') + '</b></span>';
  }).join('');

  // ---- r_info 位域条：符号索引 | 类型 ----
  const halfBits = elf.is64 ? 32 : 24, typeBits = elf.is64 ? 32 : 8;
  // 用「符号索引 << 类型位宽 | 类型」精确还原位串，避免大整数精度损失
  const infoBin = ((BigInt(r.symIndex) << BigInt(typeBits)) | BigInt(r.type))
    .toString(2).padStart(halfBits + typeBits, '0');
  const infoStrip =
    '<div class="rl-strip">' +
    '<span class="rl-seg" style="flex:' + halfBits + ';--rc:' + relocFieldColor('sym_index') + '">' +
    '<i>sym_index（高 ' + halfBits + ' 位）</i><b class="mono">' + infoBin.slice(0, halfBits) + '</b>' +
    '<em class="mono">= ' + r.symIndex + '</em></span>' +
    '<span class="rl-seg" style="flex:' + typeBits + ';--rc:' + relocFieldColor('type') + '">' +
    '<i>type（低 ' + typeBits + ' 位）</i><b class="mono">' + infoBin.slice(halfBits) + '</b>' +
    '<em class="mono">= ' + r.type + ' → ' + esc(typeName) + '</em></span>' +
    '</div>';

  // ---- 字段表 ----
  const rows = groups.map(function (g) {
    return '<tr><td class="mono xs-fname" style="color:' + relocFieldColor(g.name) + '">' + esc(g.name) +
      (g.bitsNote ? '<br><span class="muted">' + esc(g.bitsNote) + '</span>' : '') + '</td>' +
      '<td class="mono">' + esc(hx(g.value)) + '</td>' +
      '<td class="xs-mean">' + esc(g.desc) + '</td></tr>';
  }).join('');

  // ---- 修饰项（RELAX / ALIGN）：说明它修饰的是哪一条，而不是自己「改成谁」 ----
  if (modifier) {
    const prevName = prevR ? relocTypeName(elf, prevR.type) : null;
    const prevTarget = prevR ? relocPatchTarget(elf, prevR) : null;
    const seq = (prevTarget && prevTarget.insns.length)
      ? prevTarget.insns.slice(0, Math.max(1, prevTarget.patched || 1)).map(function (ins) {
        return '<div class="rl-insn relaxable" data-xr-off="' + ins.fileOffset + '" data-xr-size="' + ins.size + '">' +
          '<span class="rl-tag">可松弛</span>' +
          '<span class="sp-addr">' + hx(ins.addr) + '</span>' +
          '<span class="sp-bytes">' + Array.prototype.slice.call(ins.bytes).map(byteHex).join(' ') + '</span>' +
          '<span class="sp-text">' + esc(ins.text) + '</span></div>';
      }).join('')
      : '';
    return '<div class="xs rl" data-table="' + esc(r.table) + '">' +
      '<div class="xs-head"><b class="mono">' + esc(r.table) + '[' + r.index + ']</b>' +
      '<span class="pill">' + esc(typeName) + '</span>' +
      '<span class="pill" style="border-color:#6b5a1e;color:#ffd43b">修饰项 · 不写数据</span>' +
      '<span class="muted">表项 @' + hx(r.fileOff) + '，' + entsz + ' 字节</span>' +
      '<span class="xs-actions">' +
      '<button class="mini" data-xr-off="' + r.fileOff + '" data-xr-size="' + entsz + '">表项字节</button>' +
      (prevR ? '<button class="mini" data-xr-prev="' + prevR.index + '">展开它修饰的上一条 →</button>' : '') +
      '</span></div>' +
      '<div class="xs-bytes">' + byteCells + '</div>' +
      '<div class="rl-mod-banner">' +
      '<b>这一项不是独立的符号引用，而是「修饰项」。</b><br>' +
      '它的 <span class="mono">r_info</span> 里符号索引为 <b class="mono">0</b>（空符号 STN_UNDEF），加数为 0 —— 也就是说它<b>不引用任何符号</b>；' +
      '按 RISC-V psABI 的约定，这类条目<b>修饰的是紧邻其上的那一条重定位</b>' +
      (prevR ? '（就是 <b>' + esc(prevR.table + '[' + prevR.index + '] ' + prevName) + '</b>，两者的 r_offset 相同：' +
        hx(prevR.offset) + '）。' : '。') +
      '</div>' +
      '<div class="rl-info-title">修饰含义</div>' +
      '<div class="rl-patch-note">' + esc(patchInfo.note) + '</div>' +
      (seq ? '<div class="xs-sub">它修饰的指令序列（来自上一条重定位，' +
        esc(prevName) + ' 覆盖的字节）</div>' +
        '<div class="rl-insns">' + seq + '</div>' +
        '<div class="rl-mod-example">松弛后：链接器若判定目标在可达范围内，就把这段序列收缩成更短的等价指令' +
        '（例如 ' + (prevName === 'R_RISCV_CALL_PLT' || prevName === 'R_RISCV_CALL'
          ? '把 <b class="mono">auipc + jalr</b> 两条 8 字节的调用序列替换成一条 4 字节的 <b class="mono">jal</b>'
          : '把 auipc + addi/lw 序列缩减成 lui/addi/单条指令') +
        '），并相应调整后续地址。</div>' : '') +
      '<div class="xs-sub">字段解析</div>' +
      '<table class="grid compact xs-table"><thead><tr><th>字段</th><th>原始值</th><th>含义</th></tr></thead>' +
      '<tbody>' + rows + '</tbody></table>' +
      '<div class="rl-info-math">' + esc(typeName) + ' 的 r_info 还原：<b class="mono">r_info = (符号索引 &lt;&lt; ' + typeBits +
      ') | 类型 → (0 &lt;&lt; ' + typeBits + ') | ' + r.type + ' = ' + esc(hx(r.rawInfo)) + '</b>' +
      '　符号索引恒为 0，这正是「它不是符号引用、而是标记」的格式证据。</div>' +
      relocTypeCatalog(elf, r.type) +
      '</div>';
  }

  // ---- 被修补的位置：指令级高亮 + 被修改的位 ----
  let patchHtml = '';
  if (loc) {
    const where = '<span class="rl-where">' +
      (tgt.secOffset !== undefined ? '<b class="mono">' + hx(tgt.secOffset) + '</b>（段内偏移）' : '') +
      ' → <b class="mono">' + hx(loc.offset) + '</b>（文件偏移）' +
      (loc.section ? ' → <b>' + esc(loc.section.name) + '</b>' : '') + '</span>';
    if (insns.length) {
      const insnRow = function (ins, idx, isPatched) {
        const fieldNote = isPatched && patchInfo && patchInfo.fields[idx + 1]
          ? patchInfo.fields[idx + 1] : (isPatched && patchInfo && patchInfo.fields.length === 1 ? patchInfo.fields[0] : '');
        const bytes = Array.prototype.slice.call(ins.bytes).map(byteHex).join(' ');
        // 被修补的指令用色块强调，并标出这条指令里被改动的位域
        const fieldChips = (isPatched && patchInfo)
          ? (patchInfo.fields.length > 1
            ? '<span class="rl-field">改动位域 <b class="mono">' + esc(patchInfo.fields[idx] || patchInfo.fields[0]) + '</b></span>'
            : '<span class="rl-field">改动位域 <b class="mono">' + esc(patchInfo.fields[0]) + '</b></span>')
          : '';
        return '<div class="rl-insn' + (isPatched ? ' patched' : ' context') + '"' +
          ' data-xr-off="' + ins.fileOffset + '" data-xr-size="' + ins.size + '">' +
          '<span class="rl-tag">' + (isPatched ? '被修补' : '上下文') + '</span>' +
          '<span class="sp-addr">' + hx(ins.addr) + '</span>' +
          '<span class="sp-bytes">' + bytes + '</span>' +
          '<span class="sp-text">' + esc(ins.text) + '</span>' + fieldChips + '</div>';
      };
      let patchedIdx = 0;
      const rendered = insns.map(function (ins, i) {
        if (i < tgt.patched) { const html = insnRow(ins, patchedIdx, true); patchedIdx++; return html; }
        return insnRow(ins, i, false);
      }).join('');
      patchHtml = '<div class="rl-chain"><span class="rl-label">在哪儿改</span><span class="xr-arrow">→</span>' +
        '<span class="rl-body"><span class="rl-where-wrap">' + where + '</span></span></div>' +
        '<div class="rl-insns">' + rendered + '</div>' +
        '<div class="rl-patch-note">' +
        (tgt.unknownPatch
          ? '该类型的修补方式未收录，上面只是该位置的指令上下文。'
          : (patchInfo
            ? '<b>' + esc(typeName) + '</b>：' + esc(patchInfo.note) +
              (patchInfo.n > 1 ? '（共涉及 ' + patchInfo.n + ' 条指令）' : '')
            : '')) +
        '</div>';
    } else if (tgt.data) {
      patchHtml = '<div class="rl-chain"><span class="rl-label">在哪儿改</span><span class="xr-arrow">→</span>' +
        '<span class="rl-body">' + where + '</span></div>' +
        '<div class="rl-insns"><div class="rl-insn patched" data-xr-off="' + loc.offset + '" data-xr-size="' + tgt.data.size + '">' +
        '<span class="rl-tag">被写入</span>' +
        '<span class="sp-addr">' + hx(loc.offset) + '</span>' +
        '<span class="sp-bytes">' + tgt.data.raw.map(byteHex).join(' ') + '</span>' +
        '<span class="sp-text muted">这 ' + tgt.data.size + ' 个字节将被重定位结果覆盖</span></div></div>' +
        '<div class="rl-patch-note">' + (patchInfo ? '<b>' + esc(typeName) + '</b>：' + esc(patchInfo.note) : '') + '</div>';
    }
  } else {
    patchHtml = '<div class="rl-chain"><span class="rl-label">在哪儿改</span><span class="xr-arrow">→</span>' +
      '<span class="rl-body"><span class="xr-chip dim">r_offset 没有映射到文件字节（可能位于 .bss 或需要加载时才有地址）</span></span></div>';
  }

  // ---- 引用关系链路（改成谁 / 按什么规则改 / 加数）----
  const chain = [];
  chain.push({
    label: '改成谁', arrow: '→',
    body: nullSym
      ? '<span class="xr-chip dim">符号索引 0 = 空符号（STN_UNDEF）——本条不引用任何符号</span>' +
        '<span class="muted">' + (modifier ? '它只是标记项' : '例如 R_RISCV_RELATIVE 这类只依赖加载基址的重定位') + '</span>'
      : (sym
      ? chip('符号表项 ' + sym.table + '[' + sym.index + '] @' + hx(sym.fileOff), sym.fileOff, elf.is64 ? 24 : 16, 'shdr') +
        chip('“' + (sym.name || '(匿名)') + '”' + (sym.fileOffset !== undefined ? ' @' + hx(sym.fileOffset) : ''),
          sym.fileOffset, Math.max(1, Math.min(sym.st_size || 1, 4096)), 'content') +
        '<span class="muted">' + (sym.st_shndx === 0 ? '（未定义符号：由外部提供）' : '（定义于 ' + esc(sym.sec) + '）') + '</span>'
      : '<span class="xr-chip dim">符号索引 ' + r.symIndex + ' 在符号表中找不到对应项</span>')
  });
  chain.push({
    label: '按什么规则改', arrow: '→',
    body: '<span class="xr-chip dim">' + esc(typeName) + '</span>' +
      (typeEntry ? '<span class="muted">' + esc(typeEntry.desc) + '</span>' : '<span class="muted">（字典中暂无该类型的说明）</span>')
  });
  if (r.addend !== null && r.addend !== undefined) {
    chain.push({
      label: '加数', arrow: '+',
      body: '<span class="xr-chip dim">' + r.addend + '（' + hx(r.addend < 0 ? -r.addend : r.addend) + '）</span>' +
        '<span class="muted">最终写入值 = 符号地址 + addend' +
        (typeName.indexOf('RELATIVE') >= 0 ? '（RELATIVE 时符号地址换成加载基址）' : '') + '</span>'
    });
  }
  const chainHtml = chain.map(function (c) {
    return '<div class="rl-chain"><span class="rl-label">' + esc(c.label) + '</span>' +
      '<span class="xr-arrow">' + c.arrow + '</span><span class="rl-body">' + c.body + '</span></div>';
  }).join('');

  return '<div class="xs rl" data-table="' + esc(r.table) + '">' +
    '<div class="xs-head"><b class="mono">' + esc(r.table) + '[' + r.index + ']</b>' +
    '<span class="pill">' + esc(typeName) + '</span>' +
    '<span class="muted">表项 @' + hx(r.fileOff) + '，' + entsz + ' 字节</span>' +
    '<span class="xs-actions">' +
    '<button class="mini" data-xr-off="' + r.fileOff + '" data-xr-size="' + entsz + '">表项字节</button>' +
    (loc ? '<button class="mini" data-xr-off="' + loc.offset + '" data-xr-size="4">被修补位置</button>' : '') +
    (sym ? '<button class="mini" data-xr-sym="' + elf.symbols.indexOf(sym) + '">符号表项</button>' : '') +
    (sym && sym.fileOffset !== undefined ? '<button class="mini" data-xr-off="' + sym.fileOffset + '" data-xr-size="16">符号内容</button>' : '') +
    '</span></div>' +
    '<div class="xs-bytes">' + byteCells + '</div>' +
    '<div class="rl-info-title">r_info 位域拆解（一个 64 位整数里塞了「符号索引 + 类型」）</div>' +
    infoStrip +
    '<table class="grid compact xs-table"><thead><tr><th>字段</th><th>原始值</th><th>含义</th></tr></thead>' +
    '<tbody>' + rows + '</tbody></table>' +
    '<div class="rl-info-math">r_info 的还原方式：<b class="mono">r_info = (符号索引 &lt;&lt; ' + typeBits +
    ') | 类型</b>　→　<b class="mono">(' + r.symIndex + ' &lt;&lt; ' + typeBits + ') | ' + r.type + ' = ' + esc(hx(r.rawInfo)) + '</b></div>' +
    '<div class="xs-sub">被修补的位置（改的是哪条指令、哪几位）</div>' + patchHtml +
    '<div class="xs-sub">引用关系链路</div>' + chainHtml +
    relocTypeCatalog(elf, r.type) +
    '</div>';
}

/** 该架构下全部重定位类型（当前类型高亮），可展开查看 */
function relocTypeCatalog(elf, currentType) {
  const key = relocTypeEnumKey(elf);
  if (!key || !ENUMS[key]) {
    return '<div class="xs-sub">其它重定位类型</div><div class="muted">当前架构（' + esc(elf.arch) +
      '）暂未收录类型字典。</div>';
  }
  const e = ENUMS[key];
  const rows = e.values.map(function (v) {
    const on = v.v === currentType;
    return '<div class="ep-row' + (on ? ' on' : '') + '" data-rtype="' + v.v + '">' +
      '<span class="ep-val mono">' + v.v + '</span>' +
      '<span class="ep-name mono">' + esc(v.name) + '</span>' +
      '<span class="ep-desc">' + esc(v.desc) + '</span>' +
      '<span class="ep-mark">' + (on ? '✓ 本条重定位' : '') + '</span></div>';
  }).join('');
  return '<div class="xs-sub">全部 ' + e.values.length + ' 种 ' + e.title.split('—')[0].trim() +
    ' 重定位类型 <button class="mini rl-cat-toggle">展开 ▾</button></div>' +
    '<div class="rl-cat" hidden><div class="rl-cat-hint muted">点击任意类型可筛选其它重定位项（当前类型已高亮）</div>' +
    '<div class="ep-list">' + rows + '</div></div>';
}

/**
 * 重定位段总览：哪些符号是可重定位的（被重定位表引用的符号）
 * @param {object} elf
 * @param {object} sec .rela.* / .rel.* 段
 */
function relocSectionSummary(elf, sec) {
  const rs = elf.relocations.filter(function (r) { return r.table === sec.name; });
  if (!rs.length) return '';
  const bySym = new Map();
  let markers = 0;
  for (const r of rs) {
    // 修饰项（RELAX/ALIGN）与空符号不参与「引用目标」统计
    if (isRelocModifier(elf, r)) { markers++; continue; }
    if (r.symIndex === 0) { markers++; continue; }
    const key = r.symIndex;
    if (!bySym.has(key)) bySym.set(key, { idx: key, name: r.symbolName || (r.sym ? '(匿名符号)' : null), sym: r.sym, count: 0, types: new Set() });
    const e = bySym.get(key);
    e.count++;
    e.types.add(relocTypeName(elf, r.type));
  }
  const chips = Array.from(bySym.values()).sort(function (a, b) { return b.count - a.count; }).map(function (e) {
    const sym = e.sym;
    const off = sym ? sym.fileOff : null;
    const kind = sym ? (sym.st_shndx === 0 ? '未定义（外部符号）' : '定义于 ' + sym.sec) : '未知';
    return chip('#' + e.idx + ' ' + (e.name || '(匿名)') + ' ×' + e.count + ' · ' + kind, off, elf.is64 ? 24 : 16, sym && sym.st_shndx === 0 ? 'rela' : 'shdr');
  }).join('');
  return '<div class="rl-summary">' +
    '<div class="rl-sum-title">这段重定位涉及 <b>' + bySym.size + '</b> 个符号（它们就是需要被「重定位」的引用目标）' +
    (markers ? '，另有 <b>' + markers + '</b> 条是<b>修饰项 / 无符号项</b>（如 R_RISCV_RELAX，不引用符号、本身不写数据）' : '') + '：</div>' +
    '<div class="rl-chips">' + chips + '</div>' +
    '<div class="muted small">点芯片 → 跳到该符号在符号表中的表项；点下面任意一条重定位项 → 展开它的字段拆解与引用链路。</div>' +
    '</div>';
}

/** 在重定位表里就地展开 / 收起某条重定位项的面板 */
function toggleRelocXref(tr, r) {
  const tbl = tr.closest('table');
  const existed = $('.reloc-xref[data-for="' + r.table + '-' + r.index + '"]', tbl);
  $$('.reloc-xref', tbl).forEach(function (x) { x.remove(); });
  if (existed) return;
  const row = document.createElement('tr');
  row.className = 'reloc-xref';
  row.dataset.for = r.table + '-' + r.index;
  row.innerHTML = '<td colspan="' + tr.children.length + '">' + relocXrefPanel(S.elf, r) + '</td>';
  tr.after(row);
  wireXref(row);
  wireRelocExtras(row);
  row.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  setStatus('已展开重定位项解析：r_offset（在哪儿改）→ r_info（符号索引 + 类型）→ 符号表项 → 符号指向的内容。');
}

/** 面板内的额外交互：展开类型总表、按类型筛选 */
function wireRelocExtras(root) {
  // 修饰项面板里「展开它修饰的上一条」：切到那一条重定位的详情
  $$('[data-xr-prev]', root).forEach(function (b) {
    b.addEventListener('click', function (e) {
      e.stopPropagation();
      const idx = +b.dataset.xrPrev;
      const prev = S.elf.relocations.find(function (x) { return x.table === b.closest('.rl').dataset.table && x.index === idx; })
        || S.elf.relocations.find(function (x) { return x.index === idx; });
      if (!prev) return;
      // 优先在重定位页里点到对应行；找不到就直接把面板内容替换成上一条
      switchTab('relocs');
      const tr = $('.rel-row[data-off="' + prev.fileOff + '"]');
      if (tr) { tr.click(); }
      else { root.innerHTML = relocXrefPanel(S.elf, prev); wireXref(root); wireRelocExtras(root); }
      setStatus('已跳到它修饰的上一条重定位：' + prev.table + '[' + prev.index + '] ' + relocTypeName(S.elf, prev.type));
    });
  });
  const t = $('.rl-cat-toggle', root);
  const cat = $('.rl-cat', root);
  if (t && cat) {
    t.addEventListener('click', function (e) {
      e.stopPropagation();
      cat.hidden = !cat.hidden;
      t.textContent = cat.hidden ? '展开 ▾' : '收起 ▴';
      if (!cat.hidden) {
        const on = $('.ep-row.on', cat);
        if (on) cat.scrollTop = Math.max(0, on.offsetTop - cat.clientHeight / 2);
      }
    });
  }
  $$('.ep-row[data-rtype]', root).forEach(function (rowEl) {
    rowEl.addEventListener('click', function (e) {
      e.stopPropagation();
      const t2 = +rowEl.dataset.rtype;
      const e2 = enumEntry(relocTypeEnumKey(S.elf), t2);
      S.relocTypeFilter = (S.relocTypeFilter === t2) ? null : t2;
      renderRelocations();
      setStatus('重定位表已筛选为 ' + (S.relocTypeFilter === null ? '全部类型' :
        (e2 ? e2.name : t2) + '（' + (e2 ? e2.desc : '') + '）'));
    });
  });
}
