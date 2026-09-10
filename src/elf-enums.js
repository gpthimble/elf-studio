/* ============================================================================
 * elf-enums.js — 枚举取值解码（纯函数，不依赖 DOM）
 * ==========================================================================*/
'use strict';

function isFlagBit(v) { return v > 0 && (v & (v - 1)) === 0 && v < 0x10000000; }

function enumEntry(key, value) {
  const e = ENUMS[key];
  if (!e) return null;
  for (const v of e.values) if (v.v === value) return v;
  return null;
}

/** 复合字段（如 st_info 打包 bind/type）的子字段定义 */
function enumParts(key) {
  const e = ENUMS[key];
  return (e && e.parts) || null;
}

const FLOAT_ABI_TEXT = {
  0: 'Soft（软浮点，浮点参数通过整数寄存器传递）',
  2: 'Single (lp64f / ilp32f)',
  4: 'Double (lp64d / ilp32d)',
  6: 'Quad'
};

/** 把字段原始值翻译成人类可读的文本数组 */
function decodeValue(key, value) {
  const out = [];
  if (!key || value === undefined || value === null) return out;
  if (key === 'sh_flags' || key === 'p_flags') {
    for (const v of ENUMS[key].values) {
      if (isFlagBit(v.v)) { if (value & v.v) out.push(v.name); }
      else if (v.v >= 0x0ff00000 && (value & v.v)) out.push(v.name + ' ' + hx(value & v.v));
    }
    if (!out.length) out.push(value === 0 ? '（无标志位）' : '未知标志 ' + hx(value));
    return out;
  }
  if (key === 'riscv_e_flags') {
    out.push((value & 0x1) ? 'EF_RISCV_RVC：包含压缩指令（C 扩展）' : '未设置 EF_RISCV_RVC：目标文件不含压缩指令');
    out.push('浮点 ABI：' + (FLOAT_ABI_TEXT[value & 0x6] || '未知'));
    if (value & 0x8) out.push('EF_RISCV_RVE：RV32E 嵌入式变体（仅 16 个整数寄存器）');
    if (value & 0x10) out.push('EF_RISCV_TSO：Ztso 强序内存模型');
    if (value & 0x20) out.push('EF_RISCV_TAGGED_ADDR_ABI');
    const spec = (value & 0x700) >> 8;
    if (spec) out.push('RVC 扩展规范版本：2.' + spec);
    const known = 0x1 | 0x6 | 0x8 | 0x10 | 0x20 | 0x700;
    if (value & ~known) out.push('其它未识别位：' + hx(value & ~known));
    return out;
  }
  if (key === 'st_info') {
    const b = (value >> 4) & 0xf, t = value & 0xf;
    out.push('st_bind = ' + b + ' → ' + stBindName(b));
    out.push('st_type = ' + t + ' → ' + stTypeName(t));
    return out;
  }
  const hit = enumEntry(key, value);
  if (hit) out.push(hit.name);
  return out;
}

function stBindName(v) {
  return ({ 0: 'STB_LOCAL（局部）', 1: 'STB_GLOBAL（全局）', 2: 'STB_WEAK（弱符号）', 10: 'STB_GNU_UNIQUE' }[v]) || ('0x' + v.toString(16));
}
function stTypeName(v) {
  return ({ 0: 'STT_NOTYPE', 1: 'STT_OBJECT', 2: 'STT_FUNC', 3: 'STT_SECTION', 4: 'STT_FILE', 5: 'STT_COMMON', 6: 'STT_TLS', 10: 'STT_GNU_IFUNC' }[v]) || ('0x' + v.toString(16));
}
function stVisName(v) { return ['DEFAULT', 'INTERNAL', 'HIDDEN', 'PROTECTED'][v] || String(v); }
function stVisHint(v) {
  return ['默认可见：符号可在其它模块被解析，也可能被抢占/插入',
    '内部：处理器特定的隐藏语义，比 HIDDEN 更严格',
    '隐藏：不导出到动态符号表，其它模块不可见',
    '保护：在本模块内的引用必定绑定到本模块定义'][v] || '';
}
function stShndxName(elf, v) {
  if (v === 0) return 'UND';
  if (v === 0xfff1) return 'ABS';
  if (v === 0xfff2) return 'COMMON';
  if (v === 0xffff) return 'XINDEX';
  const s = elf.shdrs[v];
  return s ? (s.name || ('段 ' + v)) : ('段 ' + v);
}
function stShndxHint(v) {
  return ({
    0: '未定义符号：本文件引用但未定义，需要链接期或运行期由其它模块提供',
    0xfff1: '绝对值符号：st_value 是常量而非地址，重定位时不参与基址计算',
    0xfff2: '公共块：分配由链接器完成，st_value 表示对齐要求',
    0xffff: '真实段索引超过 0xFFFF，实际值在 SHT_SYMTAB_SHNDX 段中'
  }[v]) || '';
}
function relocTypeName(elf, type) {
  const key = elf.arch === 'riscv' ? 'R_RISCV' : (elf.arch === 'x86-64' ? 'R_X86_64' : null);
  if (key) { const e = enumEntry(key, type); if (e) return e.name; }
  return String(type);
}
function pTypeName(v) { const e = enumEntry('p_type', v); return e ? e.name : hx(v); }
function shTypeName(v) { const e = enumEntry('sh_type', v); return e ? e.name : hx(v); }
function eTypeName(v) { const e = enumEntry('e_type', v); return e ? e.name : hx(v); }
function machineName(v) { const e = enumEntry('e_machine', v); return e ? e.name : hx(v); }

const SHF_LETTERS = [[0x1, 'W'], [0x2, 'A'], [0x4, 'X'], [0x10, 'M'], [0x20, 'S'], [0x40, 'I'], [0x400, 'TLS'], [0x800, 'C']];
function shFlagsText(v) {
  return SHF_LETTERS.filter(function (f) { return v & f[0]; }).map(function (f) { return f[1]; }).join('') || '—';
}
function pFlagsText(v) { return ((v & 4) ? 'R' : '-') + ((v & 2) ? 'W' : '-') + ((v & 1) ? 'X' : '-'); }

/** 某一位属于哪个枚举项（按位枚举的对照依据；纯逻辑，可单测） */
function describeBit(key, bit) {
  const e = ENUMS[key];
  if (!e || !e.values) return null;
  const mask = Math.pow(2, bit);
  for (const v of e.values) if (v.v === mask) return v.name;
  for (const v of e.values) {
    if (v.v > mask && v.v < 0x10000000 && (v.v & mask) === mask) return v.name + '（掩码 ' + hx(v.v) + ' 中该位为 1）';
  }
  return null;
}

