/* ============================================================================
 * elf-parse.js — 纯前端 ELF 解析器
 * 支持 ELF32 / ELF64、小端 / 大端、可重定位 / 可执行 / 共享 / core
 * 输出：结构体 + 颜色分区(regions) + 字节级字段映射(annotations) 三套数据
 * ==========================================================================*/
'use strict';

/* ---------------------------- 字节读取工具 ---------------------------- */
function makeReader(bytes, le) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return {
    u8: (o) => (o >= 0 && o < bytes.length ? dv.getUint8(o) : 0),
    u16: (o) => (o + 2 <= bytes.length ? dv.getUint16(o, le) : 0),
    u32: (o) => (o + 4 <= bytes.length ? dv.getUint32(o, le) : 0),
    u64: (o) => (o + 8 <= bytes.length ? Number(dv.getBigUint64(o, le)) : 0),
    i32: (o) => (o + 4 <= bytes.length ? dv.getInt32(o, le) : 0),
    i64: (o) => (o + 8 <= bytes.length ? Number(dv.getBigInt64(o, le)) : 0),
    inRange: (o, n) => o >= 0 && n >= 0 && o + n <= bytes.length
  };
}

function cstr(bytes, off) {
  if (off < 0 || off >= bytes.length) return '';
  let end = off;
  const limit = Math.min(bytes.length, off + 4096);
  while (end < limit && bytes[end] !== 0) end++;
  let out = '';
  for (let i = off; i < end; i++) {
    const c = bytes[i];
    out += c >= 32 && c < 127 ? String.fromCharCode(c) : (c === 9 ? '\\t' : '\\x' + c.toString(16).padStart(2, '0'));
  }
  return out;
}

function hex(n, pad) {
  if (n === null || n === undefined || !isFinite(n)) return '—';
  const s = Math.abs(n) >= 0 ? Math.trunc(n).toString(16) : '0';
  return '0x' + (pad ? s.padStart(pad, '0') : s);
}

/* ---------------------- 段名 → 颜色分区类别 & 说明 ---------------------- */
function classifySection(name, type, flags) {
  const EXEC = 0x4, ALLOC = 0x2, WRITE = 0x1;
  if (type === 8 /*NOBITS*/) return 'bss';
  if (type === 2 || type === 11) return 'symtab';
  if (type === 3) return name === '.shstrtab' ? 'shstrtab' : 'strtab';
  if (type === 4 || type === 9 || type === 19) return 'rela';
  if (type === 6) return 'dynamic';
  if (type === 7) return 'note';
  if (type === 17 || type === 18) return 'symtab';
  const n = name || '';
  if (/^\.(text|init|fini|plt|plt\.sec|got|got\.plt|iplt|text\.)/.test(n)) {
    if (/^\.(got|plt)/.test(n)) return 'plt';
    return 'text';
  }
  if (n.startsWith('.rela') || n.startsWith('.rel.') || n === '.relr.dyn') return 'rela';
  if (n === '.dynsym') return 'dynsym';
  if (n === '.dynstr') return 'dynstr';
  if (n.startsWith('.debug') || n === '.zdebug' || n === '.gdb_index' || n === '.line' || n === '.stab') return 'debug';
  if (n.startsWith('.note')) return 'note';
  if (n.startsWith('.rodata')) return 'rodata';
  if (n === '.data' || n.startsWith('.data.') || n === '.sdata' || n === '.tdata' || n === '.init_array' || n === '.fini_array' || n === '.preinit_array' || n === '.dynamic') return 'data';
  if (n === '.comment' || n === '.GCC.command.line') return 'comment';
  if (n.startsWith('.riscv.attribute') || n === '.gnu.attributes' || n === '.ARM.attributes') return 'attr';
  if (n.startsWith('.bss') || n === '.sbss' || n === '.tbss') return 'bss';
  if (n === '.eh_frame' || n === '.eh_frame_hdr' || n === '.gcc_except_table') return 'debug';
  if (n === '.interp') return 'rodata';
  if (flags & EXEC) return 'text';
  if (flags & ALLOC && flags & WRITE) return 'data';
  if (flags & ALLOC) return 'rodata';
  return 'other';
}

/* 分区优先级（重叠时数值大者胜出显示） */
const KIND_PRIORITY = {
  ehdr: 100, phdr: 95, shdr: 95,
  symtab: 80, dynsym: 80, strtab: 80, dynstr: 80, shstrtab: 80,
  rela: 78, dynamic: 78, note: 78, attr: 78,
  text: 60, rodata: 55, data: 55, plt: 58, debug: 50, comment: 50, bss: 40,
  other: 20, gap: 5
};

/* ------------------------------ 主解析器 ------------------------------ */
function parseELF(bytes, fileName) {
  const elf = {
    name: fileName || '(memory)',
    bytes,
    size: bytes.length,
    valid: false,
    errors: [],
    warnings: [],
    annotations: [],   // 字节区间 → 字段语义（用于 Hex 探针）
    regions: [],       // 颜色分区
    byteKind: null,
    symbols: [],
    relocations: [],
    dynamic: []
  };

  if (bytes.length < 16) {
    elf.errors.push('文件过小（< 16 字节），不可能是合法 ELF。');
    return elf;
  }
  for (let i = 0; i < 4; i++) {
    if (bytes[i] !== ELF_MAGIC[i]) {
      elf.errors.push('魔数不匹配：前四字节应为 7F 45 4C 46 ("\\x7fELF")，实际为 ' +
        Array.from(bytes.slice(0, 4)).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' '));
      return elf;
    }
  }

  const cls = bytes[4], data = bytes[5];
  if (cls !== 1 && cls !== 2) { elf.errors.push('EI_CLASS 无效：' + cls + '（应为 1=ELF32 或 2=ELF64）'); return elf; }
  if (data !== 1 && data !== 2) { elf.errors.push('EI_DATA 无效：' + data + '（应为 1=小端 或 2=大端）'); return elf; }

  elf.is64 = cls === 2;
  elf.le = data === 1;
  const bits = elf.is64 ? 64 : 32;
  const R = makeReader(bytes, elf.le);
  elf.R = R;

  /* --- ELF 头 --- */
  const ident = {
    magic: Array.from(bytes.slice(0, 4)),
    cls, data,
    version: bytes[6],
    osabi: bytes[7],
    abiversion: bytes[8],
    pad: Array.from(bytes.slice(9, 16))
  };
  const ehdr = {
    e_ident: ident,
    e_type: R.u16(16),
    e_machine: R.u16(18),
    e_version: R.u32(20),
    e_entry: elf.is64 ? R.u64(24) : R.u32(24),
    e_phoff: elf.is64 ? R.u64(32) : R.u32(28),
    e_shoff: elf.is64 ? R.u64(40) : R.u32(32),
    e_flags: elf.is64 ? R.u32(48) : R.u32(36),
    e_ehsize: elf.is64 ? R.u16(52) : R.u16(40),
    e_phentsize: elf.is64 ? R.u16(54) : R.u16(42),
    e_phnum: elf.is64 ? R.u16(56) : R.u16(44),
    e_shentsize: elf.is64 ? R.u16(58) : R.u16(46),
    e_shnum: elf.is64 ? R.u16(60) : R.u16(48),
    e_shstrndx: elf.is64 ? R.u16(62) : R.u16(50)
  };
  elf.ehdr = ehdr;
  elf.arch = ARCH_ALIASES[ehdr.e_machine] || ('machine-' + ehdr.e_machine);
  const EH_SIZE = elf.is64 ? 64 : 52;
  if (ehdr.e_ehsize !== EH_SIZE) elf.warnings.push(`e_ehsize = ${ehdr.e_ehsize}，规范应为 ${EH_SIZE}。`);

  /* --- 段头表（先解析，因为程序头数量可能依赖段 0） --- */
  const SHENTSZ = elf.is64 ? 64 : 40;
  const PHENTSZ = elf.is64 ? 56 : 32;
  let shnum = ehdr.e_shnum, shstrndx = ehdr.e_shstrndx;
  const shdrs = [];
  const shoff = ehdr.e_shoff;
  if (shoff && R.inRange(shoff, SHENTSZ)) {
    const sh0 = readShdr(R, shoff, elf.is64);
    if (shnum === 0) shnum = sh0.sh_size;              // 见 gABI：段数 >= 0xFF00 时的逃逸约定
    if (shstrndx === 0xffff) shstrndx = sh0.sh_link;
    if (!ehdr.e_shentsize) ehdr.e_shentsize = SHENTSZ;
    if (ehdr.e_shentsize !== SHENTSZ) elf.warnings.push(`e_shentsize = ${ehdr.e_shentsize}，规范应为 ${SHENTSZ}。`);
    for (let i = 0; i < shnum; i++) {
      const o = shoff + i * (ehdr.e_shentsize || SHENTSZ);
      if (!R.inRange(o, SHENTSZ)) { elf.warnings.push(`段头表在索引 ${i} 处越界，已截断。`); break; }
      const s = readShdr(R, o, elf.is64);
      s.index = i; s.fileOff = o;
      shdrs.push(s);
    }
  } else if (shoff) {
    elf.errors.push(`e_shoff = ${hex(shoff)} 指向文件之外（文件大小 ${hex(bytes.length)}）。`);
  }
  elf.shdrs = shdrs;

  /* --- 段名与字符串表 --- */
  const shstrtab = shdrs[shstrndx] && shdrs[shstrndx].sh_type === 3
    ? bytes.subarray(shdrs[shstrndx].sh_offset, Math.min(bytes.length, shdrs[shstrndx].sh_offset + shdrs[shstrndx].sh_size))
    : new Uint8Array(0);
  elf.shstrtab = shstrtab;
  for (const s of shdrs) {
    s.name = shstrtab.length ? cstr(shstrtab, s.sh_name) : '';
    s.kind = classifySection(s.name, s.sh_type, s.sh_flags);
    s.purpose = SECTION_PURPOSE[s.name] || '';
  }
  elf.sectionByName = new Map(shdrs.map(s => [s.name, s]));

  /* --- 程序头表 --- */
  const phdrs = [];
  if (ehdr.e_phoff && ehdr.e_phnum) {
    const entsz = ehdr.e_phentsize || PHENTSZ;
    if (!R.inRange(ehdr.e_phoff, entsz)) {
      elf.errors.push(`e_phoff = ${hex(ehdr.e_phoff)} 越界。`);
    } else {
      if (entsz !== PHENTSZ) elf.warnings.push(`e_phentsize = ${entsz}，规范应为 ${PHENTSZ}。`);
      let count = ehdr.e_phnum;
      if (count === 0xffff && shdrs[0]) count = shdrs[0].sh_info;
      for (let i = 0; i < count; i++) {
        const o = ehdr.e_phoff + i * entsz;
        if (!R.inRange(o, PHENTSZ)) { elf.warnings.push(`程序头表在索引 ${i} 处越界，已截断。`); break; }
        const p = readPhdr(R, o, elf.is64);
        p.index = i; p.fileOff = o;
        if (p.p_offset + p.p_filesz > bytes.length)
          elf.warnings.push(`程序头 #${i} 内容超出文件末尾（${hex(p.p_offset)}+${hex(p.p_filesz)} > ${hex(bytes.length)}）。`);
        phdrs.push(p);
      }
    }
  }
  elf.phdrs = phdrs;

  /* --- 符号表 --- */
  for (const s of shdrs) {
    if (s.sh_type !== 2 && s.sh_type !== 11) continue;
    const strs = shdrs[s.sh_link];
    const strBytes = strs && R.inRange(strs.sh_offset, strs.sh_size)
      ? bytes.subarray(strs.sh_offset, strs.sh_offset + strs.sh_size) : new Uint8Array(0);
    const esz = s.sh_entsize || (elf.is64 ? 24 : 16);
    if (!esz) continue;
    const n = Math.floor(s.sh_size / esz);
    for (let i = 0; i < n; i++) {
      const o = s.sh_offset + i * esz;
      if (!R.inRange(o, esz)) break;
      const sym = readSym(R, o, elf.is64, elf.le);
      sym.index = i;
      sym.fileOff = o;
      sym.table = s.name;
      sym.tableIndex = s.index;
      sym.name = strBytes.length ? cstr(strBytes, sym.st_name) : '';
      sym.bind = (sym.st_info >> 4) & 0xf;
      sym.type = sym.st_info & 0xf;
      sym.vis = sym.st_other & 0x3;
      if (sym.st_shndx === 0xffff && elf.symtab_shndx) sym.realShndx = elf.symtab_shndx[i];
      sym.sec = shdrs[sym.st_shndx] ? shdrs[sym.st_shndx].name : (sym.st_shndx === 0 ? '(未定义)' : '');
      sym.sectionIndex = sym.st_shndx;
      // 计算符号的文件偏移（用于 Hex 跳转）
      if (sym.st_shndx > 0 && shdrs[sym.st_shndx]) {
        const sec = shdrs[sym.st_shndx];
        if (sec.sh_type !== 8 && sym.st_value >= sec.sh_addr && sym.st_value < sec.sh_addr + Math.max(sec.sh_size, 1)) {
          sym.fileOffset = sec.sh_offset + (sym.st_value - sec.sh_addr);
        }
      }
      elf.symbols.push(sym);
    }
  }
  // 符号名映射（供反汇编标注）
  elf.symByAddr = new Map();
  for (const s of elf.symbols) {
    if (!s.st_value) continue;
    const cur = elf.symByAddr.get(s.st_value);
    if (!cur || (cur.type !== 2 && s.type === 2)) elf.symByAddr.set(s.st_value, s);
  }

  /* --- 重定位表 --- */
  for (const s of shdrs) {
    if (s.sh_type !== 4 && s.sh_type !== 9) continue;
    const symTab = shdrs[s.sh_link];
    const rela = s.sh_type === 4;
    const esz = s.sh_entsize || (elf.is64 ? (rela ? 24 : 16) : (rela ? 12 : 8));
    const n = esz ? Math.floor(s.sh_size / esz) : 0;
    for (let i = 0; i < n; i++) {
      const o = s.sh_offset + i * esz;
      if (!R.inRange(o, esz)) break;
      const r = { index: i, fileOff: o, table: s.name, section: s.name, symIndex: 0, type: 0, addend: null };
      if (elf.is64) {
        r.offset = R.u64(o);
        const info = R.u64(o + 8);
        r.symIndex = Math.floor(info / 4294967296);
        r.type = info % 4294967296;
        r.addend = rela ? R.i64(o + 16) : null;
      } else {
        r.offset = R.u32(o);
        const info = R.u32(o + 4);
        r.symIndex = info >>> 8;
        r.type = info & 0xff;
        r.addend = rela ? R.i32(o + 8) : null;
      }
      r.rawInfo = elf.is64 ? R.u64(o + 8) : R.u32(o + 4);
      r.symbolName = symTab && symTab.sh_type === 2 || symTab && symTab.sh_type === 11 ? null : null;
      elf.relocations.push(r);
    }
  }
  // 关联重定位 → 符号名
  const symByTable = new Map();
  for (const s of elf.symbols) {
    if (!symByTable.has(s.tableIndex)) symByTable.set(s.tableIndex, []);
    symByTable.get(s.tableIndex)[s.index] = s;
  }
  for (const r of elf.relocations) {
    const src = shdrs.find(x => x.name === r.table);
    const list = src ? symByTable.get(src.sh_link) : null;
    const sym = list ? list[r.symIndex] : null;
    r.symbolName = sym ? (sym.name || ('<idx ' + r.symIndex + '>')) : null;
    r.sym = sym || null;
  }

  /* --- .dynamic --- */
  const dynSec = elf.sectionByName.get('.dynamic');
  if (dynSec && dynSec.sh_type === 6) {
    const esz = dynSec.sh_entsize || (elf.is64 ? 16 : 8);
    const n = esz ? Math.floor(dynSec.sh_size / esz) : 0;
    for (let i = 0; i < n; i++) {
      const o = dynSec.sh_offset + i * esz;
      if (!R.inRange(o, esz)) break;
      const tag = elf.is64 ? R.u64(o) : R.u32(o);
      const val = elf.is64 ? R.u64(o + 8) : R.u32(o + 4);
      elf.dynamic.push({ index: i, fileOff: o, tag, val, size: esz });
    }
  }

  /* --- .riscv.attributes --- */
  const attrSec = elf.sectionByName.get('.riscv.attributes');
  if (attrSec && attrSec.sh_type !== 8 && R.inRange(attrSec.sh_offset, Math.min(attrSec.sh_size, 4096))) {
    elf.riscvAttrs = parseRiscvAttributes(bytes.subarray(attrSec.sh_offset, attrSec.sh_offset + attrSec.sh_size));
  }

  /* --- 附注段 --- */
  elf.notes = [];
  for (const s of shdrs) {
    if (s.sh_type !== 7) continue;
    let o = s.sh_offset;
    const end = Math.min(bytes.length, s.sh_offset + s.sh_size);
    while (o + 12 <= end) {
      const namesz = R.u32(o), descsz = R.u32(o + 4), type = R.u32(o + 8);
      const nameStart = o + 12;
      const nameEnd = Math.min(end, nameStart + namesz);
      const name = cstr(bytes, nameStart);
      const descStart = nameStart + ((namesz + 3) & ~3);
      const desc = bytes.subarray(descStart, Math.min(end, descStart + descsz));
      elf.notes.push({ section: s.name, fileOff: o, namesz, descsz, type, name, desc });
      if (descsz === 0 && namesz === 0) break;
      o = descStart + ((descsz + 3) & ~3);
    }
  }

  buildRegions(elf);
  buildAnnotations(elf);
  elf.valid = true;
  return elf;
}

function readShdr(R, o, is64) {
  if (is64) return {
    sh_name: R.u32(o), sh_type: R.u32(o + 4), sh_flags: R.u64(o + 8), sh_addr: R.u64(o + 16),
    sh_offset: R.u64(o + 24), sh_size: R.u64(o + 32), sh_link: R.u32(o + 40), sh_info: R.u32(o + 44),
    sh_addralign: R.u64(o + 48), sh_entsize: R.u64(o + 56)
  };
  return {
    sh_name: R.u32(o), sh_type: R.u32(o + 4), sh_flags: R.u32(o + 8), sh_addr: R.u32(o + 12),
    sh_offset: R.u32(o + 16), sh_size: R.u32(o + 20), sh_link: R.u32(o + 24), sh_info: R.u32(o + 28),
    sh_addralign: R.u32(o + 32), sh_entsize: R.u32(o + 36)
  };
}

function readPhdr(R, o, is64) {
  if (is64) return {
    p_type: R.u32(o), p_flags: R.u32(o + 4), p_offset: R.u64(o + 8), p_vaddr: R.u64(o + 16),
    p_paddr: R.u64(o + 24), p_filesz: R.u64(o + 32), p_memsz: R.u64(o + 40), p_align: R.u64(o + 48)
  };
  return {
    p_type: R.u32(o), p_offset: R.u32(o + 4), p_vaddr: R.u32(o + 8), p_paddr: R.u32(o + 12),
    p_filesz: R.u32(o + 16), p_memsz: R.u32(o + 20), p_flags: R.u32(o + 24), p_align: R.u32(o + 28)
  };
}

function readSym(R, o, is64, le) {
  if (is64) return {
    st_name: R.u32(o), st_info: R.u8(o + 4), st_other: R.u8(o + 5), st_shndx: R.u16(o + 6),
    st_value: R.u64(o + 8), st_size: R.u64(o + 16)
  };
  return {
    st_name: R.u32(o), st_value: R.u32(o + 4), st_size: R.u32(o + 8),
    st_info: R.u8(o + 12), st_other: R.u8(o + 13), st_shndx: R.u16(o + 14)
  };
}

/* ---------------------- .riscv.attributes (ULEB128) ---------------------- */
function parseRiscvAttributes(buf) {
  let p = 0;
  const uleb = () => {
    let r = 0, shift = 0, b;
    do { if (p >= buf.length) return null; b = buf[p++]; r += (b & 0x7f) * Math.pow(2, shift); shift += 7; } while (b & 0x80);
    return r;
  };
  const out = { version: null, vendor: '', tags: [] };
  out.version = uleb();
  if (out.version !== 'A') out.version = String.fromCharCode(out.version || 0);
  const vendorLen = uleb();
  if (vendorLen === null) return out;
  // 注意：厂商子节的长度字段「包含长度字节自身」，因此实际名字长度为 vendorLen - 1
  const nlen = Math.max(0, vendorLen - 1);
  out.vendor = String.fromCharCode.apply(null, Array.from(buf.slice(p, p + nlen)));
  p += nlen;
  // RISC-V 属性标签编号（RISC-V Object Attribute 规范）
  const TAG = {
    1: 'Tag_file', 2: 'Tag_section', 3: '?', 4: 'Tag_stack_align', 16: 'Tag_stack_align_8',
    5: 'Tag_arch', 6: 'Tag_unaligned_access',
    8: 'Tag_priv_spec', 10: 'Tag_priv_spec_minor', 12: 'Tag_priv_spec_revision',
    14: 'Tag_atomic_abi'
  };
  const ATOMIC = { 0: '(未指定)', 1: '(A6C — 原子操作在 6 字节对齐下原子)', 2: '(A7 — 原子操作最多 8 字节)' };
  while (p < buf.length) {
    const tag = uleb();
    if (tag === null) break;
    if (tag === 0) { out.tags.push({ tag: 0, name: 'Tag_file (padding/结束)', value: '' }); break; }
    if (tag === 5) { // Tag_arch: 字符串（长度含结尾 NUL）
      const len = uleb();
      if (len === null) break;
      const v = String.fromCharCode.apply(null, Array.from(buf.slice(p, p + Math.max(0, len - 1))));
      p += len;
      out.tags.push({ tag, name: 'Tag_arch — 目标 ISA 字符串', value: v });
    } else if (tag === 16) {
      out.tags.push({ tag, name: 'Tag_stack_align_8 — 16 字节栈对齐', value: '已置位' });
    } else if (tag === 14) {
      const v = uleb();
      out.tags.push({ tag, name: 'Tag_atomic_abi', value: v + ' ' + (ATOMIC[v] || '') });
    } else {
      const v = uleb();
      out.tags.push({ tag, name: TAG[tag] || ('tag ' + tag), value: v });
    }
  }
  return out;
}

/* -------------------- 颜色分区构建（字节级 kind 数组） -------------------- */
function buildRegions(elf) {
  const regions = [];
  const push = (start, size, kind, label, priority, extra) => {
    if (size <= 0 || start < 0 || start >= elf.size) return;
    const end = Math.min(elf.size, start + size);
    if (end <= start) return;
    regions.push(Object.assign({ start, end, kind, label, priority: priority === undefined ? (KIND_PRIORITY[kind] || 10) : priority }, extra || {}));
  };

  const EH = elf.is64 ? 64 : 52;
  push(0, Math.min(EH, elf.size), 'ehdr', 'ELF Header', 100, { kindName: KIND_LABEL.ehdr });
  if (elf.ehdr.e_phoff && elf.ehdr.e_phnum)
    push(elf.ehdr.e_phoff, elf.ehdr.e_phnum * (elf.ehdr.e_phentsize || 0), 'phdr', 'Program Header Table', 95);
  if (elf.ehdr.e_shoff && elf.shdrs.length)
    push(elf.ehdr.e_shoff, elf.shdrs.length * (elf.ehdr.e_shentsize || 0), 'shdr', 'Section Header Table', 95);

  for (const s of elf.shdrs) {
    if (s.index === 0) continue;
    if (s.sh_type === 8 || s.sh_type === 0) continue; // NOBITS / NULL 无文件内容
    push(s.sh_offset, s.sh_size, s.kind, s.name || ('<段 ' + s.index + '>'), KIND_PRIORITY[s.kind] || 10,
      { sectionIndex: s.index, section: s });
  }
  // 程序头覆盖但没有任何段描述的字节 → other
  for (const p of elf.phdrs) {
    if (p.p_type !== 1 && p.p_type !== 0x6474e550 && p.p_type !== 0x6474e553) continue;
    push(p.p_offset, p.p_filesz, 'other', 'PT_LOAD #' + p.index + ' (无对应段)', 8, { phIndex: p.index });
  }

  regions.sort((a, b) => (a.start - b.start) || (b.priority - a.priority) || (a.end - b.end));

  // 逐字节胜者判定 + 合并成最终区间
  const byteKind = new Uint8Array(elf.size);
  const kindIds = {}; const kindNames = []; let nextKind = 1;
  const idOf = (k) => { if (!kindIds[k]) { kindIds[k] = nextKind++; kindNames[kindIds[k]] = k; } return kindIds[k]; };

  const merged = [];
  let cursor = 0;
  while (cursor < elf.size) {
    let best = null;
    for (const r of regions) {
      if (r.start > cursor) break;
      if (r.end <= cursor) continue;
      if (!best || r.priority > best.priority || (r.priority === best.priority && r.end > best.end)) best = r;
    }
    if (!best) {
      const last = merged[merged.length - 1];
      const end = (() => { let e = elf.size; for (const r of regions) if (r.start > cursor && r.start < e) e = r.start; return e; })();
      if (last && last.kind === 'gap' && last.end === cursor) last.end = end;
      else { merged.push({ start: cursor, end, kind: 'gap', label: '（未映射/空隙）', priority: 0, gap: true }); }
      cursor = end;
      continue;
    }
    // 若后续存在优先级更高的分区，当前胜出者的可见范围必须在此被截断，
    // 否则宽泛的 PT_LOAD 会吞掉其中的 .text/.data/符号表等。
    let end = Math.min(best.end, elf.size);
    for (const r of regions) {
      if (r.start > cursor && r.start < end && r.priority > best.priority) end = r.start;
    }
    const last = merged[merged.length - 1];
    if (last && last.kind === best.kind && last.end === cursor &&
        last.sectionIndex === best.sectionIndex && last.label === best.label) {
      last.end = end;
    } else {
      merged.push(Object.assign({}, best, { start: cursor, end }));
    }
    cursor = end;
  }
  // 填充 byteKind
  for (const r of merged) {
    const id = idOf(r.kind);
    for (let i = r.start; i < r.end; i++) byteKind[i] = id;
  }
  elf.byteKind = byteKind;
  elf.kindId = kindIds;
  elf.kindNameById = kindNames;
  elf.regions = merged;
  elf.kindTotals = {};
  for (const r of merged) elf.kindTotals[r.kind] = (elf.kindTotals[r.kind] || 0) + (r.end - r.start);
}

/* ------------------ 字节区间 → 字段语义标注（Hex 探针数据源） ------------------ */
function buildAnnotations(elf) {
  const ann = [];
  const bits = elf.is64 ? 64 : 32;

  const addFields = (fields, base, container, extra) => {
    for (const f of fields) {
      ann.push(Object.assign({
        start: base + f.off, end: base + f.off + f.size, size: f.size,
        field: f.name, desc: f.desc, enumKey: f.enum || null,
        container: container
      }, extra || {}));
    }
  };

  addFields(EHDR_FIELDS[bits], 0, 'ELF 头 (Elf' + bits + '_Ehdr)');

  const PHSZ = elf.is64 ? 56 : 32;
  for (const p of elf.phdrs)
    addFields(PHDR_FIELDS[bits], p.fileOff, '程序头 #' + p.index + ' (Elf' + bits + '_Phdr)',
      { phIndex: p.index, holder: { type: 'phdr', index: p.index, size: PHSZ } });

  const SHSZ = elf.is64 ? 64 : 40;
  for (const s of elf.shdrs)
    addFields(SHDR_FIELDS[bits], s.fileOff, '段头 #' + s.index + (s.name ? ' ' + s.name : ''),
      { shIndex: s.index, holder: { type: 'shdr', index: s.index, size: SHSZ } });

  // 符号表项（只标注名字字段，避免海量警告级标注；实际符号项都标注以便探针显示）
  const SYMSZ = elf.is64 ? 24 : 16;
  for (const sym of elf.symbols) {
    if (sym.tableIndex === 0) continue;
    const holder = { type: 'sym', index: sym.index, table: sym.table, size: SYMSZ };
    for (const f of SYM_FIELDS[bits])
      ann.push({
        start: sym.fileOff + f.off, end: sym.fileOff + f.off + f.size, size: f.size,
        field: f.name, desc: f.desc, enumKey: f.enum || null,
        container: sym.table + '[' + sym.index + '] ' + (sym.name || '(匿名)'), holder,
        sym
      });
  }
  // 重定位项
  const relocEnumKey = elf.arch === 'riscv' ? 'R_RISCV' : (elf.arch === 'x86-64' ? 'R_X86_64' : null);
  for (const r of elf.relocations) {
    const holder = { type: 'rela', index: r.index, table: r.table, size: elf.is64 ? (r.addend === null ? 16 : 24) : (r.addend === null ? 8 : 12) };
    for (const f of RELA_FIELDS[bits]) {
      if (f.onlyRela && r.addend === null) continue;     // SHT_REL 没有 r_addend 字段
      ann.push({
        start: r.fileOff + f.off, end: r.fileOff + f.off + f.size, size: f.size,
        field: f.name, desc: f.desc, enumKey: f.name === 'r_info' ? relocEnumKey : null,
        container: r.table + '[' + r.index + ']', holder, reloc: r
      });
    }
  }
  // 动态表项
  for (const d of elf.dynamic) {
    const holder = { type: 'dyn', index: d.index, size: d.size };
    ann.push({ start: d.fileOff, end: d.fileOff + (elf.is64 ? 8 : 4), size: elf.is64 ? 8 : 4, field: 'd_tag', desc: '动态表标签，详见 DT_* 枚举。', enumKey: 'DT_tag', container: '.dynamic[' + d.index + ']', holder });
    ann.push({ start: d.fileOff + (elf.is64 ? 8 : 4), end: d.fileOff + d.size, size: elf.is64 ? 8 : 4, field: 'd_un (d_val / d_ptr)', desc: '标签对应的值：可能是字符串偏移、地址或计数，含义由 d_tag 决定。', container: '.dynamic[' + d.index + ']', holder });
  }

  ann.sort((a, b) => a.start - b.start || b.size - a.size);
  elf.annotations = ann;
  elf.annIndex = null; // 惰性构建
}

/* 在标注数组中二分查找命中项 */
function annotationAt(elf, offset) {
  if (!elf.annotations.length) return null;
  if (!elf.annIndex) {
    // 稀疏索引：每 64 字节记录起始搜索位置
    const stride = 64, n = Math.ceil(elf.size / stride) + 1;
    const idx = new Int32Array(n).fill(-1);
    let j = 0;
    for (let b = 0; b < n; b++) {
      const target = b * stride;
      while (j < elf.annotations.length && elf.annotations[j].start < target && elf.annotations[j].end <= target) j++;
      let k = j, found = -1;
      while (k < elf.annotations.length && elf.annotations[k].start < target + stride) {
        if (elf.annotations[k].end > target) { found = k; break; }
        k++;
      }
      idx[b] = found;
    }
    elf.annIndex = idx;
  }
  let i = elf.annIndex[Math.min(elf.annIndex.length - 1, Math.floor(offset / 64))];
  if (i < 0) return null;
  while (i < elf.annotations.length && elf.annotations[i].start <= offset) {
    const a = elf.annotations[i];
    if (offset >= a.start && offset < a.end) return a;
    i++;
    if (i < elf.annotations.length && elf.annotations[i].start > offset) break;
  }
  return null;
}

/* --------------------------- 地址映射与查询 --------------------------- */

/* 文件偏移 → 虚拟地址 */
function offsetToVaddr(elf, off) {
  for (const s of elf.shdrs) {
    if (!(s.sh_flags & 0x2) || s.sh_type === 8 || s.sh_size === 0) continue;
    if (off >= s.sh_offset && off < s.sh_offset + s.sh_size) return { vaddr: s.sh_addr + (off - s.sh_offset), source: '段 ' + s.name };
  }
  for (const p of elf.phdrs) {
    if (p.p_type !== 1) continue;
    if (off >= p.p_offset && off < p.p_offset + p.p_filesz) return { vaddr: p.p_vaddr + (off - p.p_offset), source: '程序头 #' + p.index };
  }
  return null;
}

/* 虚拟地址 → 文件偏移 */
function vaddrToOffset(elf, va) {
  for (const s of elf.shdrs) {
    if (!(s.sh_flags & 0x2) || s.sh_type === 8 || s.sh_size === 0) continue;
    if (va >= s.sh_addr && va < s.sh_addr + s.sh_size) return { offset: s.sh_offset + (va - s.sh_addr), section: s };
  }
  for (const p of elf.phdrs) {
    if (p.p_type !== 1) continue;
    if (va >= p.p_vaddr && va < p.p_vaddr + p.p_filesz) return { offset: p.p_offset + (va - p.p_vaddr), phdr: p };
  }
  return null;
}

/* 取某段在文件中的字节 */
function sectionBytes(elf, sec) {
  if (!sec || sec.sh_type === 8 || sec.sh_type === 0) return new Uint8Array(0);
  const start = Math.max(0, sec.sh_offset);
  const end = Math.min(elf.size, sec.sh_offset + sec.sh_size);
  return start <= end ? elf.bytes.subarray(start, end) : new Uint8Array(0);
}

/* 分类统计（用于概览面板） */
function summarize(elf) {
  const byKind = {};
  for (const r of elf.regions) {
    if (!byKind[r.kind]) byKind[r.kind] = { kind: r.kind, label: KIND_LABEL[r.kind] || r.kind, bytes: 0, count: 0 };
    byKind[r.kind].bytes += r.end - r.start;
    byKind[r.kind].count++;
  }
  return Object.values(byKind).sort((a, b) => b.bytes - a.bytes);
}

if (typeof module !== 'undefined') {
  module.exports = { parseELF, ENUMS };
}
