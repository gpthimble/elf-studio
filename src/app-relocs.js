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

/** 被修补位置附近的指令（RISC-V 的重定位大多在修补指令里的立即数） */
function relocPatchedInsns(elf, r) {
  if (elf.arch !== 'riscv') return [];
  const loc = vaddrToOffset(elf, r.offset);
  if (!loc || !loc.section) return [];
  const sec = loc.section;
  const bytes = sectionBytes(elf, sec);
  const pos = loc.offset - sec.sh_offset;
  if (pos < 0 || pos >= bytes.length) return [];
  try {
    return riscvDisassemble(bytes.subarray(pos), r.offset, {
      bits: elf.is64 ? 64 : 32,
      symbols: new Map(),
      hasRVC: (elf.ehdr.e_flags & 1) === 1,
      forceC: 'auto', fileBase: loc.offset, maxBytes: 12
    }).slice(0, 3);
  } catch (e) { return []; }
}

/** 单个重定位项的解析面板 */
function relocXrefPanel(elf, r) {
  if (!r) return '';
  const entsz = elf.is64 ? (r.addend === null ? 16 : 24) : (r.addend === null ? 8 : 12);
  const sym = r.sym || null;                 // 解析阶段已按 sh_link 关联好符号表项
  const groups = relocFieldGroups(elf, r);
  const loc = vaddrToOffset(elf, r.offset);
  const insns = relocPatchedInsns(elf, r);
  const typeName = relocTypeName(elf, r.type);
  const typeEntry = enumEntry(elf.arch === 'riscv' ? 'R_RISCV' : 'R_X86_64', r.type);

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

  // ---- 引用关系链路 ----
  const chain = [];
  chain.push({
    label: '改成谁', arrow: '→',
    body: sym
      ? chip('符号表项 ' + sym.table + '[' + sym.index + '] @' + hx(sym.fileOff), sym.fileOff, elf.is64 ? 24 : 16, 'shdr') +
        chip('“' + (sym.name || '(匿名)') + '”' + (sym.fileOffset !== undefined ? ' @' + hx(sym.fileOffset) : ''),
          sym.fileOffset, Math.max(1, Math.min(sym.st_size || 1, 4096)), 'content') +
        '<span class="muted">' + (sym.st_shndx === 0 ? '（未定义符号：由外部提供）' : '（定义于 ' + esc(sym.sec) + '）') + '</span>'
      : '<span class="xr-chip dim">符号索引 ' + r.symIndex + ' 在符号表中找不到对应项</span>'
  });
  chain.push({
    label: '按什么规则改', arrow: '→',
    body: '<span class="xr-chip dim">' + esc(typeName) + '</span>' +
      (typeEntry ? '<span class="muted">' + esc(typeEntry.desc) + '</span>' : '<span class="muted">（字典中暂无该类型的说明）</span>')
  });
  chain.push({
    label: '在哪儿改', arrow: '→',
    body: (loc
      ? chip('文件偏移 ' + hx(loc.offset) + (loc.section ? '（' + loc.section.name + '）' : ''), loc.offset, 4, 'patch')
      : '<span class="xr-chip dim">r_offset 没有映射到文件字节（可能位于 .bss）</span>') +
      (insns.length
        ? '<div class="rl-insns">' + insns.map(function (ins) {
          return '<div class="rl-insn" data-xr-off="' + ins.fileOffset + '" data-xr-size="' + ins.size + '">' +
            '<span class="sp-addr">' + hx(ins.addr) + '</span>' +
            '<span class="sp-bytes">' + Array.prototype.slice.call(ins.bytes).map(byteHex).join(' ') + '</span>' +
            '<span class="sp-text">' + esc(ins.text) + '</span></div>';
        }).join('') + '<div class="muted small">↑ 被修补的指令（重定位通常改的就是这里的立即数）</div></div>'
        : '')
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

  return '<div class="xs rl">' +
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
    '<div class="xs-sub">引用关系链路</div>' + chainHtml +
    '</div>';
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
  for (const r of rs) {
    const key = r.symIndex;
    if (!bySym.has(key)) bySym.set(key, { idx: key, name: r.symbolName, sym: r.sym, count: 0, types: new Set() });
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
    '<div class="rl-sum-title">这段重定位涉及 <b>' + bySym.size + '</b> 个符号（它们就是需要被「重定位」的引用目标）：</div>' +
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
  row.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  setStatus('已展开重定位项解析：r_offset（在哪儿改）→ r_info（符号索引 + 类型）→ 符号表项 → 符号指向的内容。');
}
