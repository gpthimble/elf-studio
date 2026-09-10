/* ============================================================================
 * app-symbols.js — 符号表项解析面板（十六进制 ↔ 字段 ↔ 引用关系）
 *
 * 一个符号表项（Elf64_Sym / Elf32_Sym）里的每个字段其实都是一个「指针」：
 *   st_name  → 字符串表里的偏移  → 符号名
 *   st_shndx → 段表下标          → 段头表项 → 段内容
 *   st_value → 段内地址/偏移     → 段内容中的具体字节
 *   st_size  → 该符号占据的长度  → 内容区间
 *   st_info  → 绑定 + 类型（决定上面几个字段怎么解释、别的模块能不能引用它）
 * 本面板把这些链路一次画出来，并列出「谁引用了这个符号」（重定位）。
 * ==========================================================================*/
'use strict';

const SYM_FIELD_COLORS = {
  st_name: '#f783ac', st_value: '#4dabf7', st_size: '#22b8cf',
  st_info: '#ffa94d', st_other: '#ffd43b', st_shndx: '#51cf66'
};

function symFieldColor(name) { return SYM_FIELD_COLORS[name] || '#8d9bb0'; }

/** 该符号所属字符串表（.symtab/.dynsym 的 sh_link 指向的表） */
function symStrTab(elf, sym) {
  const tbl = elf.shdrs[sym.tableIndex];
  return tbl ? elf.shdrs[tbl.sh_link] : null;
}

/** 该符号被哪些重定位引用（入向引用） */
function symInboundRelocs(elf, sym) {
  return elf.relocations.filter(function (r) {
    if (r.symIndex !== sym.index) return false;
    const tbl = elf.shdrs.find(function (s) { return s.name === r.table; });
    return tbl && tbl.sh_link === sym.tableIndex;
  });
}

function chip(text, off, size, cls) {
  if (off === null || off === undefined) return '<span class="xr-chip dim">' + esc(text) + '</span>';
  return '<button class="xr-chip ' + (cls || '') + '" data-xr-off="' + off + '" data-xr-size="' + (size || 1) + '">' +
    esc(text) + '</button>';
}

/**
 * 渲染某个符号表项的解析 + 引用关系面板
 * @param {object} elf
 * @param {object} sym 解析器产出的符号对象
 */
function symbolXrefPanel(elf, sym) {
  if (!sym) return '';
  const bits = elf.is64 ? 64 : 32;
  const entsz = elf.is64 ? 24 : 16;
  const fields = SYM_FIELDS[bits];
  const strtab = symStrTab(elf, sym);
  const strBytes = strtab ? sectionBytes(elf, strtab) : new Uint8Array(0);
  const nameOffInStr = sym.st_name;
  const nameAbsOff = strtab ? strtab.sh_offset + nameOffInStr : null;
  const sec = (sym.st_shndx > 0 && sym.st_shndx < 0xff00) ? elf.shdrs[sym.st_shndx] : null;
  const contentOff = sym.fileOffset;
  const inbound = symInboundRelocs(elf, sym);

  // ---- 表项自身的字节，按字段着色 ----
  let byteCells = '';
  for (const f of fields) {
    const raw = [];
    for (let i = 0; i < f.size; i++) raw.push(elf.bytes[sym.fileOff + f.off + i]);
    byteCells += '<span class="xs-field" style="--fc:' + symFieldColor(f.name) + '" title="' +
      esc(f.name + '（' + f.size + ' 字节）') + '">' +
      '<i>' + esc(f.name) + '</i>' +
      '<b class="mono">' + raw.map(byteHex).join(' ') + '</b></span>';
  }

  // ---- 字段 → 引用目标 ----
  const rows = [];
  rows.push({
    field: 'st_name', raw: hx(sym.st_name, 8), meaning: '字符串表偏移',
    target: strtab
      ? chip('“' + (sym.name || '(空)') + '” @ ' + esc(strtab.name) + '+0x' + nameOffInStr.toString(16) + ' → 文件 ' + hx(nameAbsOff),
        nameAbsOff, Math.max(1, (sym.name || '').length + 1), 'name')
      : '<span class="xr-chip dim">没有字符串表</span>'
  });
  rows.push({
    field: 'st_info', raw: hx(sym.st_info, 2),
    meaning: 'bind = ' + hx((sym.st_info >> 4) & 0xf) + ' (' + stBindName(sym.bind) + ') ／ type = ' + hx(sym.st_info & 0xf) + ' (' + stTypeName(sym.type) + ')',
    target: '<span class="xr-chip dim">无外部引用（决定其它字段的解释方式）</span>'
  });
  rows.push({
    field: 'st_other', raw: hx(sym.st_other, 2), meaning: '可见性 ' + stVisName(sym.vis),
    target: '<span class="xr-chip dim">无外部引用（影响动态链接可否跨模块解析）</span>'
  });
  rows.push({
    field: 'st_shndx', raw: hx(sym.st_shndx, 4),
    meaning: sec ? ('段表下标 ' + sym.st_shndx + ' → ' + sec.name)
      : (sym.st_shndx === 0 ? 'SHN_UNDEF（未定义）' : stShndxName(elf, sym.st_shndx)),
    target: sec
      ? chip('段头 #' + sec.index + ' @' + hx(sec.fileOff), sec.fileOff, bits === 64 ? 64 : 40, 'shdr') +
        chip(sec.name + ' 内容 @' + hx(sec.sh_offset), sec.sh_offset, Math.min(sec.sh_size, 4096), 'sec')
      : '<span class="xr-chip dim">未定义符号：由链接器/动态链接器在其它模块中解析</span>'
  });
  rows.push({
    field: 'st_value', raw: hx(sym.st_value, elf.is64 ? 16 : 8),
    meaning: sec ? hx(sym.st_value, elf.is64 ? 16 : 8) + '（' + (elf.ehdr.e_type === 1 ? '段内偏移' : '虚拟地址') + '）' : '占位值（未定义）',
    target: contentOff !== undefined
      ? chip('段内容 ' + hx(contentOff) + (sec ? '（' + sec.name + '）' : ''), contentOff, Math.max(1, Math.min(sym.st_size || 1, 4096)), 'content') +
        (sym.st_shndx === 0 ? '' : '')
      : '<span class="xr-chip dim">没有对应的文件字节（如 .bss）</span>'
  });
  rows.push({
    field: 'st_size', raw: hx(sym.st_size, elf.is64 ? 16 : 8),
    meaning: '符号长度 ' + fmtComma(sym.st_size) + ' 字节',
    target: (contentOff !== undefined && sym.st_size)
      ? chip('[' + hx(contentOff) + ' – ' + hx(contentOff + sym.st_size) + ')', contentOff, Math.min(sym.st_size, 4096), 'range')
      : '<span class="xr-chip dim">大小未知</span>'
  });

  const rowHtml = rows.map(function (r) {
    return '<tr>' +
      '<td class="mono xs-fname" style="color:' + symFieldColor(r.field) + '">' + esc(r.field) + '</td>' +
      '<td class="mono">' + esc(r.raw) + '</td>' +
      '<td class="xs-mean">' + esc(r.meaning) + '</td>' +
      '<td class="xs-link"><span class="xr-arrow">→</span> ' + r.target + '</td></tr>';
  }).join('');

  // ---- 入向引用：谁引用了这个符号 ----
  let inboundHtml;
  if (!inbound.length) {
    inboundHtml = sym.st_shndx === 0
      ? '<div class="xr-none">未定义符号，但本文件里没有任何重定位引用它（可能由调试信息引用）。</div>'
      : '<div class="xr-none">本文件里没有重定位引用该符号（它可能是被外部模块引用的导出符号）。</div>';
  } else {
    inboundHtml = '<div class="xr-list">' + inbound.map(function (r) {
      const tblSec = elf.shdrs[r.tableIndex !== undefined ? r.tableIndex : 0];
      const targetOff = vaddrToOffset(elf, r.offset);
      const tgt = elf.shdrs.find(function (s) { return s.name === (r.target || '').split('+')[0]; });
      return '<div class="xr-in">' +
        '<span class="xr-arrow">←</span>' +
        chip(r.table + '[' + r.index + '] @' + hx(r.fileOff), r.fileOff, elf.is64 ? 24 : 12, 'rela') +
        '<span class="mono xs-rt">' + esc(relocTypeName(elf, r.type)) + '</span>' +
        '<span class="muted">修补位置 ' + hx(r.offset) + '</span>' +
        (targetOff ? chip('→ 文件 ' + hx(targetOff.offset), targetOff.offset, 4, 'patch') : '') +
        (r.addend ? '<span class="muted">addend ' + r.addend + '</span>' : '') +
        '</div>';
    }).join('') + '</div>';
  }

  const kindLine = sym.st_shndx === 0
    ? '本文件中<b>未定义</b>，需要由其它模块在链接期或运行期提供。'
    : (sym.type === 2
      ? '这是一个<b>函数</b>符号，st_value 指向函数体第一条指令，st_size 是函数体长度。'
      : (sym.type === 1 ? '这是一个<b>数据对象</b>符号，st_value 指向变量/数组所在字节。' : '符号类型为 ' + esc(stTypeName(sym.type)) + '。'));

  return '<div class="xs">' +
    '<div class="xs-head"><b class="mono">' + esc(sym.name || '(匿名符号)') + '</b>' +
    '<span class="pill">' + esc(sym.table) + '[' + sym.index + ']</span>' +
    '<span class="muted">表项 @' + hx(sym.fileOff) + '，' + entsz + ' 字节</span>' +
    '<span class="xs-actions">' +
    '<button class="mini" data-xr-off="' + sym.fileOff + '" data-xr-size="' + entsz + '">表项字节</button>' +
    (contentOff !== undefined ? '<button class="mini" data-xr-off="' + contentOff + '" data-xr-size="' + Math.max(1, Math.min(sym.st_size || 1, 8192)) + '">段内容</button>' : '') +
    (sym.type === 2 && sym.st_shndx !== 0 ? '<button class="mini" data-xr-disasm="' + sym.st_value + '">反汇编</button>' : '') +
    '</span></div>' +
    '<div class="xs-bytes">' + byteCells + '</div>' +
    '<div class="xs-note">' + kindLine + ' 下面把表项里的每个字段当作一个「指针」，逐条列出它指向哪里。</div>' +
    '<table class="grid compact xs-table"><thead><tr><th>字段</th><th>原始值</th><th>含义</th><th>指向 / 引用目标</th></tr></thead>' +
    '<tbody>' + rowHtml + '</tbody></table>' +
    '<div class="xs-sub">谁引用了这个符号（入向引用）</div>' + inboundHtml +
    '</div>';
}

/** 给面板里的可跳转元素挂事件（内容行、按钮、反汇编） */
/** 在符号表里就地展开 / 收起某个符号的解析面板 */
function toggleSymXref(tr, sym) {
  const tbl = tr.closest('table');
  const existed = $('.sym-xref[data-for="' + sym.index + '"]', tbl);
  $$('.sym-xref', tbl).forEach(function (x) { x.remove(); });
  if (existed) return;                                  // 再点一次 = 收起
  const row = document.createElement('tr');
  row.className = 'sym-xref';
  row.dataset.for = sym.index;
  const cols = tr.children.length;
  row.innerHTML = '<td colspan="' + cols + '">' + symbolXrefPanel(S.elf, sym) + '</td>';
  tr.after(row);
  wireXref(row);
  row.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  setStatus('已展开符号 ' + (sym.name || '(匿名)') + ' 的表项解析：st_name → 字符串表、st_shndx → 段头、' +
    'st_value → 段内容，并列出引用它的重定位。');
}

function wireXref(root) {
  $$('[data-xr-off]', root).forEach(function (b) {
    const off = +b.dataset.xrOff, size = +b.dataset.xrSize || 1;
    b.addEventListener('click', function (e) {
      e.stopPropagation();
      selectBytes(off, size, { smooth: true });
      setStatus('已定位到引用目标：文件偏移 ' + hx(off) + '，' + size + ' 字节');
    });
    b.addEventListener('mouseenter', function () { hoverRange(off, size); });
    b.addEventListener('mouseleave', clearHover);
  });
  $$('[data-xr-disasm]', root).forEach(function (b) {
    b.addEventListener('click', function (e) {
      e.stopPropagation();
      openDisasmAt(+b.dataset.xrDisasm);
    });
  });
}
