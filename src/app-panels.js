/* ============================================================================
 * app-panels.js — 各结构面板的渲染与交互
 *   ELF 头 / 程序头 / 段头表 / 段内容 / 符号表 / 重定位 / 枚举字典 / 反汇编
 * ==========================================================================*/
'use strict';

/* 一段「字段 → 字节区间」的通用渲染 */
function rowForField(elf, f, raw, baseOff, extraAttr) {
  const start = baseOff + f.off;
  let rawTxt, decoded = '';
  if (Array.isArray(raw)) {
    rawTxt = '<span class="muted">' + raw.map(byteHex).join(' ') + '</span>';
  } else if (raw === undefined) {
    rawTxt = '—';
  } else {
    rawTxt = f.size === 1 ? hx(raw, 2) + ' (' + raw + ')' : hx(raw);
    const vals = decodeValue(f.enum, raw);
    if (vals.length) decoded = vals.join('；');
    else if (typeof raw === 'number' && raw > 0x1000) decoded = fmtComma(raw) + ' （十进制）';
  }
  return '<tr class="fld" data-off="' + start + '" data-size="' + f.size + '"' +
    (f.enum ? ' data-dict="' + f.enum + '"' : '') + (extraAttr || '') +
    ' title="' + esc(f.desc) + '">' +
    '<td class="mono fname">' + esc(f.name) + '</td>' +
    '<td class="mono">' + hx(f.off, 2) + '</td>' +
    '<td class="mono">' + f.size + '</td>' +
    '<td class="mono">' + rawTxt + '</td>' +
    '<td class="fdesc">' + (decoded ? '<b class="dec">' + esc(decoded) + '</b> ' : '') +
    (f.enum ? '<button class="mini enum-hint" title="点击弹出该字段的全部可选取值与说明">全部取值 ▸</button> ' : '') +
    '<span class="muted">' + esc(f.desc) + '</span></td></tr>';
}

function wireFieldRows(root) {
  $$('tr.fld', root).forEach(function (tr) {
    tr.addEventListener('mouseenter', function () {
      const off = +tr.dataset.off;
      hoverRange(off, +tr.dataset.size);          // 整段字段一起高亮，而不是只亮一个字节
      if (S.pinned === null) updateInspector(off, +tr.dataset.size);
    });
    tr.addEventListener('mouseleave', clearHover);
    tr.addEventListener('click', function () {
      const off = +tr.dataset.off, size = +tr.dataset.size;
      selectBytes(off, size);                            // 只做 Hex 定位 + 固定探针，不跳走
      const nm = tr.querySelector('.fname');
      setStatus('已定位到字段 ' + (nm ? nm.textContent : '') + '：文件偏移 ' + hx(off) + '，' + size + ' 字节' +
        (tr.dataset.dict ? '（已弹出该字段的枚举取值与说明）' : ''));
      if (tr.dataset.dict) showEnumPopover(tr, tr.dataset.dict, off, size);
      else closeEnumPopover();
    });
  });
  $$('[data-sel]', root).forEach(function (b) {
    b.addEventListener('click', function (e) {
      e.stopPropagation();
      const p = b.dataset.sel.split(',');
      selectBytes(+p[0], +p[1]);
    });
  });
}

/* ---------------------------- ELF 头 ---------------------------- */
function renderElfHeader() {
  const elf = S.elf;
  const pane = $('#pane-ehdr');
  if (!elf.valid) { pane.innerHTML = '<div class="card">解析失败，无 ELF 头可显示。</div>'; return; }
  const bits = elf.is64 ? 64 : 32;
  const rows = EHDR_FIELDS[bits].map(function (f) {
    let raw;
    if (f.name.indexOf('e_ident') === 0) {
      raw = f.size === 1 ? elf.bytes[f.off] : Array.prototype.slice.call(elf.bytes.subarray(f.off, f.off + f.size));
    } else {
      raw = elf.ehdr[f.name];
    }
    return rowForField(elf, f, raw, 0);
  }).join('');
  const ehSize = bits === 64 ? 64 : 52;
  pane.innerHTML = '<div class="card"><div class="card-h"><b>Elf' + bits + '_Ehdr 结构</b>' +
    '<span class="muted">共 ' + ehSize + ' 字节，位于文件偏移 0x0（文件最开始）</span>' +
    '<button class="mini" data-sel="0,' + ehSize + '">选中整个头部</button></div>' +
    '<table class="grid"><thead><tr><th>字段</th><th>偏移</th><th>字节</th><th>原始值</th><th>解读 / 说明</th></tr></thead>' +
    '<tbody>' + rows + '</tbody></table></div>';
  wireFieldRows(pane);
}

/* ---------------------------- 程序头 ---------------------------- */
function renderProgramHeaders() {
  const elf = S.elf;
  const pane = $('#pane-phdr');
  if (!elf.valid) { pane.innerHTML = ''; return; }
  if (!elf.phdrs.length) {
    pane.innerHTML = '<div class="card"><b>没有程序头表</b><p class="muted">' +
      '程序头表描述「运行期内存映像」，只有可执行文件与共享库才需要它。当前文件（很可能是 ET_REL 可重定位目标文件）是链接器的输入，用不上加载信息，因此 e_phoff = 0。' +
      '这类文件的结构应主要通过段表 (Section Header Table) 来理解。</p></div>';
    return;
  }
  const bits = elf.is64 ? 64 : 32;
  const entsz = bits === 64 ? 56 : 32;
  const cards = elf.phdrs.map(function (p) {
    const rows = PHDR_FIELDS[bits].map(function (f) { return rowForField(elf, f, p[f.name], p.fileOff); }).join('');
    const extra = p.p_memsz > p.p_filesz
      ? '，内存大小 ' + fmtSize(p.p_memsz) + '（多出的 ' + fmtSize(p.p_memsz - p.p_filesz) + ' 由加载器填 0）'
      : '';
    return '<div class="card"><div class="card-h"><span class="pill k-phdr">段 #' + p.index + '</span>' +
      '<b>' + esc(pTypeName(p.p_type)) + '</b><span class="pill">' + pFlagsText(p.p_flags) + '</span>' +
      '<span class="muted">文件 ' + hx(p.p_offset) + '(' + fmtSize(p.p_filesz) + ') → 虚拟地址 ' + hx(p.p_vaddr) + extra + '</span>' +
      '<button class="mini" data-sel="' + p.fileOff + ',' + entsz + '">选中该表项</button></div>' +
      '<table class="grid compact"><thead><tr><th>字段</th><th>偏移</th><th>字节</th><th>原始值</th><th>解读 / 说明</th></tr></thead>' +
      '<tbody>' + rows + '</tbody></table></div>';
  }).join('');
  pane.innerHTML = '<div class="card muted small">程序头表位于文件偏移 ' + hx(elf.ehdr.e_phoff) + '，共 ' +
    elf.phdrs.length + ' 项 × ' + elf.ehdr.e_phentsize + ' 字节。它是「加载器视角」：内核只关心 PT_LOAD，动态链接器关心 PT_DYNAMIC / PT_INTERP。' +
    '与「链接器视角」的段表交叉对照，可以完整理解一个 ELF 文件。</div>' + cards;
  wireFieldRows(pane);
}

/* ---------------------------- 段头表 ---------------------------- */
function renderSectionHeaders() {
  const elf = S.elf;
  const pane = $('#pane-shdr');
  if (!elf.valid || !elf.shdrs.length) { pane.innerHTML = '<div class="card muted">没有段头表。</div>'; return; }
  const bits = elf.is64 ? 64 : 32;
  const entsz = bits === 64 ? 64 : 40;
  const rows = elf.shdrs.map(function (s) {
    return '<tr class="shdr-row" data-index="' + s.index + '" data-off="' + s.fileOff + '">' +
      '<td class="mono">' + s.index + '</td>' +
      '<td><i class="dot" style="background:var(--c-' + s.kind + ')"></i>' + esc(s.name || (s.index === 0 ? 'NULL' : '(无名)')) + '</td>' +
      '<td class="mono">' + esc(shTypeName(s.sh_type)) + '</td>' +
      '<td class="mono">' + shFlagsText(s.sh_flags) + '</td>' +
      '<td class="mono">' + hx(s.sh_addr, elf.is64 ? 10 : 6) + '</td>' +
      '<td class="mono">' + hx(s.sh_offset) + '</td>' +
      '<td class="mono">' + fmtComma(s.sh_size) + '</td>' +
      '<td class="mono">' + s.sh_link + '</td><td class="mono">' + s.sh_info + '</td>' +
      '<td class="mono">' + s.sh_addralign + '</td><td class="mono">' + s.sh_entsize + '</td></tr>';
  }).join('');

  const details = elf.shdrs.map(function (s) {
    const fieldRows = SHDR_FIELDS[bits].map(function (f) { return rowForField(elf, f, s[f.name], s.fileOff); }).join('');
    return '<div class="card shdr-detail" data-index="' + s.index + '">' +
      '<div class="card-h"><i class="dot" style="background:var(--c-' + s.kind + ')"></i>' +
      '<b class="mono">' + esc(s.name || '(无名段)') + '</b><span class="pill">段头 #' + s.index + '</span>' +
      '<span class="muted">' + esc(shTypeName(s.sh_type)) + ' · 标志 ' + shFlagsText(s.sh_flags) + ' · ' + fmtSize(s.sh_size) + ' 字节</span>' +
      (s.sh_type === 8 ? '' : '<button class="mini" data-sel="' + s.sh_offset + ',' + Math.max(1, Math.min(s.sh_size, 8192)) + '">查看内容</button>') +
      '<button class="mini" data-sel="' + s.fileOff + ',' + entsz + '">选中段头</button></div>' +
      (s.purpose ? '<div class="purpose">📘 ' + esc(s.purpose) + '</div>' : '') +
      '<table class="grid compact"><thead><tr><th>字段</th><th>偏移</th><th>字节</th><th>原始值</th><th>解读 / 说明</th></tr></thead>' +
      '<tbody>' + fieldRows + '</tbody></table></div>';
  }).join('');

  pane.innerHTML = '<div class="card"><div class="card-h"><b>段头表 (Section Header Table)</b>' +
    '<span class="muted">位于 ' + hx(elf.ehdr.e_shoff) + '，共 ' + elf.shdrs.length + ' 项 × ' + elf.ehdr.e_shentsize + ' 字节</span>' +
    '<button class="mini" data-sel="' + elf.ehdr.e_shoff + ',' + (elf.shdrs.length * elf.ehdr.e_shentsize) + '">选中整表</button></div>' +
    '<div class="table-scroll"><table class="grid"><thead><tr><th>#</th><th>名称</th><th>类型 sh_type</th><th>标志</th>' +
    '<th>地址 sh_addr</th><th>偏移 sh_offset</th><th>大小 sh_size</th><th>link</th><th>info</th><th>对齐</th><th>表项</th></tr></thead>' +
    '<tbody>' + rows + '</tbody></table></div>' +
    '<div class="muted small">点击任意行 → Hex 视图定位到该段头的物理字节；下方会展开该段头的完整字段解析。</div></div>' + details;

  $$('.shdr-row', pane).forEach(function (tr) {
    tr.addEventListener('mouseenter', function () { hoverRange(+tr.dataset.off, entsz); });
    tr.addEventListener('mouseleave', clearHover);
    tr.addEventListener('click', function () {
      selectBytes(+tr.dataset.off, entsz);
      const d = $('.shdr-detail[data-index="' + tr.dataset.index + '"]', pane);
      if (d) d.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    });
  });
  wireFieldRows(pane);
}

/* ---------------------------- 段内容 ---------------------------- */
const PREVIEW_LINES = 14;

/* ---------------- 符号表解码面板：把表项字节逐字段翻译成人能读的内容 ---------------- */
function symbolTableDecode(elf, sec) {
  const bits = elf.is64 ? 64 : 32;
  const entsz = elf.is64 ? 24 : 16;
  const syms = elf.symbols.filter(function (s) { return s.tableIndex === sec.index; });
  const shown = syms.slice(0, 60);
  const head = '<tr><th>表项偏移</th><th>原始字节（' + entsz + ' B）</th><th>st_name</th>' +
    '<th>st_info</th><th>st_other</th><th>st_shndx</th><th>st_value</th><th>st_size</th></tr>';
  const rows = shown.map(function (s) {
    const bytes = elf.bytes.subarray(s.fileOff, Math.min(elf.size, s.fileOff + entsz));
    const raw = Array.prototype.slice.call(bytes).map(byteHex).join(' ');
    const shrunk = raw.length > 30 ? raw.slice(0, 29) + '…' : raw;
    const shndx = stShndxName(elf, s.st_shndx);
    const valVaddr = s.st_shndx !== 0 && s.st_shndx < 0xff00 ? ' <span class="muted">@' + shndx + '</span>' : '';
    const cls = 'sp-row-decode' + (s.type === 2 ? ' isfunc' : '');
    return '<tr class="' + cls + '" data-sym="' + elf.symbols.indexOf(s) + '" data-off="' + s.fileOff + '" data-size="' + entsz + '">' +
      '<td class="mono">' + hx(s.fileOff) + '</td>' +
      '<td class="mono sp-raw" title="' + esc(raw) + '">' + esc(shrunk) + '</td>' +
      '<td class="mono sp-name">' + esc(s.name || '<span class="muted">(空)</span>') + '</td>' +
      '<td class="mono">' + hx(s.st_info, 2) + ' → ' + esc(stBindName(s.bind)) + ' / ' + esc(stTypeName(s.type)) + '</td>' +
      '<td class="mono">' + hx(s.st_other, 2) + ' → ' + esc(stVisName(s.vis)) + '</td>' +
      '<td class="mono">' + s.st_shndx + ' → ' + esc(shndx) + '</td>' +
      '<td class="mono">' + hx(s.st_value, elf.is64 ? 10 : 6) + valVaddr + '</td>' +
      '<td class="mono">' + fmtComma(s.st_size) + '</td></tr>';
  }).join('');
  const total = entsz * 0 + (elf.is64 ? '8/4/1/1/2/8/8' : '4/4/1/1/2/4/4');
  return '<div class="sp-toolbar"><span class="muted">符号表项解码（共 ' + syms.length + ' 项，显示前 ' + shown.length + ' 项）' +
    '　每项 ' + entsz + ' 字节，字段宽度：' + total + '</span>' +
    '<button class="mini" data-tab-jump="symbols">打开完整符号表 →</button></div>' +
    '<div class="table-scroll" style="max-height:300px"><table class="grid compact">' +
    '<thead>' + head + '</thead><tbody>' + rows + '</tbody></table></div>' +
    '<div class="sec-sym-slot"></div>' +
    '<div class="sp-note muted">每一列都是表项里若干个十六进制字节翻译出来的：' +
    '<b>st_name</b> 是字符串表偏移（已还原成符号名），<b>st_info</b> 拆成 bind/type，' +
    '<b>st_shndx</b> 换算成段名，<b>st_value</b> 是地址或偏移。' +
    '点击任意一行 → 下方展开该符号表项的<b>解析与引用关系面板</b>（每个字段指向哪里、谁引用了它）。</div>';
}

/* ---------------- 数据段解码面板：十六进制 ↔ 字符串 / 整数 / 浮点 / 指针 ---------------- */
const DECODE_MODES = [
  ['strings', '字符串'],
  ['u32', '32 位字'],
  ['u64', '64 位字'],
  ['ptr', '指针候选']
];

function decodeModeOf(sec) {
  S.decodeMode = S.decodeMode || {};
  return S.decodeMode[sec.index] || 'auto';
}

/** 在数据段里扫描可打印字符串 */
function scanStrings(elf, sec, limit) {
  const bytes = sectionBytes(elf, sec);
  const out = [];
  let p = 0;
  while (p < bytes.length && out.length < limit) {
    let e = p;
    while (e < bytes.length && bytes[e] >= 32 && bytes[e] < 127) e++;
    const len = e - p;
    if (len >= 4) {
      out.push({ off: p, text: String.fromCharCode.apply(null, Array.prototype.slice.call(bytes.subarray(p, e))) });
      p = e + 1;
    } else p++;
  }
  return out;
}

/** 值是否落在某个已映射段内（用于识别指针） */
function resolvePointer(elf, v) {
  const sec = elf.shdrs.find(function (s) {
    return (s.sh_flags & 0x2) && s.index !== 0 && s.sh_size > 0 && v >= s.sh_addr && v < s.sh_addr + s.sh_size;
  });
  if (!sec) return null;
  const sym = elf.symbols.find(function (s) { return s.type === 2 && s.st_value === v; });
  return { sec: sec.name, off: v - sec.sh_addr, sym: sym ? sym.name : null };
}

function dataDecodePanel(elf, sec) {
  const bytes = sectionBytes(elf, sec);
  if (!bytes.length) return '<div class="sp-note muted">该段没有文件字节。</div>';
  const strings = scanStrings(elf, sec, 1);
  let mode = decodeModeOf(sec);
  if (mode === 'auto') mode = strings.length >= 3 ? 'strings' : 'u32';
  const sw = '<div class="sp-modes">解码视图：' + DECODE_MODES.map(function (m) {
    return '<button class="mini sp-mode' + (m[0] === mode ? ' on' : '') + '" data-mode="' + m[0] + '" data-sec="' + sec.index + '">' + m[1] + '</button>';
  }).join('') + '</div>';

  if (mode === 'strings') {
    const list = scanStrings(elf, sec, 80);
    const rows = list.map(function (x) {
      return '<div class="sp-line str" data-off="' + (sec.sh_offset + x.off) + '" data-size="' + (x.text.length + 1) + '">' +
        '<span class="sp-addr">+' + hx(x.off, 3) + '</span><span class="sp-name mono">' + esc(x.text) + '</span></div>';
    }).join('');
    return '<div class="sp-toolbar">' + sw + '<span class="muted">扫描到 ' + list.length + ' 个字符串</span></div>' +
      (rows ? '<div class="sp-code">' + rows + '</div>' : '<div class="sp-note muted">没有找到可打印字符串。</div>');
  }

  if (mode === 'ptr') {
    const size = elf.is64 ? 8 : 4;
    const step = size;
    const rows = [];
    for (let o = 0; o + size <= bytes.length && rows.length < 40; o += step) {
      const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      const v = elf.is64 ? dv.getBigUint64(o, elf.le) : dv.getUint32(o, elf.le);
      const num = Number(v);
      const hit = (num > 0x1000 && num < 0xffffffff) ? resolvePointer(elf, num) : null;
      if (hit) rows.push({ o: o, v: num, hit: hit, hex: (elf.is64 ? '0x' + v.toString(16).padStart(16, '0') : hx(num, 8)) });
    }
    return '<div class="sp-toolbar">' + sw + '<span class="muted">找到 ' + rows.length + ' 个落在已映射段内的指针候选</span></div>' +
      (rows.length ? '<div class="sp-code">' + rows.map(function (r) {
        return '<div class="sp-line ptr" data-off="' + (sec.sh_offset + r.o) + '" data-size="' + size + '">' +
          '<span class="sp-addr">+' + hx(r.o, 3) + '</span>' +
          '<span class="sp-name mono">' + esc(r.hex) + '</span>' +
          '<span class="sp-text">→ ' + esc(r.hit.sec) + '+0x' + r.hit.off.toString(16) +
          (r.hit.sym ? ' <b class="ok">' + esc(r.hit.sym) + '</b>' : '') + '</span></div>';
      }).join('') + '</div>' : '<div class="sp-note muted">没有发现指向已映射段的指针。</div>');
  }

  // 32 / 64 位字视图：每行 16 字节，逐字给出十进制、十六进制与浮点解读
  const size = mode === 'u64' ? 8 : 4;
  const perRow = size === 8 ? 2 : 4;
  const limitBytes = Math.min(bytes.length, 46 * 16);
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const rowN = Math.ceil(limitBytes / 16);
  let body = '';
  for (let r = 0; r < rowN; r++) {
    const base = r * 16;
    let hexs = '', asc = '';
    for (let i = 0; i < 16; i++) {
      const bi = base + i;
      if (bi >= bytes.length) { hexs += '   '; asc += ' '; continue; }
      hexs += byteHex(bytes[bi]) + ' ';
      asc += (bytes[bi] >= 32 && bytes[bi] < 127) ? esc(String.fromCharCode(bytes[bi])) : '·';
    }
    const cells = [];
    for (let k = 0; k < perRow; k++) {
      const o = base + k * size;
      if (o + size > bytes.length) { cells.push('<span class="dd-cell muted">—</span>'); continue; }
      if (size === 4) {
        const u = dv.getUint32(o, elf.le), i2 = dv.getInt32(o, elf.le);
        const f = dv.getFloat32(o, elf.le);
        const ptr = (u > 0x1000) ? resolvePointer(elf, u) : null;
        cells.push('<span class="dd-cell" title="u32=' + u + ' i32=' + i2 + ' f32=' + f + '">' +
          '<b class="mono">' + hx(u, 8) + '</b>' +
          '<em class="mono">' + (u > 999999 ? u.toExponential(3) : u) + '</em>' +
          '<i class="mono">' + (isFinite(f) && Math.abs(f) > 1e-6 && Math.abs(f) < 1e7 ? 'f32 ' + Number(f.toPrecision(5)) : '') + '</i>' +
          (ptr ? '<u class="mono">→ ' + esc(ptr.sec) + '+0x' + ptr.off.toString(16) + (ptr.sym ? ' ' + esc(ptr.sym) : '') + '</u>' : '') +
          '</span>');
      } else {
        const u = dv.getBigUint64(o, elf.le);
        const f = dv.getFloat64(o, elf.le);
        const ptr = (u > 0x1000n && u < 0xffffffffn) ? resolvePointer(elf, Number(u)) : null;
        cells.push('<span class="dd-cell" title="u64=' + u + ' f64=' + f + '">' +
          '<b class="mono">0x' + u.toString(16).padStart(16, '0') + '</b>' +
          '<em class="mono">' + (u > 999999n ? Number(u).toExponential(3) : u.toString()) + '</em>' +
          '<i class="mono">' + (isFinite(f) && Math.abs(f) > 1e-6 && Math.abs(f) < 1e15 ? 'f64 ' + Number(f.toPrecision(6)) : '') + '</i>' +
          (ptr ? '<u class="mono">→ ' + esc(ptr.sec) + '+0x' + ptr.off.toString(16) + (ptr.sym ? ' ' + ptr.sym : '') + '</u>' : '') +
          '</span>');
      }
    }
    body += '<div class="dd-row" data-off="' + (sec.sh_offset + base) + '" data-size="16">' +
      '<span class="dd-off mono">+' + hx(base, 4) + '</span>' +
      '<span class="dd-hex mono">' + hexs + '</span>' +
      '<span class="dd-ascii mono">' + asc + '</span>' +
      '<span class="dd-cells">' + cells.join('') + '</span></div>';
  }
  return '<div class="sp-toolbar">' + sw +
    '<span class="muted">显示前 ' + rowN + ' 行（每行 16 字节），鼠标悬停单元格可看完整解读</span></div>' +
    '<div class="sp-code dd">' + body + '</div>' +
    (bytes.length > limitBytes ? '<div class="sp-note muted">仅显示前 ' + fmtComma(limitBytes) + ' 字节，可在左侧 Hex 视图中继续浏览。</div>' : '');
}

/** 段内容摘要（一行文字概括这个段里到底有什么） */
function sectionSummary(elf, sec) {
  const n = sec.sh_size;
  if (sec.sh_type === 8) return '仅占内存，无文件内容';
  if (sec.kind === 'text') {
    const insns = previewInsns(elf, sec, 1e9);
    const funcs = elf.symbols.filter(function (s) {
      return s.type === 2 && s.st_shndx !== 0 && inSection(elf, s, sec);
    }).length;
    return fmtComma(n) + ' 字节 · ' + fmtComma(insns.length) + ' 条指令 · ' + funcs + ' 个函数符号';
  }
  if (sec.sh_type === 2 || sec.sh_type === 11) {
    const syms = elf.symbols.filter(function (s) { return s.tableIndex === sec.index; });
    const f = syms.filter(function (s) { return s.type === 2; }).length;
    return syms.length + ' 个符号（其中函数 ' + f + ' 个）';
  }
  if (sec.sh_type === 3) {
    const cnt = countStrings(sectionBytes(elf, sec));
    return cnt + ' 个字符串 · ' + fmtComma(n) + ' 字节';
  }
  if (sec.sh_type === 4 || sec.sh_type === 9) {
    const rs = elf.relocations.filter(function (r) { return r.table === sec.name; });
    return rs.length + ' 条重定位';
  }
  if (sec.sh_type === 6) return elf.dynamic.length + ' 条动态表项';
  if (sec.sh_type === 7) return elf.notes.length + ' 条附注信息';
  if (sec.kind === 'attr' && elf.riscvAttrs) {
    const arch = elf.riscvAttrs.tags.find(function (t) { return t.tag === 5; });
    return 'ISA: ' + (arch ? arch.value : '未知');
  }
  return fmtComma(n) + ' 字节';
}

function countStrings(bytes) {
  let c = 0;
  for (let i = 0; i < bytes.length; i++) if (bytes[i] === 0 && i > 0) c++;
  return c;
}

function previewInsns(elf, sec, limit) {
  const code = sectionBytes(elf, sec);
  if (!code.length) return [];
  if (limit >= 1e8) {                      // 全量结果缓存，避免同一段重复反汇编
    elf._disCache = elf._disCache || new Map();
    if (elf._disCache.has(sec.index)) return elf._disCache.get(sec.index);
    const all = disassemble(elf, sec, code, sec.sh_addr);
    elf._disCache.set(sec.index, all);
    return all;
  }
  const maxBytes = limit < 1e8 ? Math.min(code.length, limit * 4 + 16) : code.length;
  return disassemble(elf, sec, code.subarray(0, maxBytes), sec.sh_addr);
}

/** 每个段的内容预览：反汇编 / 符号名 / 字符串 / 重定位 / 十六进制转储 */
function sectionPreview(elf, sec) {
  if (sec.sh_type === 8) return '<div class="sp-note">SHT_NOBITS：该段在文件中不占字节，只在内存里按 sh_size 分配（典型如 .bss）。</div>';
  const bytes = sectionBytes(elf, sec);
  if (!bytes.length) return '<div class="sp-note muted">该段没有可读取的文件字节。</div>';

  if (sec.kind === 'text') {
    const insns = previewInsns(elf, sec, PREVIEW_LINES);
    const lines = insns.slice(0, PREVIEW_LINES).map(function (ins) {
      const raw = Array.prototype.slice.call(ins.bytes || []).map(byteHex).join(' ');
      return '<div class="sp-line' + (ins.symbol ? ' is-sym' : '') + (ins.illegal ? ' bad' : '') +
        '" data-off="' + ins.fileOffset + '" data-size="' + (ins.size || 1) + '" data-addr="' + ins.addr + '">' +
        '<span class="sp-addr">' + hx(ins.addr, elf.is64 ? 8 : 6) + '</span>' +
        '<span class="sp-bytes">' + raw + '</span>' +
        '<span class="sp-text">' + esc(ins.text) + '</span>' +
        '<span class="sp-note-cell">' + (ins.symbol ? '<span class="tag sym">' + esc(ins.symbol) + '</span>' : '') +
        (ins.targetSymbol ? '<span class="tag target">' + esc(ins.targetSymbol) + '</span>' : '') + '</span></div>';
    }).join('');
    const insnCount = previewInsns(elf, sec, 1e9).length;
    return '<div class="sp-toolbar"><span class="muted">指令预览（前 ' + PREVIEW_LINES + ' 条，共 ' +
      fmtComma(insnCount) + ' 条）</span>' +
      '<span class="muted">点击任意指令 → 下方显示它的二进制位域与助记符对照</span>' +
      '<button class="mini" data-open-disasm="' + sec.name + '">在反汇编视图中打开 →</button>' +
      '<button class="mini" data-sel="' + sec.sh_offset + ',' + Math.min(sec.sh_size, 256) + '">看原始字节</button></div>' +
      '<div class="sp-code">' + lines + '</div>' +
      '<div class="sec-enc-slot"><div class="sp-note muted">↑ 点上方任意一条指令，这里会显示它的位域拆解（opcode / funct3 / rd / rs1 / imm…）与助记符的对应关系。</div></div>';
  }

  if (sec.sh_type === 2 || sec.sh_type === 11) {
    return symbolTableDecode(elf, sec);
  }

  if (sec.sh_type === 3) {
    const out = [];
    let p = 0;
    const seen = [];
    while (p < bytes.length && seen.length < 40) {
      const s = cstr(bytes, p);
      if (s) seen.push({ off: p, s: s });
      p += s.length + 1;
      if (s.length === 0 && p > 0 && bytes[p - 1] === 0) { /* 连续空串，继续 */ }
      if (p >= bytes.length) break;
    }
    const rows = seen.map(function (x) {
      return '<div class="sp-line str" data-off="' + (sec.sh_offset + x.off) + '" data-size="' + (x.s.length + 1) + '">' +
        '<span class="sp-addr">' + hx(x.off, 4) + '</span>' +
        '<span class="sp-name mono">' + esc(x.s) + '</span></div>';
    }).join('');
    return '<div class="sp-toolbar"><span class="muted">字符串预览（前 ' + seen.length + ' 条）</span>' +
      '<button class="mini" data-sel="' + sec.sh_offset + ',' + Math.min(sec.sh_size, 256) + '">看原始字节</button></div>' +
      '<div class="sp-code">' + rows + '</div>';
  }

  if (sec.sh_type === 4 || sec.sh_type === 9) {
    const rs = elf.relocations.filter(function (r) { return r.table === sec.name; }).slice(0, 26);
    const rows = rs.map(function (r) {
      return '<div class="sp-line" data-off="' + r.fileOff + '" data-size="' + (elf.is64 ? 24 : 12) +
        '" data-reloc="' + esc(sec.name) + ':' + r.index + '">' +
        '<span class="sp-addr">' + hx(r.fileOff) + '</span>' +
        '<span class="sp-name mono">' + esc(relocTypeName(elf, r.type)) + '</span>' +
        '<span class="sp-text muted">r_offset=' + hx(r.offset, elf.is64 ? 10 : 6) + '</span>' +
        '<span class="sp-note-cell">' + esc(r.symbolName || ('#' + r.symIndex)) +
        (r.addend !== null && r.addend !== undefined ? ' + ' + r.addend : '') + '</span></div>';
    }).join('');
    return '<div class="sp-toolbar"><span class="muted">重定位项预览（前 ' + rs.length + ' 条）</span>' +
      '<span class="muted">点击任意一条 → 下方展开它的字段拆解与引用链路</span>' +
      '<button class="mini" data-tab-jump="relocs">打开完整重定位表 →</button></div>' +
      relocSectionSummary(elf, sec) +
      '<div class="sp-code">' + rows + '</div>' +
      '<div class="sec-reloc-slot"></div>';
  }

  if (sec.sh_type === 6) {
    const rows = elf.dynamic.map(function (d) {
      const e2 = enumEntry('DT_tag', d.tag);
      const hint = d.tag === 1 ? ' → "' + cstr(elf.sectionByName.get('.dynstr') ? sectionBytes(elf, elf.sectionByName.get('.dynstr')) : new Uint8Array(0), d.val) + '"' : '';
      return '<div class="sp-line" data-off="' + d.fileOff + '" data-size="' + d.size + '">' +
        '<span class="sp-addr">' + hx(d.fileOff) + '</span>' +
        '<span class="sp-name mono">' + esc(e2 ? e2.name : ('tag ' + d.tag)) + '</span>' +
        '<span class="sp-text mono">' + hx(d.val) + esc(hint) + '</span></div>';
    }).join('');
    return '<div class="sp-toolbar"><span class="muted">动态表 ' + elf.dynamic.length + ' 项</span></div><div class="sp-code">' + rows + '</div>';
  }

  if (sec.sh_type === 7) {
    const rows = elf.notes.filter(function (n) { return n.section === sec.name; }).map(function (n) {
      const hexs = Array.prototype.slice.call(n.desc).map(byteHex).join(' ');
      return '<div class="sp-line" data-off="' + n.fileOff + '" data-size="12">' +
        '<span class="sp-addr">' + hx(n.fileOff) + '</span>' +
        '<span class="sp-name mono">' + esc(n.name) + '</span>' +
        '<span class="sp-text muted">type=' + n.type + (n.name === 'GNU' && n.type === 3 ? ' (build-id)' : '') + '</span>' +
        '<span class="sp-note-cell mono">' + esc(hexs) + '</span></div>';
    }).join('');
    return '<div class="sp-code">' + rows + '</div>';
  }

  if (sec.kind === 'attr' && elf.riscvAttrs && sec.name === '.riscv.attributes') {
    const rows = elf.riscvAttrs.tags.map(function (t) {
      return '<div class="sp-line"><span class="sp-name mono">' + esc(t.name) + '</span>' +
        '<span class="sp-text mono">' + esc(t.value) + '</span></div>';
    }).join('');
    return '<div class="sp-toolbar"><span class="muted">厂商 ' + esc(elf.riscvAttrs.vendor) + '</span></div><div class="sp-code">' + rows + '</div>';
  }

  // 其它段（.rodata / .data / .comment / .debug_* 等）→ 内容解码面板
  return dataDecodePanel(elf, sec);
}

function renderSections() {
  const elf = S.elf;
  const pane = $('#pane-sections');
  if (!elf.valid) { pane.innerHTML = ''; return; }
  const cards = elf.shdrs.filter(function (s) { return s.index !== 0; }).map(function (s) {
    const noBits = s.sh_type === 8;
    return '<div class="card sec-card" data-sec-index="' + s.index + '" data-off="' + s.sh_offset + '" data-size="' + Math.max(1, s.sh_size) + '">' +
      '<div class="card-h"><i class="dot" style="background:var(--c-' + s.kind + ')"></i>' +
      '<b class="mono">' + esc(s.name || '(无名)') + '</b>' +
      '<span class="pill">' + esc(shTypeName(s.sh_type)) + '</span>' +
      '<span class="pill">' + shFlagsText(s.sh_flags) + '</span>' +
      '<span class="muted">虚拟地址 ' + hx(s.sh_addr, elf.is64 ? 10 : 6) + ' · 文件偏移 ' +
      (noBits ? '— (SHT_NOBITS)' : hx(s.sh_offset)) + ' · ' + fmtComma(s.sh_size) + ' 字节' +
      (noBits ? '（只在内存中占位，文件里没有对应字节）' : '') + '</span></div>' +
      (s.purpose ? '<div class="purpose">📘 ' + esc(s.purpose) + '</div>' : '') +
      '<div class="sec-content">' + sectionPreview(elf, s) + '</div>' +
      '</div>';
  }).join('');
  pane.innerHTML = cards;
  $$('.sec-card', pane).forEach(function (c) {
    c.addEventListener('click', function (e) {
      const modeBtn = e.target.closest('.sp-mode');
      if (modeBtn) {
        e.stopPropagation();
        S.decodeMode = S.decodeMode || {};
        S.decodeMode[+modeBtn.dataset.sec] = modeBtn.dataset.mode;
        renderSections();
        return;
      }
      const dis = e.target.closest('[data-open-disasm]');
      if (dis) { e.stopPropagation(); openDisasmAt(indexSecAddr(dis.dataset.openDisasm), null, dis.dataset.openDisasm); return; }
      const tabJump = e.target.closest('[data-tab-jump]');
      if (tabJump) { e.stopPropagation(); switchTab(tabJump.dataset.tabJump); return; }
      const selBtn = e.target.closest('[data-sel]');
      if (selBtn) {
        e.stopPropagation();
        const p = selBtn.dataset.sel.split(',');
        selectBytes(+p[0], +p[1], { smooth: true });
        return;
      }
      const line = e.target.closest('[data-off]');
      if (line) {
        e.stopPropagation();
        const off = +line.dataset.off, size = +line.dataset.size || 1;
        selectBytes(off, Math.min(size, 4096), { smooth: true });
        // .text 的指令行 → 在下方的编码槽里展示位域拆解
        const addr = line.dataset.addr;
        if (addr !== undefined) {
          const slot = c.querySelector('.sec-enc-slot');
          const secIdx = +c.dataset.secIndex;
          const list = (S.elf._disCache && S.elf._disCache.get(secIdx)) || [];
          const insn = list.find(function (x) { return x.addr === +addr; });
          if (slot && insn) {
            slot.innerHTML = insnEncodingBlock(S.elf, insn);
            slot.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
            setStatus('指令 ' + insn.text + ' 的位域拆解已显示在下方（二进制 ↔ 助记符对照）');
          }
          return;
        }
        // .rela.* 的重定位行 → 展开字段拆解与引用链路
        if (line.dataset.reloc) {
          const parts = line.dataset.reloc.split(':');
          const r = S.elf.relocations.find(function (x) { return x.table === parts[0] && x.index === +parts[1]; });
          const slot = c.querySelector('.sec-reloc-slot');
          if (r && slot) {
            slot.innerHTML = relocXrefPanel(S.elf, r);
            wireXref(slot);
            slot.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
            setStatus('已展开重定位项 ' + r.table + '[' + r.index + ']：' + relocTypeName(S.elf, r.type) +
              '，引用符号 ' + (r.symbolName || ('#' + r.symIndex)));
          }
          return;
        }
        if (line.dataset.sym !== undefined) {
          const sym = S.elf.symbols[+line.dataset.sym];
          if (sym) {
            const slot = c.querySelector('.sec-sym-slot');
            if (slot) {
              slot.innerHTML = symbolXrefPanel(S.elf, sym);
              wireXref(slot);
              slot.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
            }
            setStatus('已展开符号 ' + sym.name + ' 的表项解析与引用关系（表项 ' + hx(sym.fileOff) +
              '，内容 ' + (sym.fileOffset !== undefined ? hx(sym.fileOffset) : '不占文件空间') + '）');
          }
        }
        return;
      }
      const off = +c.dataset.off;
      selectBytes(off, Math.min(+c.dataset.size, S.elf.size - off), { smooth: true });
    });
    c.addEventListener('mouseover', function (e) {
      const line = e.target.closest('[data-off]');
      if (line) hoverRange(+line.dataset.off, Math.max(1, Math.min(+line.dataset.size || 1, 4096)));
    });
    c.addEventListener('mouseout', clearHover);
  });
}

function indexSecAddr(name) {
  const s = S.elf.sectionByName.get(name);
  return s ? s.sh_addr : 0;
}

/* ---------------------------- 符号表 ---------------------------- */
function renderSymbols() {
  const elf = S.elf;
  const pane = $('#pane-symbols');
  if (!elf.valid) { pane.innerHTML = ''; return; }
  const f = S.symFilter;
  const tables = [];
  elf.symbols.forEach(function (s) { if (tables.indexOf(s.table) < 0) tables.push(s.table); });

  const list = elf.symbols.filter(function (s) {
    if (f.type === 'func' && s.type !== 2) return false;
    if (f.type === 'object' && s.type !== 1) return false;
    if (f.type === 'undef' && s.st_shndx !== 0) return false;
    if (f.bind === 'local' && s.bind !== 0) return false;
    if (f.bind === 'global' && s.bind === 0) return false;
    if (f.table !== 'all' && s.table !== f.table) return false;
    if (f.q) {
      const q = f.q.toLowerCase();
      if (String(s.name).toLowerCase().indexOf(q) < 0 && hx(s.st_value).indexOf(q) < 0) return false;
    }
    return true;
  });

  const rows = list.slice(0, 2000).map(function (s) {
    const isFunc = s.type === 2 && s.st_shndx !== 0;
    return '<tr class="sym-row' + (isFunc ? ' isfunc' : '') + '" data-idx="' + elf.symbols.indexOf(s) + '">' +
      '<td class="mono">' + s.index + '</td>' +
      '<td class="mono sname">' + esc(s.name || '(匿名)') + '</td>' +
      '<td class="mono">' + hx(s.st_value, elf.is64 ? 10 : 6) + '</td>' +
      '<td class="mono">' + fmtComma(s.st_size) + '</td>' +
      '<td class="mono">' + esc(stTypeName(s.type)) + '</td>' +
      '<td class="mono">' + esc(stBindName(s.bind)) + '</td>' +
      '<td class="mono nowrap" title="' + esc(stVisHint(s.vis)) + '">' + esc(stVisName(s.vis)) + '</td>' +
      '<td class="mono nowrap" title="' + esc(stShndxHint(s.st_shndx)) + '">' + esc(stShndxName(elf, s.st_shndx)) + '</td>' +
      '<td class="mono">' + hx(s.fileOff) + '</td>' +
      '<td class="mono">' + (s.fileOffset !== undefined ? hx(s.fileOffset) : '—') + '</td>' +
      '<td class="sym-acts">' +
      '<button class="mini" data-entry="1" title="跳转到该符号在符号表中的表项字节（st_name/st_value/st_info…）">表项</button>' +
      (s.fileOffset !== undefined ? '<button class="mini" data-content="1" title="跳转到该符号指向的段内容">内容</button>' : '') +
      '<button class="mini" data-xref="1" title="展开该表项的字段解析与引用关系图">解析</button>' +
      (isFunc ? '<button class="mini" data-disasm="1" title="在反汇编视图中打开该函数">反汇编</button>' : '') +
      '</td></tr>';
  }).join('') || '<tr><td colspan="10" class="muted">没有匹配的符号</td></tr>';

  pane.innerHTML = '<div class="card"><div class="card-h"><b>符号表</b>' +
    '<select id="sym-table"><option value="all">全部表</option>' + tables.map(function (t) {
      return '<option value="' + esc(t) + '">' + esc(t || '(未命名)') + '</option>';
    }).join('') + '</select>' +
    '<select id="sym-type"><option value="all">全部类型</option><option value="func">仅函数 STT_FUNC</option>' +
    '<option value="object">仅数据对象 STT_OBJECT</option><option value="undef">仅未定义符号</option></select>' +
    '<select id="sym-bind"><option value="all">全部绑定</option><option value="local">仅局部 LOCAL</option>' +
    '<option value="global">仅全局 GLOBAL/WEAK</option></select>' +
    '<input id="sym-q" placeholder="搜索名称或地址…" value="' + esc(f.q) + '">' +
    '<span class="muted">共 ' + elf.symbols.length + ' 个，显示 ' + list.length + ' 个</span></div>' +
    '<div class="table-scroll tall"><table class="grid"><thead><tr><th>#</th><th>名称</th><th>st_value</th><th>st_size</th>' +
    '<th>类型</th><th>绑定</th><th>可见性</th><th>所属段</th><th>表项偏移</th><th>内容偏移</th><th>跳转</th></tr></thead>' +
    '<tbody>' + rows + '</tbody></table></div>' +
    '<div class="muted small"><b>表项偏移</b> = 该符号在 .symtab/.dynsym 中那一行表项自身的物理位置；' +
    '<b>内容偏移</b> = st_value 换算出的段内字节位置（.bss 等不占文件空间的符号则为 —）。' +
    '点「表项」看符号是怎么被记录的，点「内容」看它指向的代码/数据。</div></div>';

  $('#sym-table').value = f.table;
  $('#sym-type').value = f.type;
  $('#sym-bind').value = f.bind;
  $('#sym-table').addEventListener('change', function (e) { f.table = e.target.value; renderSymbols(); });
  $('#sym-type').addEventListener('change', function (e) { f.type = e.target.value; renderSymbols(); });
  $('#sym-bind').addEventListener('change', function (e) { f.bind = e.target.value; renderSymbols(); });
  $('#sym-q').addEventListener('input', function (e) {
    f.q = e.target.value;
    clearTimeout(renderSymbols._t);
    renderSymbols._t = setTimeout(renderSymbols, 180);
  });

  $$('.sym-row', pane).forEach(function (tr) {
    const sym = elf.symbols[+tr.dataset.idx];
    tr.addEventListener('mouseenter', function () {
      if (sym.fileOffset !== undefined) hoverRange(sym.fileOffset, Math.max(1, Math.min(sym.st_size || 1, 4096)));
      else hoverRange(sym.fileOff, elf.is64 ? 24 : 16);
    });
    tr.addEventListener('mouseleave', clearHover);
    tr.addEventListener('click', function (e) {
      if (e.target.dataset.disasm) { openDisasmAt(sym.st_value, sym); return; }
      if (e.target.dataset.entry) {                       // 符号表项本身
        selectBytes(sym.fileOff, elf.is64 ? 24 : 16, { smooth: true });
        setStatus('已定位到符号 ' + sym.name + ' 在符号表中的表项：' + hx(sym.fileOff) +
          '（' + sym.table + '[' + sym.index + ']）');
        return;
      }
      if (e.target.dataset.content) {                     // 符号指向的段内容
        selectBytes(sym.fileOffset, Math.max(1, Math.min(sym.st_size || 1, 8192)), { smooth: true });
        setStatus('已定位到符号 ' + sym.name + ' 指向的段内容：' + hx(sym.fileOffset) + '（' + sym.sec + '）');
        return;
      }
      if (e.target.dataset.xref) {                        // 展开解析与引用关系面板
        toggleSymXref(tr, sym);
        return;
      }
      if (sym.fileOffset !== undefined) {
        selectBytes(sym.fileOffset, Math.max(1, Math.min(sym.st_size || 1, 8192)), { smooth: true });
      } else if (sym.st_shndx === 0) {
        setStatus('符号 ' + sym.name + ' 是未定义符号（SHN_UNDEF），本文件内没有它的实体字节。');
      } else {
        selectBytes(sym.fileOff, elf.is64 ? 24 : 16, { smooth: true });
        setStatus('符号 ' + sym.name + ' 指向的是不占文件空间的区域（如 .bss），虚拟地址 ' + hx(sym.st_value) +
          '；已改为定位它在符号表中的表项。');
      }
      toggleSymXref(tr, sym);                             // 点行同时展开引用关系面板
    });
  });
}

/* ---------------------------- 重定位 ---------------------------- */
function renderRelocations() {
  const elf = S.elf;
  const pane = $('#pane-relocs');
  if (!elf.valid) { pane.innerHTML = ''; return; }
  if (!elf.relocations.length) {
    pane.innerHTML = '<div class="card"><b>没有重定位表</b><p class="muted">' +
      '重定位表达「在哪个位置、按什么规则填入哪个符号的地址」。静态链接完成的可执行文件通常没有重定位；' +
      '而 -pie / -shared 产物会保留 .rela.dyn、.rela.plt 等，供动态链接器在加载时修补。</p></div>';
    return;
  }
  const rows = elf.relocations.map(function (r) {
    return '<tr class="rel-row" data-off="' + r.fileOff + '">' +
      '<td class="mono">' + esc(r.table) + '</td><td class="mono">' + r.index + '</td>' +
      '<td class="mono">' + hx(r.offset, elf.is64 ? 10 : 6) + '</td>' +
      '<td class="mono">' + esc(relocTypeName(elf, r.type)) + '</td>' +
      '<td class="mono">' + esc(r.symbolName || ('#' + r.symIndex)) + '</td>' +
      '<td class="mono">' + (r.addend === null ? '—' : (r.addend < 0 ? '-' + hx(-r.addend) : hx(r.addend))) + '</td></tr>';
  }).join('');
  pane.innerHTML = '<div class="card"><div class="card-h"><b>重定位表</b><span class="muted">共 ' + elf.relocations.length + ' 项</span></div>' +
    relocSectionSummary(elf, elf.shdrs.find(function (s) { return s.name === elf.relocations[0].table; }) || elf.shdrs[0]) +
    '<div class="table-scroll tall"><table class="grid"><thead><tr><th>所在表</th><th>#</th><th>r_offset（虚拟地址）</th>' +
    '<th>类型</th><th>符号</th><th>加数 addend</th></tr></thead><tbody>' + rows + '</tbody></table></div>' +
    '<div class="muted small">提示：r_info 是打包字段——64 位下高 32 位为符号索引、低 32 位为类型；32 位下高 24 位为符号索引、低 8 位为类型。' +
    'RISC-V 的地址装载被拆成 HI20/LO12 两条重定位配合修补，这源自 32 位定长指令无法容纳完整地址。</div></div>';
  $$('.rel-row', pane).forEach(function (tr) {
    tr.addEventListener('click', function (e) {
      const r = elf.relocations.find(function (x) { return x.fileOff === +tr.dataset.off; });
      selectBytes(+tr.dataset.off, elf.is64 ? 24 : 12);
      if (r) {
        selectVaddr(r.offset, 4, { smooth: true });
        toggleRelocXref(tr, r);          // 就地展开字段拆解 + 引用链路
      }
    });
  });
}

/* ---------------------------- 枚举字典 ---------------------------- */
/* 字典不按主题罗列，而是按「字段在文件中的出现顺序」组织：
 * 这样从文件开头往下读，遇到的每个枚举字段都能在字典里按同样顺序找到。 */
function enumFieldIndex(elf) {
  const list = [], byId = new Map();
  if (!elf || !elf.valid) return list;
  for (const a of elf.annotations) {
    if (!a.enumKey || !ENUMS[a.enumKey]) continue;
    const id = a.enumKey + '@' + a.field;
    let item = byId.get(id);
    if (!item) {
      item = {
        id: id, key: a.enumKey, field: a.field, first: a.start, size: a.size,
        count: 0, offsets: [], holders: [], sample: a
      };
      byId.set(id, item);
      list.push(item);
    }
    item.count++;
    item.offsets.push(a.start);
    if (item.holders.indexOf(a.container) < 0 && item.holders.length < 3) item.holders.push(a.container);
  }
  return list;
}

/**
 * 扫描文件中的所有字段标注，找出某个枚举在文件中「被用在哪些字节上」。
 * 返回 Map<取值, {start, size, container}>，用于字典里一键定位到 Hex。
 */
function enumUsages(elf, key) {
  const map = new Map();
  if (!elf || !elf.valid) return map;
  const e = ENUMS[key];
  if (!e || !e.values.length) return map;
  for (const a of elf.annotations) {
    if (a.enumKey !== key) continue;
    const val = fieldRawValue(elf, a);
    const info = { start: a.start, size: a.size, container: a.container, field: a.field };
    if (e.mask) {
      // 位掩码型：为每个被置位的标志位记录第一次出现的位置
      for (const v of e.values) {
        if (isFlagBit(v.v) && (val & v.v) && !map.has(v.v)) map.set(v.v, info);
      }
    } else if (!map.has(val)) {
      map.set(val, info);
    }
  }
  return map;
}

/** 某个复合字段（st_info）的子字段在文件中的位置 */
function partUsage(elf, part) {
  return enumUsages(elf, part.enum);
}

function openDictionary(key) {
  S.dictKey = key;
  S.dictMode = 'key';
  switchTab('dict');
  renderDictionary();
  const el = $('#dict-table');
  if (el) el.scrollIntoView({ block: 'nearest' });
}

function dictUsedValues(elf, key) {
  const used = new Set();
  if (!elf || !elf.valid) return used;
  if (key === 'e_type') used.add(elf.ehdr.e_type);
  else if (key === 'e_machine') used.add(elf.ehdr.e_machine);
  else if (key === 'e_version') used.add(elf.ehdr.e_version);
  else if (key === 'riscv_e_flags') used.add(elf.ehdr.e_flags);
  else if (key === 'EI_CLASS') used.add(elf.ehdr.e_ident.cls);
  else if (key === 'EI_DATA') used.add(elf.ehdr.e_ident.data);
  else if (key === 'EI_OSABI') used.add(elf.ehdr.e_ident.osabi);
  else if (key === 'p_type') elf.phdrs.forEach(function (p) { used.add(p.p_type); });
  else if (key === 'sh_type') elf.shdrs.forEach(function (s) { used.add(s.sh_type); });
  else if (key === 'st_shndx') elf.symbols.forEach(function (s) { used.add(s.st_shndx); });
  else if (key === 'DT_tag') elf.dynamic.forEach(function (d) { used.add(d.tag); });
  else if (key === 'R_RISCV' || key === 'R_X86_64') elf.relocations.forEach(function (r) { used.add(r.type); });
  else if (key === 'st_info') elf.symbols.forEach(function (s) { used.add(s.st_info); });
  return used;
}

/* 字段枚举值（紧凑列表） */
function enumValueList(enm, usageMap, keyHint) {
  return '<div class="ep-list">' + enm.values.map(function (v) {
    const hit = usageMap.get(v.v);
    const isMask = enm.mask;
    const on = !!hit;
    return '<div class="ep-row' + (on ? ' on' : '') + '">' +
      '<span class="ep-val mono">' + (isMask ? hx(v.v, 6) : v.v) + '</span>' +
      '<span class="ep-name mono">' + esc(v.name) + '</span>' +
      '<span class="ep-desc">' + esc(v.desc) + '</span>' +
      '<span class="ep-mark">' + (on
        ? '<button class="mini jmp" data-jump-off="' + hit.start + '" data-jump-size="' + hit.size + '"' +
          ' title="定位到 ' + esc(hit.container || '') + '">✓ 本文件使用 · 定位</button>'
        : '') + '</span></div>';
  }).join('') + '</div>';
}

function renderDictionary() {
  const elf = S.elf;
  const pane = $('#pane-dict');
  const index = enumFieldIndex(elf);

  // 默认选中文件中第一个枚举字段（即偏移最小的那个），保持与 Hex 顺序一致
  let sel = null;
  let key = S.dictKey;
  if (S.dictMode !== 'key') {
    sel = index.find(function (it) { return it.id === S.dictSelId; }) || index[0] || null;
    if (sel) { S.dictSelId = sel.id; key = sel.key; }
  }
  const e = ENUMS[key];

  // 左侧导航：① 文件中的枚举字段（按偏移顺序） ② 本文件未出现的枚举
  const usedKeys = [];
  index.forEach(function (it) {
    if (usedKeys.indexOf(it.key) < 0) usedKeys.push(it.key);
    const ps = enumParts(it.key);
    if (ps) ps.forEach(function (p) { if (usedKeys.indexOf(p.enum) < 0) usedKeys.push(p.enum); });
  });
  const remaining = Object.keys(ENUMS).filter(function (k) { return usedKeys.indexOf(k) < 0; });
  const nav =
    '<div class="dict-group"><div class="dict-group-h">本文件中的枚举字段（按文件偏移顺序）</div>' +
    (index.length ? index.map(function (it) {
      return '<button class="dict-item dict-field' + (sel && it.id === sel.id ? ' on' : '') + '" data-field-id="' + esc(it.id) + '">' +
        '<span class="df-off mono">' + hx(it.first, 4) + '</span>' +
        '<span class="df-name">' + esc(it.field) + '</span>' +
        '<span class="muted">' + (it.count > 1 ? it.count + ' 处' : '') + '</span></button>';
    }).join('') : '<div class="muted small">该文件没有可解析的枚举字段。</div>') + '</div>' +
    (remaining.length ? '<div class="dict-group"><div class="dict-group-h">其它枚举（本文件未使用）</div>' +
      remaining.map(function (k) {
        return '<button class="dict-item' + (S.dictMode === 'key' && k === key ? ' on' : '') + '" data-key="' + k + '">' + k +
          '<span class="muted">' + ENUMS[k].values.length + '</span></button>';
      }).join('') + '</div>' : '');

  const usages = enumUsages(elf, key);

  const parts = enumParts(key);
  const mainTable = parts
    ? '<div class="callout">这是一个<b>打包字段</b>：一个字节里塞了两个子字段，必须按下表拆分理解。</div>' +
      parts.map(function (p) {
        const sub = ENUMS[p.enum];
        return '<h4 class="dict-sub">' + esc(p.name) + ' <span class="muted">' + esc(p.bits) + ' · ' + esc(p.desc) + '</span></h4>' +
          enumValueList(sub, partUsage(elf, p), p.enum);
      }).join('')
    : enumValueList(e, usages, key);

  const firstAnn = sel ? sel.sample : null;
  const locateBtn = firstAnn
    ? '<button class="mini" id="dict-locate">在 Hex 中定位该字段</button>' : '';

  // 该字段在文件中的所有出现位置（点击即可逐个跳转）
  const instances = sel && sel.offsets.length > 1
    ? '<div class="dict-instances"><span class="muted">在文件中出现 ' + sel.count + ' 处：</span>' +
      sel.offsets.slice(0, 80).map(function (o) {
        return '<button class="mini chip" data-jump-off="' + o + '" data-jump-size="' + sel.size + '">' + hx(o) + '</button>';
      }).join('') + (sel.offsets.length > 80 ? '<span class="muted">… 其余 ' + (sel.offsets.length - 80) + ' 处</span>' : '') + '</div>'
    : '';

  const curCallout = (sel && firstAnn)
    ? '<div class="callout">本文件中 <b>' + esc(sel.field) + '</b> 位于 <b class="mono">' + hx(firstAnn.start) + '</b>（' +
      firstAnn.size + ' 字节）' +
      (firstAnn.container ? '，属于 ' + esc(firstAnn.container) : '') + '。<br>当前原始值 <b class="mono">' +
      hx(fieldRawValue(elf, firstAnn)) + '</b>' +
      (decodeValue(key, fieldRawValue(elf, firstAnn)).length
        ? ' → ' + decodeValue(key, fieldRawValue(elf, firstAnn)).map(esc).join('；') : '') + '</div>'
    : '';

  const flagsCallout = (key === 'riscv_e_flags' && elf && elf.valid)
    ? '<div class="callout"><b>本文件 e_flags = ' + hx(elf.ehdr.e_flags, 4) + '</b><br>' +
      decodeValue(key, elf.ehdr.e_flags).map(esc).join('<br>') + '</div>'
    : '';

  const layouts = [['Elf32_Ehdr', EHDR_FIELDS[32]], ['Elf64_Ehdr', EHDR_FIELDS[64]],
  ['Elf32_Phdr', PHDR_FIELDS[32]], ['Elf64_Phdr', PHDR_FIELDS[64]],
  ['Elf32_Shdr', SHDR_FIELDS[32]], ['Elf64_Shdr', SHDR_FIELDS[64]],
  ['Elf32_Sym', SYM_FIELDS[32]], ['Elf64_Sym', SYM_FIELDS[64]],
  ['Elf32_Rela', RELA_FIELDS[32]], ['Elf64_Rela', RELA_FIELDS[64]]]
    .map(function (x) { return structLayoutCard(x[0], x[1]); }).join('');

  pane.innerHTML = '<div class="dict-wrap">' +
    '<aside class="dict-nav"><div class="dict-title">字典导航 · 按文件偏移顺序</div>' + nav +
    '<div class="dict-note">左侧条目按字段在文件中的<b>字节顺序</b>排列，与 Hex 视图从上到下的浏览顺序一致。' +
    '标记 <b>✓ 本文件使用</b> 的取值可点击，Hex 会滚动并高亮到该字段的物理字节。</div></aside>' +
    '<div class="dict-body">' +
    '<div class="card"><div class="card-h"><b>' + esc(e.title) + '</b><span class="pill">' + esc(e.abi) + '</span>' + locateBtn + '</div>' +
    '<div class="dict-desc">' + esc(e.desc) + '</div>' + curCallout + flagsCallout + instances + mainTable + '</div>' +
    '<div class="card"><div class="card-h"><b>结构字段布局速查</b><span class="muted">每个字段的偏移、长度与作用</span></div>' +
    '<div class="muted small">点击任意字段行 → 在 Hex 视图中定位到文件中第一个该结构的对应字节，并弹出该字段的可选取值与说明；与当前文件位数不符的结构会被置灰。</div>' +
    '<div class="layout-grid">' + layouts + '</div>' +
    '<div class="muted small">' + esc(NOTE_FIELD_DOC) + '</div></div>' +
    '</div></div>';

  $$('.dict-item', pane).forEach(function (b) {
    b.addEventListener('click', function () {
      if (b.dataset.fieldId) { S.dictSelId = b.dataset.fieldId; S.dictMode = 'field'; }
      else { S.dictKey = b.dataset.key; S.dictMode = 'key'; }
      renderDictionary();
    });
  });
  $$('[data-jump-off]', pane).forEach(function (b) {
    b.addEventListener('click', function (ev) {
      ev.stopPropagation();
      selectBytes(+b.dataset.jumpOff, +b.dataset.jumpSize, { smooth: true });
      setStatus('已定位到该取值对应的字段字节：文件偏移 ' + hx(+b.dataset.jumpOff));
    });
    b.addEventListener('mouseenter', function () { hoverRange(+b.dataset.jumpOff, +b.dataset.jumpSize); });
    b.addEventListener('mouseleave', clearHover);
  });
  const loc = $('#dict-locate');
  if (loc && firstAnn) {
    loc.addEventListener('click', function () {
      selectBytes(firstAnn.start, firstAnn.size, { smooth: true });
      setStatus('已定位到字段 ' + firstAnn.field + '（' + firstAnn.container + '）@ ' + hx(firstAnn.start));
    });
  }
  wireLayoutRows(pane);
}

/** 该结构在文件中的第一个实例（用于把字段布局表变成可跳转的导航） */
function structInstance(elf, type) {
  if (!elf || !elf.valid) return null;
  const is64 = type.indexOf('64') !== -1;
  if (is64 !== elf.is64) return null;                 // 与文件位数不符 → 置灰
  if (type.indexOf('Ehdr') >= 0) return { off: 0, size: is64 ? 64 : 52 };
  if (type.indexOf('Phdr') >= 0) { const p = elf.phdrs[0]; return p ? { off: p.fileOff, size: is64 ? 56 : 32 } : null; }
  if (type.indexOf('Shdr') >= 0) { const s = elf.shdrs[0]; return s ? { off: s.fileOff, size: is64 ? 64 : 40 } : null; }
  if (type.indexOf('Sym') >= 0) { const s = elf.symbols[0]; return s ? { off: s.fileOff, size: is64 ? 24 : 16 } : null; }
  if (type.indexOf('Rela') >= 0) { const r = elf.relocations[0]; return r ? { off: r.fileOff, size: is64 ? 24 : 12 } : null; }
  return null;
}

function structLayoutCard(title, fields) {
  let total = 0;
  fields.forEach(function (f) { total = Math.max(total, f.off + f.size); });
  const inst = structInstance(S.elf, title);
  const rows = fields.map(function (f) {
    const d = f.desc.length > 46 ? f.desc.slice(0, 46) + '…' : f.desc;
    const attr = inst ? ' data-off="' + (inst.off + f.off) + '" data-size="' + f.size +
      '" data-holder="' + esc(title) + ' 实例 @ ' + hx(inst.off) + '"' : '';
    return '<div class="layout-row' + (inst ? ' jumpable' : ' dim') + '"' + attr +
      ' title="' + esc(f.desc) + (inst ? '（点击定位到文件偏移 ' + hx(inst.off + f.off) + '）' : '（当前文件不包含该结构）') + '">' +
      '<span class="mono lo">' + hx(f.off, 2) + '</span>' +
      '<b class="mono ln">' + esc(f.name) + '</b><span class="muted ls">' + f.size + 'B</span>' +
      '<span class="muted ldesc">' + esc(d) + '</span></div>';
  }).join('');
  return '<div class="layout-card' + (inst ? ' live' : '') + '"><div class="layout-h">' + title +
    ' <span class="muted">共 ' + total + ' 字节' + (inst ? ' · 实例 @ ' + hx(inst.off) : ' · 本文件无此结构') + '</span></div>' +
    '<div class="layout-rows">' + rows + '</div></div>';
}

/** 结构字段布局行：悬停高亮整段字节，点击定位 */
function wireLayoutRows(root) {
  $$('.layout-row.jumpable', root).forEach(function (row) {
    row.addEventListener('mouseenter', function () { hoverRange(+row.dataset.off, +row.dataset.size); });
    row.addEventListener('mouseleave', clearHover);
    row.addEventListener('click', function () {
      selectBytes(+row.dataset.off, +row.dataset.size, { smooth: true });
      setStatus('已定位到字段字节：' + row.dataset.holder + '，文件偏移 ' + hx(+row.dataset.off));
    });
  });
}
