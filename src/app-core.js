/* ============================================================================
 * app-core.js — 全局状态、工具函数、文件加载、联动、字节探针、概览面板
 * ==========================================================================*/
'use strict';

const S = {
  elf: null,
  hex: null,
  tab: 'overview',
  dictKey: 'e_type',
  dictSelId: null,      // 字典左侧选中的「字段条目」id
  dictMode: 'field',    // 'field' = 按文件偏移浏览字段；'key' = 直接看某个枚举
  pinned: null,       // 被固定的字节探针偏移
  symFilter: { q: '', type: 'all', bind: 'all', table: 'all' },
  disasm: { sec: null, start: 0, aliases: true, forceC: 'auto', showBytes: true, limit: 400 }
};

const $ = (sel, root) => (root || document).querySelector(sel);
const $$ = (sel, root) => Array.prototype.slice.call((root || document).querySelectorAll(sel));

/* ---------------------------- 字段导航 ----------------------------
 * 「逐位 / 逐字段」浏览：光标在文件中的位置既可以用方向键单步，
 * 也可以用 [ ] 在结构字段之间跳转；被选中的位置会「钉住」探针内容，
 * 这样鼠标移开也不会丢失信息。
 */
function currentOffset() {
  if (S.hex && S.hex.cursor >= 0) return S.hex.cursor;
  if (S.pinned) return S.pinned.start;
  return -1;
}

/** 定位到某个文件偏移（可选高亮长度、是否钉住探针） */
function focusOffset(off, size, opts) {
  opts = opts || {};
  if (!S.elf) return;
  off = Math.max(0, Math.min(S.elf.size - 1, off));
  size = Math.max(1, Math.min(size || 1, S.elf.size - off));
  if (opts.smooth) S.hex.jumpTo(off, size, { smooth: true });
  else {
    S.hex.setSelection(off, off + size);
    S.hex.setCursor(off);
    S.hex.ensureVisible(off);
    if (opts.flash !== false) S.hex.flash(off, size);
  }
  S.hex.anchor = off;
  if (opts.pin !== false) pinRange(off, size);
  else updateInspector(off, size);
}

function pinRange(off, size) {
  S.pinned = { start: off, size: size };
  updateInspector(off, size);
}

function unpin() {
  S.pinned = null;
  updateInspector(S.hex ? S.hex.hover : -1);
}

function stepByte(delta) {
  if (!S.elf) return;
  const cur = currentOffset();
  focusOffset((cur < 0 ? 0 : cur) + delta, 1, { smooth: false });
}

function stepPage(dir) {
  if (!S.elf) return;
  const cur = currentOffset();
  focusOffset((cur < 0 ? 0 : cur) + dir * S.hex.pageBytes(), 1);
}

/** 在结构字段之间前后跳转（annotations 已按偏移排序） */
function stepField(dir) {
  if (!S.elf) return;
  const list = S.elf.annotations;
  if (!list.length) { setStatus('该文件中没有可导航的结构字段（没有头部/符号表/重定位等结构）'); return; }
  const cur = currentOffset();
  let i;
  if (dir > 0) {
    i = 0;
    while (i < list.length && list[i].start <= cur) i++;
    if (i >= list.length) i = 0;
  } else {
    i = list.length - 1;
    while (i >= 0 && list[i].start >= cur) i--;
    if (i < 0) i = list.length - 1;
  }
  const a = list[i];
  focusOffset(a.start, a.end - a.start, { pin: true });
  setStatus('字段导航：' + a.field + ' @ ' + (a.container || '') +
    '（文件偏移 ' + hx(a.start) + '，第 ' + (i + 1) + ' / ' + list.length + ' 个字段）');
}

/** 当前偏移落在第几个字段上（用于探针里的进度显示） */
function fieldIndexOf(off) {
  const list = S.elf ? S.elf.annotations : [];
  let lo = 0, hi = list.length - 1, ans = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (list[mid].start <= off) { ans = mid; lo = mid + 1; } else hi = mid - 1;
  }
  for (let i = ans; i >= 0 && i >= ans - 4; i--) {
    if (off >= list[i].start && off < list[i].end) return { index: i, total: list.length };
  }
  return ans >= 0 ? { index: ans, total: list.length } : { index: -1, total: list.length };
}

/** 悬停字段行 / 表格行时，整段高亮对应的物理字节 */
function hoverRange(start, size) {
  if (S.hex) S.hex.setHoverRange(start, start + Math.max(1, size || 1));
}
function clearHover() {
  if (S.hex) S.hex.clearHover();
  if (S.pinned === null) updateInspector(-1);
}

function resetNavigation() {
  S.pinned = null;
  if (S.hex) { S.hex.clearHover(); S.hex.cursor = -1; S.hex.setSelection(-1, -1); }
}

/* 全局键盘：无论焦点在哪，只要不在输入框里就能逐位 / 逐字段浏览 */
function onGlobalKey(e) {
  if (!S.elf) return;
  if (e.metaKey || e.ctrlKey || e.altKey) return;
  const t = e.target;
  if (t && (t.tagName === 'INPUT' || t.tagName === 'SELECT' || t.tagName === 'TEXTAREA')) return;
  let handled = true;
  if (e.key === 'Escape' && enumPopEl) { closeEnumPopover(); e.preventDefault(); return; }
  switch (e.key) {
    case 'ArrowRight': stepByte(1); break;
    case 'ArrowLeft': stepByte(-1); break;
    case 'ArrowDown': stepByte(16); break;
    case 'ArrowUp': stepByte(-16); break;
    case 'PageDown': stepPage(1); break;
    case 'PageUp': stepPage(-1); break;
    case 'Home': focusOffset(0, 1, { smooth: false }); break;
    case 'End': focusOffset(S.elf.size - 1, 1, { smooth: false }); break;
    case ']': case '】': stepField(1); break;
    case '[': case '【': stepField(-1); break;
    case 'Escape': unpin(); break;
    default: handled = false;
  }
  if (handled) e.preventDefault();
}

/* ---------------------------- 概览面板 ---------------------------- */
function badgeList(elf) {
  const b = [];
  if (!elf.valid) return '';
  b.push('<span class="badge b-arch">' + esc(machineName(elf.ehdr.e_machine)) + '</span>');
  b.push('<span class="badge">' + (elf.is64 ? 'ELF64' : 'ELF32') + '</span>');
  b.push('<span class="badge">' + (elf.le ? '小端序 LSB' : '大端序 MSB') + '</span>');
  b.push('<span class="badge b-type">' + esc(eTypeName(elf.ehdr.e_type)) + '</span>');
  const abi = enumEntry('EI_OSABI', elf.ehdr.e_ident.osabi);
  b.push('<span class="badge">ABI: ' + esc(abi ? abi.name : elf.ehdr.e_ident.osabi) + '</span>');
  if (elf.ehdr.e_flags & 1) b.push('<span class="badge b-rvc">RVC 压缩指令</span>');
  return b.join('');
}

function kv(label, value) {
  return '<div><label>' + label + '</label><b>' + value + '</b></div>';
}
function kvBtn(label, value, attr) {
  return '<div><label>' + label + '</label><b>' + value + '</b> <button class="mini" ' + attr + '>定位</button></div>';
}

function renderOverview() {
  const elf = S.elf;
  const pane = $('#pane-overview');
  const tot = elf.size || 1;
  const stats = summarize(elf);

  const segs = elf.regions.map(function (r) {
    const w = Math.max(0.05, (r.end - r.start) / tot * 100).toFixed(4);
    return '<span class="ov-seg" style="left:' + (r.start / tot * 100).toFixed(4) + '%;width:' + w +
      '%;background:var(--c-' + r.kind + ')" data-start="' + r.start + '" data-end="' + r.end +
      '" title="' + esc(kindName(r.kind)) + ' · ' + esc(r.label || '') + ' @ ' + hx(r.start) + '–' + hx(r.end) + '"></span>';
  }).join('');

  const legend = stats.map(function (s) {
    return '<button class="lg-item" data-kind="' + s.kind + '">' +
      '<i style="background:var(--c-' + s.kind + ')"></i>' +
      '<span class="lg-name">' + esc(kindName(s.kind)) + '</span>' +
      '<span class="lg-bar"><b style="width:' + (s.bytes / tot * 100).toFixed(2) + '%;background:var(--c-' + s.kind + ')"></b></span>' +
      '<span class="lg-num">' + fmtSize(s.bytes) + ' · ' + (s.bytes / tot * 100).toFixed(1) + '%</span>' +
      '<span class="lg-cnt">' + s.count + ' 块</span></button>';
  }).join('');

  const notes = elf.notes.length
    ? elf.notes.map(function (n) {
      const data = Array.prototype.slice.call(n.desc).map(byteHex).join('');
      return '<li><code>' + esc(n.section) + '</code> 名字=<b>' + esc(n.name) + '</b> 类型=' + n.type +
        (n.name === 'GNU' && n.type === 3 ? ' <span class="tag target">GNU build-id</span>' : '') +
        '<br><span class="mono muted">' + esc(data) + '</span></li>';
    }).join('')
    : '<li class="muted">该文件没有附注段 (.note.*)</li>';

  const attrs = elf.riscvAttrs
    ? '<li>厂商：<b>' + esc(elf.riscvAttrs.vendor) + '</b></li>' + elf.riscvAttrs.tags.map(function (t) {
      return '<li>' + esc(t.name) + '：<b class="mono">' + esc(t.value) + '</b></li>';
    }).join('')
    : '<li class="muted">该文件没有 .riscv.attributes 段</li>';

  const checks = elf.errors.map(function (e) { return '<li class="err">✗ ' + esc(e) + '</li>'; }).join('') +
    elf.warnings.map(function (e) { return '<li class="warn">⚠ ' + esc(e) + '</li>'; }).join('');

  pane.innerHTML =
    '<div class="card"><div class="card-h"><b>目标文件</b>' + badgeList(elf) + '</div>' +
    '<div class="kv-grid">' +
    kv('文件名', esc(elf.name)) +
    kv('文件大小', fmtComma(elf.size) + ' 字节 (' + hx(elf.size) + ')') +
    kvBtn('入口地址 e_entry', hx(elf.ehdr.e_entry, elf.is64 ? 16 : 8), 'data-jump-va="' + elf.ehdr.e_entry + '"') +
    kvBtn('程序头表 e_phoff', hx(elf.ehdr.e_phoff), 'data-jump-off="' + elf.ehdr.e_phoff + '"') +
    kvBtn('段头表 e_shoff', hx(elf.ehdr.e_shoff), 'data-jump-off="' + elf.ehdr.e_shoff + '"') +
    kv('结构规模', elf.phdrs.length + ' 个程序头 · ' + elf.shdrs.length + ' 个段头 · ' +
      elf.symbols.length + ' 个符号 · ' + elf.relocations.length + ' 个重定位') +
    '</div></div>' +

    '<div class="card"><div class="card-h"><b>全文件结构分布</b><span class="muted">点击色块或图例即可定位到对应字节区间</span></div>' +
    '<div class="ov-bar" id="ov-bar">' + segs + '<div class="ov-window" id="ov-window"></div></div>' +
    '<div class="legend">' + legend + '</div></div>' +

    '<div class="card cols2">' +
    '<div><div class="card-h">附注信息 (Note)</div><ul class="plain">' + notes + '</ul></div>' +
    '<div><div class="card-h">RISC-V 属性 (.riscv.attributes)</div><ul class="plain">' + attrs + '</ul></div>' +
    '</div>' +

    (checks ? '<div class="card"><div class="card-h"><b>校验结果</b></div><ul class="plain">' + checks + '</ul></div>' : '');

  $$('[data-jump-off]', pane).forEach(function (b) {
    b.addEventListener('click', function () { selectBytes(+b.dataset.jumpOff, 1); });
  });
  $$('[data-jump-va]', pane).forEach(function (b) {
    b.addEventListener('click', function () { selectVaddr(+b.dataset.jumpVa, 4); });
  });
  $$('.lg-item', pane).forEach(function (b) {
    b.addEventListener('click', function () {
      const r = S.elf.regions.find(function (x) { return x.kind === b.dataset.kind; });
      if (r) selectBytes(r.start, r.end - r.start, { smooth: true });
    });
  });
  const bar = $('#ov-bar');
  bar.addEventListener('click', function (e) {
    const seg = e.target.closest('.ov-seg');
    if (seg) { selectBytes(+seg.dataset.start, +seg.dataset.end - +seg.dataset.start); return; }
    const rect = bar.getBoundingClientRect();
    const p = (e.clientX - rect.left) / rect.width;
    selectBytes(Math.floor(p * S.elf.size), 1);
  });
  updateOverviewViewport();
}

/* 左右分栏拖拽：让用户按需给 Hex 视图或结构面板更多空间 */
function wireSplitter() {
  const sp = $('#splitter');
  const split = $('.split');
  if (!sp || !split) return;
  let dragging = false;
  function move(e) {
    const r = split.getBoundingClientRect();
    const p = Math.max(22, Math.min(80, ((e.clientX - r.left) / r.width) * 100));
    split.style.setProperty('--left-w', p.toFixed(2) + '%');
  }
  sp.addEventListener('mousedown', function (e) {
    dragging = true; sp.classList.add('dragging');
    document.body.style.userSelect = 'none';
    e.preventDefault();
  });
  window.addEventListener('mousemove', function (e) { if (dragging) move(e); });
  window.addEventListener('mouseup', function () {
    if (!dragging) return;
    dragging = false; sp.classList.remove('dragging');
    document.body.style.userSelect = '';
    if (S.hex) S.hex.update(true);
    updateOverviewViewport();
  });
}

/* ---------------------------- 启动 ---------------------------- */
function boot() {
  S.hex = new HexView($('#hexview'), {
    onHover: function (off, shift, ev) {
      if (S.pinned === null) updateInspector(off);
      if (ev && ev.buttons) { hideByteTip(); return; }    // 正在拖选时不弹窗
      scheduleByteTip(off, ev);
    },
    onSelect: function (sel) {
      if (!sel) return;
      // 在 Hex 上单击 / 拖选 → 钉住探针内容，鼠标移开也不会丢失
      pinRange(sel.start, sel.end - sel.start);
      markDisasmLineForOffset(sel.start);
    },
    onScroll: function () { updateOverviewViewport(); hideByteTip(); }
  });
  wireTabs();
  wireToolbar();
  wireDropZone();
  wireSplitter();
  wireInspectorNav();
  document.addEventListener('keydown', onGlobalKey);
  window.addEventListener('resize', function () { S.hex.update(true); updateOverviewViewport(); });
  document.addEventListener('keydown', function (e) {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'o') { e.preventDefault(); $('#file-input').click(); }
  });
  const demo = $('#demo-btn');
  if (demo) demo.addEventListener('click', loadDemo);
  // 便于自动化验证 / 直接体验：打开 elf-studio.html?demo=1 时自动载入内置示例
  if (/[?&]demo(=1)?\b/.test(location.search)) loadDemo();
  // 调试/自动化观察入口
  window.__elfStudio = S;
}

/* ---------------------------- 文件加载 ---------------------------- */
async function loadFiles(fileList) {
  const files = Array.prototype.slice.call(fileList || []);
  if (!files.length) return;
  const f = files[0];
  setStatus('正在读取 ' + f.name + ' …');
  try {
    const buf = new Uint8Array(await f.arrayBuffer());
    parseAndShow(buf, f.name);
  } catch (err) {
    setStatus('读取文件失败：' + err.message);
  }
}

function parseAndShow(bytes, name) {
  const t0 = performance.now();
  let elf;
  try {
    elf = parseELF(bytes, name);
  } catch (err) {
    setStatus('解析异常：' + err.message);
    return;
  }
  const dt = performance.now() - t0;
  S.elf = elf;
  S.pinned = null;
  S.disasm.sec = null;
  $('#empty-state').classList.add('hidden');
  $('#workspace').classList.remove('hidden');
  $('#file-title').textContent = name;
  const meta = elf.valid
    ? fmtSize(elf.size) + ' · ' + eTypeName(elf.ehdr.e_type) + ' · ' + machineName(elf.ehdr.e_machine)
    : fmtSize(elf.size) + ' · 解析失败';
  $('#file-meta').textContent = meta;
  setStatus(elf.valid
    ? '解析完成：' + fmtSize(elf.size) + '，' + elf.shdrs.length + ' 个段，' + elf.phdrs.length + ' 个程序头，' +
      elf.symbols.length + ' 个符号，' + elf.relocations.length + ' 个重定位（耗时 ' + dt.toFixed(1) + ' ms）'
    : '解析失败：' + elf.errors.join('；'));
  S.hex.setElf(elf);
  renderOverview();
  renderElfHeader();
  renderProgramHeaders();
  renderSectionHeaders();
  renderSections();
  renderSymbols();
  renderRelocations();
  renderDictionary();
  renderDisasm();
  updateInspector(-1);
  switchTab('overview');
}

function setStatus(txt) { $('#status').textContent = txt; }

/* ---------------------------- 顶栏 ---------------------------- */
function wireToolbar() {
  $('#file-input').addEventListener('change', function (e) { loadFiles(e.target.files); });
  $('#open-btn').addEventListener('click', function () { $('#file-input').click(); });
  $('#jump-input').addEventListener('keydown', function (e) {
    if (e.key !== 'Enter') return;
    const q = e.target.value.trim();
    if (q && S.elf) doJumpQuery(q);
  });
}

function doJumpQuery(q) {
  const elf = S.elf;
  let target = null;
  const cleaned = q.replace(/_/g, '');
  if (/^(0x[0-9a-f]+|[0-9a-f]+h)$/i.test(cleaned)) {
    const val = parseInt(cleaned.replace(/h$/i, '').replace(/^0x/i, ''), 16);
    if (val >= 0 && val < elf.size) target = { off: val, size: 1, why: '文件偏移' };
    else { const r = vaddrToOffset(elf, val); if (r) target = { off: r.offset, size: 1, why: '虚拟地址' }; }
  } else if (/^\d+$/.test(cleaned)) {
    const val = parseInt(cleaned, 10);
    if (val < elf.size) target = { off: val, size: 1, why: '十进制偏移' };
    else { const r = vaddrToOffset(elf, val); if (r) target = { off: r.offset, size: 1, why: '虚拟地址' }; }
  }
  if (!target) {
    const s = elf.sectionByName.get(q) || elf.sectionByName.get('.' + q);
    if (s) target = { off: s.sh_offset, size: s.sh_size, why: '段 ' + s.name };
  }
  if (!target) {
    let sym = elf.symbols.find(function (s) { return s.name === q; });
    if (!sym) sym = elf.symbols.find(function (s) { return s.name && q && s.name.indexOf(q) >= 0; });
    if (sym) {
      let off = sym.fileOffset;
      if (off === undefined && sym.st_shndx !== 0) {
        const r = vaddrToOffset(elf, sym.st_value);
        if (r) off = r.offset;
      }
      if (off !== undefined) target = { off: off, size: Math.max(1, Math.min(sym.st_size || 1, 65536)), why: '符号 ' + sym.name, sym: sym };
    }
  }
  if (!target) { setStatus('未找到与 “' + q + '” 匹配的偏移 / 段 / 符号'); return; }
  selectBytes(target.off, target.size, { smooth: true });
  if (target.sym && target.sym.type === 2) openDisasmAt(target.sym.st_value, target.sym);
  setStatus('已定位到' + target.why + '：文件偏移 ' + hx(target.off));
}

function wireDropZone() {
  const dz = $('#dropzone');
  let depth = 0;
  function stop(e) { e.preventDefault(); e.stopPropagation(); }
  ['dragenter', 'dragover'].forEach(function (ev) {
    document.addEventListener(ev, function (e) {
      stop(e);
      if (e.dataTransfer && Array.prototype.indexOf.call(e.dataTransfer.types || [], 'Files') >= 0) {
        if (ev === 'dragenter') depth++;
        dz.classList.add('active');
      }
    });
  });
  document.addEventListener('dragleave', function (e) { stop(e); depth--; if (depth <= 0) { depth = 0; dz.classList.remove('active'); } });
  document.addEventListener('drop', function (e) {
    stop(e); depth = 0; dz.classList.remove('active');
    if (e.dataTransfer && e.dataTransfer.files) loadFiles(e.dataTransfer.files);
  });
}

function loadDemo() {
  try {
    const b64 = window.DEMO_ELF_BASE64;
    if (!b64) { setStatus('未内置示例文件'); return; }
    const bin = atob(b64);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    parseAndShow(arr, 'demo-hello-riscv64.elf');
  } catch (e) { setStatus('加载示例失败：' + e.message); }
}

/* ---------------------------- 标签页 ---------------------------- */
const TABS = [
  ['overview', '概览'],
  ['ehdr', 'ELF 头'],
  ['phdr', '程序头'],
  ['shdr', '段头表'],
  ['sections', '段内容'],
  ['symbols', '符号表'],
  ['relocs', '重定位'],
  ['disasm', '反汇编'],
  ['dict', '枚举字典']
];

function wireTabs() {
  const bar = $('#tabs');
  bar.innerHTML = TABS.map(function (t) { return '<button class="tab" data-tab="' + t[0] + '">' + t[1] + '</button>'; }).join('');
  bar.addEventListener('click', function (e) {
    const b = e.target.closest('.tab');
    if (b) switchTab(b.dataset.tab);
  });
}

function switchTab(tab) {
  S.tab = tab;
  $$('#tabs .tab').forEach(function (b) { b.classList.toggle('on', b.dataset.tab === tab); });
  $$('#tabpanes > section').forEach(function (s) { s.classList.toggle('on', s.id === 'pane-' + tab); });
}

/* ---------------------------- 联动入口 ---------------------------- */
function selectBytes(off, size, opts) {
  opts = opts || {};
  focusOffset(off || 0, size || 1, { smooth: opts.smooth !== false, pin: opts.pin !== false, flash: true });
}

function selectVaddr(va, size, opts) {
  const r = vaddrToOffset(S.elf, va);
  if (!r) {
    setStatus('虚拟地址 ' + hx(va) + ' 没有对应的文件偏移（可能属于 .bss 等 NOBITS 区域）');
    return false;
  }
  selectBytes(r.offset, size || 1, opts);
  return true;
}

function updateOverviewViewport() {
  if (!S.elf) return;
  const bar = $('#ov-bar');
  if (!bar) return;
  const info = S.hex.visibleInfo();
  const a = (info.first * 16) / S.elf.size;
  const b = Math.min(1, ((info.first + info.count) * 16) / S.elf.size);
  const win = $('#ov-window');
  if (!win) return;
  win.style.left = (a * 100) + '%';
  win.style.width = Math.max(0.4, (b - a) * 100) + '%';
}

/* ---------------------------- 字节探针 ---------------------------- */

/* --------------------- 字段枚举弹出面板（Popover） ---------------------
 * 点击某个字段时，就近弹出该字段的「全部可选取值 + 当前值 + 规范说明」。
 * 面板是浮层，不改变任何表格的布局，因此不会打断按字节顺序的浏览节奏。
 */
let enumPopEl = null;

function closeEnumPopover() {
  if (enumPopEl) { enumPopEl.remove(); enumPopEl = null; }
}

function enumPopoverRow(key, v, currentVal, elf, ann) {
  const isMask = ENUMS[key].mask;
  const on = (currentVal !== null && currentVal !== undefined) &&
    (isMask ? (isFlagBit(v.v) && (currentVal & v.v) === v.v) : v.v === currentVal);
  return '<div class="ep-row' + (on ? ' on' : '') + '">' +
    '<span class="ep-val mono">' + (isMask ? hx(v.v, 6) : v.v) + '</span>' +
    '<span class="ep-name mono">' + esc(v.name) + '</span>' +
    '<span class="ep-desc">' + esc(v.desc) + '</span>' +
    '<span class="ep-mark">' + (on ? '✓ 本文件取值' : '') + '</span></div>';
}

/**
 * @param {Element} anchor 触发元素（字段行）
 * @param {string} key     枚举键
 * @param {number} off     字段在文件中的起始偏移
 * @param {number} size    字段字节数
 */
function showEnumPopover(anchor, key, off, size) {
  closeEnumPopover();
  const elf = S.elf;
  if (!elf || !ENUMS[key] || !anchor) return;
  const e = ENUMS[key];
  const ann = annotationAt(elf, off) || (off + size > 0 ? { start: off, size: size, field: e.title.split(' ')[0] } : null);
  const curVal = ann && ann.start === off ? fieldRawValue(elf, ann) : null;
  const parts = enumParts(key);

  let body;
  if (parts) {
    body = parts.map(function (p) {
      const sub = ENUMS[p.enum];
      const subVal = (p.enum === 'st_bind') ? (curVal >> 4) & 0xf
        : (p.enum === 'st_type') ? (curVal & 0xf) : null;
      return '<div class="ep-part">' +
        '<div class="ep-part-h"><b>' + esc(p.name) + '</b>' +
        '<span class="pill">' + esc(p.bits) + '</span>' +
        '<span class="muted">' + esc(p.desc) + '</span>' +
        '<button class="mini ep-dict" data-dict="' + p.enum + '">字典 →</button></div>' +
        '<div class="ep-list">' + sub.values.map(function (v) {
          return enumPopoverRow(p.enum, v, subVal, elf, ann);
        }).join('') + '</div></div>';
    }).join('');
  } else {
    body = '<div class="ep-list">' + e.values.map(function (v) {
      return enumPopoverRow(key, v, curVal, elf, ann);
    }).join('') + '</div>';
  }

  const decoded = decodeValue(key, curVal).join('；');
  const va = offsetToVaddr(elf, off);
  const pop = document.createElement('div');
  pop.className = 'enum-pop';
  pop.innerHTML =
    '<div class="ep-head">' +
    '<div><b>' + esc(ann && ann.field ? ann.field : e.title.split(' ')[0]) + '</b>' +
    '<span class="pill">' + esc(key) + '</span>' +
    '<span class="muted">' + esc(e.abi) + '</span></div>' +
    '<button class="mini ep-close" title="关闭 (Esc)">✕</button></div>' +
    '<div class="ep-cur">' +
    '<span>当前取值 <b class="mono">' + (curVal === null ? '—' : hx(curVal)) + '</b></span>' +
    '<span>位置 <b class="mono">' + hx(off) + '</b> · ' + size + ' 字节' +
    (va ? ' · VAddr <b class="mono">' + hx(va.vaddr) + '</b>' : '') + '</span>' +
    (decoded ? '<span class="ep-decoded">→ ' + esc(decoded) + '</span>' : '') +
    '<button class="mini" id="ep-flash">闪烁定位</button></div>' +
    '<div class="ep-desc-full">' + esc(e.desc) + '</div>' +
    bytesGroupBlock(elf, off, size, key, '该字段的字节与位视图') +
    '<div class="ep-body">' + body + '</div>';
  document.body.appendChild(pop);

  // 定位：优先放在锚点下方，空间不足则放上方；并夹在视口内
  const r = anchor.getBoundingClientRect();
  const pw = pop.offsetWidth, ph = pop.offsetHeight;
  let left = Math.min(Math.max(8, r.left + r.width / 2 - pw / 2), window.innerWidth - pw - 8);
  let top = r.bottom + 8;
  if (top + ph > window.innerHeight - 8) top = Math.max(8, r.top - ph - 8);
  pop.style.left = left + 'px';
  pop.style.top = top + 'px';
  enumPopEl = pop;
  // 把「当前取值」那一行滚入面板可视区（只滚动面板自身，不影响页面其它区域）
  const curRow = pop.querySelector('.ep-row.on');
  const bodyEl = pop.querySelector('.ep-body');
  if (curRow && bodyEl) {
    const rr = curRow.getBoundingClientRect(), br = bodyEl.getBoundingClientRect();
    bodyEl.scrollTop += (rr.top - br.top) - (bodyEl.clientHeight - rr.height) / 2;
  }

  pop.querySelector('.ep-close').addEventListener('click', closeEnumPopover);
  const flashBtn = pop.querySelector('#ep-flash');
  if (flashBtn) flashBtn.addEventListener('click', function () { S.hex.flash(off, size); });
  pop.querySelectorAll('.ep-dict').forEach(function (b) {
    b.addEventListener('click', function () { closeEnumPopover(); openDictionary(b.dataset.dict); });
  });
  anchor.classList.add('pop-open');
  setTimeout(function () {
    document.addEventListener('mousedown', onDocMouseDownForPop, true);
  }, 0);
}

function onDocMouseDownForPop(e) {
  if (!enumPopEl) { document.removeEventListener('mousedown', onDocMouseDownForPop, true); return; }
  if (enumPopEl.contains(e.target)) return;
  if (e.target.closest && e.target.closest('tr.fld')) return;   // 点击其它字段行 → 由它自己重开
  closeEnumPopover();
}

/* --------------------- 字节组解读悬浮窗（字节序对照） ---------------------
 * 悬停 Hex 中某个字节时，就近浮出一个小窗：把从该字节开始的一组字节
 * 分别按「文件字节序」与「相反字节序」解读成整数 / 浮点数 / 字符串，
 * 便于直接比对 LSB 与 MSB 两种读法下的数值差异。
 */
let byteTipEl = null;
let byteTipTimer = 0;
let byteTipOn = true;
try { byteTipOn = localStorage.getItem('elfstudio.byteTip') !== '0'; } catch (e) { byteTipOn = true; }

/**
 * 字节组对照块：原始字节 → 另一种字节序的字节顺序 → 两种读法的数值 → 二进制位图。
 * 这是把「文件里看到的字节」和「字典里的枚举值」对上号的关键视图。
 */
function bytesGroupBlock(elf, start, size, enumKey, titleOverride) {
  const g = groupView(elf.bytes, start, size, elf.le);
  const le = elf.le;
  const primName = le ? '小端 (本文件)' : '大端 (本文件)';
  const compName = le ? '大端 (对照)' : '小端 (对照)';
  const bitsArr = g.bits.split(' ');
  // 位图：每 8 位一组，置位的 bit 高亮，并标出组内最高位的位号
  let bitCells = '';
  for (let gi = 0; gi < bitsArr.length; gi++) {
    const group = bitsArr[gi];
    const high = size * 8 - 1 - gi * 8;
    bitCells += '<span class="bb-grp"><i class="bb-bnum">' + high + '</i>';
    for (let i = 0; i < group.length; i++) {
      const bitNo = high - i;
      const on = group[i] === '1';
      bitCells += '<b class="bb-bit' + (on ? ' on' : '') + '" data-bit="' + bitNo + '" title="bit ' + bitNo + (on ? '：置位' : '：为 0') + '">' + group[i] + '</b>';
    }
    bitCells += '</span>';
  }
  // 置位 bit 的枚举对照
  let setInfo = '';
  if (g.setBits.length) {
    const tags = g.setBits.slice(0, 24).map(function (b) {
      const names = [];
      if (enumKey) { const n = describeBit(enumKey, b); if (n) names.push(n); }
      return '<span class="bit-tag"><b>bit ' + b + '</b>' + (names.length ? ' → ' + esc(names[0]) : '') + '</span>';
    }).join('');
    setInfo = '<div class="bb-set">置位：' + g.setBits.slice(0, 24).map(function (b) { return '<b>' + b + '</b>'; }).join(', ') +
      (g.setBits.length > 24 ? ' …' : '') + '</div><div class="bb-tags">' + tags + '</div>';
  } else {
    setInfo = '<div class="bb-set muted">所有位均为 0（该值为 0）</div>';
  }
  return '<div class="bb">' +
    '<div class="bb-head">' + esc(titleOverride || ('从 ' + hx(start) + ' 起的 ' + size + ' 字节')) +
    '<span class="muted">' + esc(primName) + '</span></div>' +
    '<div class="bb-row"><label>原始字节</label><code>' + esc(g.rawHex) + '</code>' +
    '<span class="muted">文件中的存储顺序</span></div>' +
    '<div class="bb-row"><label>' + (le ? '大端预览' : '小端预览') + '</label><code>' + esc(g.swappedHex) + '</code>' +
    '<span class="muted">按另一字节序重排后的可读顺序</span></div>' +
    '<div class="bb-row"><label>数值</label>' +
    '<code>' + esc(primName) + ' = ' + esc(g.primHex) + ' = ' + esc(g.prim) + '</code></div>' +
    '<div class="bb-row"><label></label><code class="dim">' + esc(compName) + ' = ' + esc(g.compHex) + ' = ' + esc(g.comp) + '</code></div>' +
    '<div class="bb-bits">' + bitCells + '</div>' +
    setInfo +
    (g.avail < size ? '<div class="muted small">注意：该组已越过文件末尾，缺失的 ' + (size - g.avail) + ' 字节按 0 处理。</div>' : '') +
    '</div>';
}

function hideByteTip() {
  clearTimeout(byteTipTimer);
  if (byteTipEl) { byteTipEl.remove(); byteTipEl = null; }
}

function setByteTipEnabled(on) {
  byteTipOn = on;
  try { localStorage.setItem('elfstudio.byteTip', on ? '1' : '0'); } catch (e) { /* file:// 下可能不可用 */ }
  if (!on) hideByteTip();
}

function showByteTip(off, ev) {
  if (!byteTipOn || !S.elf || off < 0 || !ev) return;
  const elf = S.elf;
  const info = interpretBytes(elf.bytes, off, elf.le);
  if (!info.rows.length) return;
  const ann = annotationAt(elf, off);
  const reg = S.hex.regionAt(off);
  const le = elf.le;
  // 字节组对照：优先按「所属字段的大小」成组，没有字段时按当前位置起的 4 字节
  const grpStart = ann ? ann.start : off;
  const grpSize = ann ? ann.size : 4;
  const grpTitle = ann
    ? '字段 ' + ann.field + '（' + ann.size + ' 字节 @ ' + hx(ann.start) + '）'
    : ('从 ' + hx(off) + ' 起的 4 字节');
  const rows = info.rows.map(function (r) {
    const hexPrim = r.primHex && r.primHex !== '0x' ? r.primHex : '';
    const hexComp = r.compHex && r.compHex !== '0x' ? r.compHex : '';
    return '<div class="bt-row" data-size="' + r.size + '" data-off="' + off + '">' +
      '<span class="bt-type mono">' + r.name + '</span>' +
      '<span class="bt-size muted">' + r.size + 'B</span>' +
      '<span class="bt-cell"><b class="mono">' + esc(r.prim) + '</b>' + (hexPrim ? '<em class="mono">' + esc(hexPrim) + '</em>' : '') + '</span>' +
      (r.size > 1
        ? '<span class="bt-cell comp"><b class="mono">' + esc(r.comp) + '</b>' + (hexComp ? '<em class="mono">' + esc(hexComp) + '</em>' : '') + '</span>'
        : '<span class="bt-cell comp muted">—</span>') +
      '</div>';
  }).join('');
  const tip = document.createElement('div');
  tip.className = 'byte-tip';
  tip.innerHTML =
    '<div class="bt-head"><b class="mono">' + hx(off, 8) + '</b>' +
    '<span class="muted">' + (reg ? esc(kindName(reg.kind)) : '') + '</span>' +
    '<span class="bt-endian">' + (le ? 'little-endian（本文件）' : 'big-endian（本文件）') + '</span></div>' +
    (ann ? '<div class="bt-field">字段 <b>' + esc(ann.field) + '</b>' +
      (ann.enumKey ? ' <span class="muted">→ ' + esc(decodeValue(ann.enumKey, fieldRawValue(elf, ann)).join('；')) + '</span>' : '') + '</div>' : '') +
    bytesGroupBlock(elf, grpStart, grpSize, ann ? ann.enumKey : null, grpTitle) +
    '<div class="bt-cols"><span>类型</span><span>本文件字节序</span><span>对照（另一字节序）</span></div>' +
    rows +
    (info.string ? '<div class="bt-str">字符串 <b class="mono">“' + esc(info.string) + '”</b></div>' : '');
  document.body.appendChild(tip);
  hideByteTip();
  byteTipEl = tip;

  // 定位在光标右下方，越界则翻转
  const w = tip.offsetWidth, h = tip.offsetHeight;
  let x = ev.clientX + 16, y = ev.clientY + 16;
  if (x + w > window.innerWidth - 8) x = Math.max(8, ev.clientX - w - 16);
  if (y + h > window.innerHeight - 8) y = Math.max(8, window.innerHeight - h - 8);
  tip.style.left = x + 'px';
  tip.style.top = y + 'px';

  // 悬停某一行 → 在 Hex 中高亮该行对应的字节组，直观看出"这几个字节"
  $$('.bt-row', tip).forEach(function (rowEl) {
    rowEl.addEventListener('mouseenter', function () {
      S.hex.setHoverRange(off, off + (+rowEl.dataset.size));
    });
  });
}

/** 悬停 Hex 时更新悬浮窗（带轻微延迟，避免快速划过时闪烁） */
function scheduleByteTip(off, ev) {
  clearTimeout(byteTipTimer);
  if (!byteTipOn || off < 0) { hideByteTip(); return; }
  byteTipTimer = setTimeout(function () { showByteTip(off, ev); }, 45);
}

function updateInspector(off, size) {
  const elf = S.elf;
  updateInspectorProgress(off, size);
  if (!elf || off === undefined || off < 0) {
    $('#ins-off').textContent = $('#ins-va').textContent = $('#ins-byte').textContent = '—';
    $('#ins-region').textContent = '—';
    $('#ins-region').className = 'ins-val mono';
    $('#ins-field').textContent = '—';
    $('#ins-desc').textContent = '把鼠标移到左侧 Hex 上的任意字节 → 这里会实时显示它的物理偏移、虚拟地址、所属字段与字段含义。单击可固定选中，拖动可选中一段区间。';
    $('#ins-enum').innerHTML = '';
    return;
  }
  // 光标同步（用键盘/按钮移动时，让 Hex 视图中的光标跟随）
  if (S.hex && S.hex.cursor !== off) { S.hex.cursor = off; S.hex._paint(); }
  const len = size || 1;
  const isMulti = len > 1;
  const b0 = elf.bytes[off];
  const va = offsetToVaddr(elf, off);
  const reg = S.hex.regionAt(off);
  const ann = annotationAt(elf, off);

  $('#ins-off').textContent = hx(off, 8) + '  (' + fmtComma(off) + ')';
  $('#ins-va').textContent = va ? hx(va.vaddr, elf.is64 ? 16 : 8) : '—（未映射到内存）';
  $('#ins-va').title = va ? '来源：' + va.source : '该偏移不被任何可分配段/段描述覆盖';

  if (!isMulti) {
    const ch = (b0 >= 32 && b0 < 127) ? "  '" + String.fromCharCode(b0) + "'" : '  (非可打印)';
    $('#ins-byte').textContent = '0x' + byteHex(b0) + ' = ' + b0 + ' = 0b' + b0.toString(2).padStart(8, '0') + ch;
  } else {
    const n = Math.min(len, 12);
    let s = len + ' 字节：';
    for (let i = off; i < off + n; i++) s += byteHex(elf.bytes[i]) + ' ';
    $('#ins-byte').textContent = s + (len > n ? '…' : '');
  }

  $('#ins-region').textContent = reg ? (kindName(reg.kind) + '  ·  ' + (reg.label || '')) : '（未分类）';
  $('#ins-region').className = 'ins-val mono k-' + (reg ? reg.kind : 'gap');

  if (ann) {
    $('#ins-field').textContent = ann.field + (ann.container ? '   @ ' + ann.container : '');
    let desc = ann.desc || '';
    if (ann.enumKey) {
      const vals = decodeValue(ann.enumKey, fieldRawValue(elf, ann));
      if (vals.length) desc += '　→ 按枚举解码：' + vals.join('；');
    }
    $('#ins-desc').textContent = desc;
    renderEnumHint(ann);
  } else {
    $('#ins-field').textContent = '（该字节不属于任何结构字段）';
    const sec = sectionAtOffset(elf, off);
    let d = reg ? '该字节位于「' + kindName(reg.kind) + '」分区（' + (reg.label || '') + '）。' : '该字节不在任何已识别的结构内。';
    if (sec && sec.purpose) d += ' ' + sec.purpose;
    $('#ins-desc').textContent = d;
    $('#ins-enum').innerHTML = '';
  }
}

/** 探针顶部的导航状态：固定标记 + 当前位置/字段进度 */
function updateInspectorProgress(off, size) {
  const pinEl = $('#ins-pin');
  const progEl = $('#ins-progress');
  if (!pinEl || !progEl) return;
  if (S.pinned !== null) {
    pinEl.innerHTML = '📌 已固定 ' + hx(S.pinned.start) + ' <button class="mini" id="ins-unpin">取消固定 (Esc)</button>';
    pinEl.classList.add('pinned-on');
    const btn = $('#ins-unpin');
    if (btn) btn.addEventListener('click', unpin);
  } else {
    pinEl.textContent = S.elf ? '悬停预览中' : '';
    pinEl.classList.remove('pinned-on');
  }
  if (!S.elf || off === undefined || off < 0) { progEl.textContent = ''; return; }
  const f = fieldIndexOf(off);
  const pct = (off / (S.elf.size || 1) * 100).toFixed(2);
  progEl.textContent = '偏移 ' + hx(off) + ' / ' + hx(S.elf.size) + '（' + pct + '%）' +
    (f.index >= 0 ? '　·　字段 ' + (f.index + 1) + ' / ' + f.total : '　·　不在结构字段内');
}

/* 探针上的逐位 / 逐字段按钮 */
function wireInspectorNav() {
  const map = {
    'nav-byte-prev': function () { stepByte(-1); },
    'nav-byte-next': function () { stepByte(1); },
    'nav-field-prev': function () { stepField(-1); },
    'nav-field-next': function () { stepField(1); }
  };
  Object.keys(map).forEach(function (id) {
    const b = $('#' + id);
    if (b) b.addEventListener('click', map[id]);
  });
  const tipToggle = $('#byte-tip-toggle');
  if (tipToggle) {
    tipToggle.checked = byteTipOn;
    tipToggle.onchange = function () { setByteTipEnabled(tipToggle.checked); };
  }
}

function fieldRawValue(elf, ann) {
  // 打包字段需要特殊取值：r_info 的高/低位分别表示符号索引与重定位类型
  if (ann.reloc && ann.field === 'r_info') return ann.reloc.type;
  const R = elf.R, base = ann.start;
  if (ann.size === 1) return elf.bytes[base];
  if (ann.size === 2) return R.u16(base);
  if (ann.size === 4) return R.u32(base);
  if (ann.size === 8) return R.u64(base);
  return elf.bytes[base];
}

function renderEnumHint(ann) {
  const holder = $('#ins-enum');
  if (!ann.enumKey || !ENUMS[ann.enumKey]) { holder.innerHTML = ''; return; }
  const e = ENUMS[ann.enumKey];
  const val = fieldRawValue(S.elf, ann);
  const hits = e.values.filter(function (v) {
    return e.mask ? (isFlagBit(v.v) && (val & v.v) === v.v) : v.v === val;
  });
  holder.innerHTML = '<button class="link" id="ins-enum-open">弹出 ' + esc(e.title.split('—')[0].trim()) +
    ' 的全部取值与说明 ▸</button>' +
    (hits.length ? ' <span class="muted">当前：' + hits.map(function (v) { return esc(v.name); }).join(', ') + '</span>' : '');
  holder.querySelector('#ins-enum-open').addEventListener('click', function () {
    showEnumPopover($('#ins-field'), ann.enumKey, ann.start, ann.size);
  });
}

function sectionAtOffset(elf, off) {
  for (const s of elf.shdrs) {
    if (s.index === 0 || s.sh_type === 8 || s.sh_size === 0) continue;
    if (off >= s.sh_offset && off < s.sh_offset + s.sh_size) return s;
  }
  return null;
}

/* ---------------------------- 概览面板 ---------------------------- */
function badgeList(elf) {
  const b = [];
  if (!elf.valid) return '';
  b.push('<span class="badge b-arch">' + esc(machineName(elf.ehdr.e_machine)) + '</span>');
  b.push('<span class="badge">' + (elf.is64 ? 'ELF64' : 'ELF32') + '</span>');
  b.push('<span class="badge">' + (elf.le ? '小端序 LSB' : '大端序 MSB') + '</span>');
  b.push('<span class="badge b-type">' + esc(eTypeName(elf.ehdr.e_type)) + '</span>');
  const abi = enumEntry('EI_OSABI', elf.ehdr.e_ident.osabi);
  b.push('<span class="badge">ABI: ' + esc(abi ? abi.name : elf.ehdr.e_ident.osabi) + '</span>');
  if (elf.ehdr.e_flags & 1) b.push('<span class="badge b-rvc">RVC 压缩指令</span>');
  return b.join('');
}

function renderOverview() {
  const elf = S.elf;
  const pane = $('#pane-overview');
  const tot = elf.size || 1;
  const stats = summarize(elf);

  const segs = elf.regions.map(function (r) {
    const w = Math.max(0.05, (r.end - r.start) / tot * 100).toFixed(4);
    return '<span class="ov-seg" style="left:' + (r.start / tot * 100).toFixed(4) + '%;width:' + w +
      '%;background:var(--c-' + r.kind + ')" data-start="' + r.start + '" data-end="' + r.end +
      '" title="' + esc(kindName(r.kind)) + ' · ' + esc(r.label || '') + ' @ ' + hx(r.start) + '–' + hx(r.end) + '"></span>';
  }).join('');

  const legend = stats.map(function (s) {
    return '<button class="lg-item" data-kind="' + s.kind + '">' +
      '<i style="background:var(--c-' + s.kind + ')"></i>' +
      '<span class="lg-name">' + esc(kindName(s.kind)) + '</span>' +
      '<span class="lg-bar"><b style="width:' + (s.bytes / tot * 100).toFixed(2) + '%;background:var(--c-' + s.kind + ')"></b></span>' +
      '<span class="lg-num">' + fmtSize(s.bytes) + ' · ' + (s.bytes / tot * 100).toFixed(1) + '%</span>' +
      '<span class="lg-cnt">' + s.count + ' 块</span></button>';
  }).join('');

  const notes = elf.notes.length
    ? elf.notes.map(function (n) {
      const data = Array.prototype.slice.call(n.desc).map(function (b) { return byteHex(b); }).join('');
      return '<li><code>' + esc(n.section) + '</code> 名字=<b>' + esc(n.name) + '</b> 类型=' + n.type +
        (n.name === 'GNU' && n.type === 3 ? ' <span class="tag target">GNU build-id</span>' : '') +
        '<br><span class="mono muted">' + esc(data) + '</span></li>';
    }).join('')
    : '<li class="muted">该文件没有附注段 (.note.*)</li>';

  const attrs = elf.riscvAttrs
    ? '<li>厂商：<b>' + esc(elf.riscvAttrs.vendor) + '</b></li>' + elf.riscvAttrs.tags.map(function (t) {
      return '<li>' + esc(t.name) + '：<b class="mono">' + esc(t.value) + '</b></li>';
    }).join('')
    : '<li class="muted">该文件没有 .riscv.attributes 段</li>';

  const checks = elf.errors.map(function (e) { return '<li class="err">✗ ' + esc(e) + '</li>'; }).join('') +
    elf.warnings.map(function (e) { return '<li class="warn">⚠ ' + esc(e) + '</li>'; }).join('');

  pane.innerHTML =
    '<div class="card"><div class="card-h"><b>目标文件</b>' + badgeList(elf) + '</div>' +
    '<div class="kv-grid">' +
    kv('文件名', esc(elf.name)) +
    kv('文件大小', fmtComma(elf.size) + ' 字节 (' + hx(elf.size) + ')') +
    kvBtn('入口地址 e_entry', hx(elf.ehdr.e_entry, elf.is64 ? 16 : 8), 'data-jump-va="' + elf.ehdr.e_entry + '"') +
    kvBtn('程序头表 e_phoff', hx(elf.ehdr.e_phoff), 'data-jump-off="' + elf.ehdr.e_phoff + '"') +
    kvBtn('段头表 e_shoff', hx(elf.ehdr.e_shoff), 'data-jump-off="' + elf.ehdr.e_shoff + '"') +
    kv('结构规模', elf.phdrs.length + ' 个程序头 · ' + elf.shdrs.length + ' 个段头 · ' +
      elf.symbols.length + ' 个符号 · ' + elf.relocations.length + ' 个重定位') +
    '</div></div>' +

    '<div class="card"><div class="card-h"><b>全文件结构分布</b><span class="muted">点击色块或图例即可定位到对应字节区间</span></div>' +
    '<div class="ov-bar" id="ov-bar">' + segs + '<div class="ov-window" id="ov-window"></div></div>' +
    '<div class="legend">' + legend + '</div></div>' +

    '<div class="card cols2">' +
    '<div><div class="card-h">附注信息 (Note)</div><ul class="plain">' + notes + '</ul></div>' +
    '<div><div class="card-h">RISC-V 属性 (.riscv.attributes)</div><ul class="plain">' + attrs + '</ul></div>' +
    '</div>' +

    (checks ? '<div class="card"><div class="card-h"><b>校验结果</b></div><ul class="plain">' + checks + '</ul></div>' : '');

  $$('[data-jump-off]', pane).forEach(function (b) {
    b.addEventListener('click', function () { selectBytes(+b.dataset.jumpOff, 1); });
  });
  $$('[data-jump-va]', pane).forEach(function (b) {
    b.addEventListener('click', function () { selectVaddr(+b.dataset.jumpVa, 4); });
  });
  $$('.lg-item', pane).forEach(function (b) {
    b.addEventListener('click', function () {
      const r = S.elf.regions.find(function (x) { return x.kind === b.dataset.kind; });
      if (r) selectBytes(r.start, r.end - r.start, { smooth: true });
    });
  });
  const bar = $('#ov-bar');
  bar.addEventListener('click', function (e) {
    const seg = e.target.closest('.ov-seg');
    if (seg) { selectBytes(+seg.dataset.start, +seg.dataset.end - +seg.dataset.start); return; }
    const rect = bar.getBoundingClientRect();
    const p = (e.clientX - rect.left) / rect.width;
    selectBytes(Math.floor(p * S.elf.size), 1);
  });
  updateOverviewViewport();
}

function kv(label, value) {
  return '<div><label>' + label + '</label><b>' + value + '</b></div>';
}
function kvBtn(label, value, attr) {
  return '<div><label>' + label + '</label><b>' + value + '</b> <button class="mini" ' + attr + '>定位</button></div>';
}
