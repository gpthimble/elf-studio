/* ============================================================================
 * hexview.js — 多色块 Hex 视图
 *  · 虚拟滚动：只渲染可视窗口内的行，百万行文件同样流畅
 *  · 按 ELF 物理结构逐字节着色（region → CSS class）
 *  · 行内标注分区起点，行首色条标识所属结构
 *  · 悬停/点击/拖选 → 回调上层做字节级探针与联动
 * ==========================================================================*/
'use strict';

const BYTES_PER_ROW = 16;
const ROW_H = 21;          // 与 CSS 中 --row-h 保持一致

class HexView {
  constructor(root, opts) {
    this.root = root;
    this.opts = opts || {};
    this.elf = null;
    this.offW = 8;
    this.selection = null;     // {start, end}
    this.hover = -1;
    this.hoverRange = null;    // {start, end} 整段字段悬停高亮（比单字节更醒目）
    this.cursor = -1;
    this.flashRange = null;
    this._raf = 0;
    this._lastFirst = -1;
    this._build();
  }

  _build() {
    this.root.classList.add('hexview');
    this.root.innerHTML = `
      <div class="hv-head">
        <span class="hv-hcol" title="文件偏移量（十六进制）">偏移</span>
        <span class="hv-hbytes">${Array.from({ length: 16 }, (_, i) => i.toString(16).toUpperCase().padStart(2, '0')).join(' ')}</span>
        <span class="hv-hascii">ASCII 文本</span>
        <span class="hv-hstruct">结构分区</span>
      </div>
      <div class="hv-scroll" tabindex="0">
        <div class="hv-spacer"></div>
        <div class="hv-rows"></div>
      </div>`;
    this.head = this.root.querySelector('.hv-head');
    this.scroll = this.root.querySelector('.hv-scroll');
    this.spacer = this.root.querySelector('.hv-spacer');
    this.rows = this.root.querySelector('.hv-rows');

    this.scroll.addEventListener('scroll', () => this._schedule());
    this.rows.addEventListener('mousemove', (e) => this._onMove(e));
    this.rows.addEventListener('mouseleave', () => { this.hover = -1; if (this.opts.onHover) this.opts.onHover(-1, false, null); });
    this.rows.addEventListener('mousedown', (e) => this._onDown(e));
    window.addEventListener('mouseup', () => { this._dragging = false; });
    this.rows.addEventListener('mouseover', () => this._schedule());
    if (this.opts.onScroll) this.scroll.addEventListener('scroll', () => this.opts.onScroll(this.scroll.scrollTop, this.visibleInfo()));
  }

  setElf(elf) {
    this.elf = elf;
    this.offW = Math.max(8, Math.ceil(Math.log2(Math.max(elf.size, 2)) / 4) + 2);
    this.totalRows = Math.ceil(elf.size / BYTES_PER_ROW);
    this.spacer.style.height = (this.totalRows * ROW_H) + 'px';
    this.scroll.scrollTop = 0;
    this.selection = null; this.cursor = -1; this.hover = -1; this.flashRange = null;
    this._lastFirst = -1;
    this.update(true);
  }

  visibleInfo() {
    const first = Math.max(0, Math.floor(this.scroll.scrollTop / ROW_H));
    const count = Math.ceil(this.scroll.clientHeight / ROW_H) + 2;
    return { first, count, last: Math.min(this.totalRows, first + count) };
  }

  _schedule() {
    if (this._raf) return;
    this._raf = requestAnimationFrame(() => { this._raf = 0; this.update(); });
  }

  update(force) {
    if (!this.elf) return;
    const { first, count, last } = this.visibleInfo();
    if (!force && first === this._lastFirst && count === this._visCount) {
      this._paint();
      return;
    }
    this._lastFirst = first; this._visCount = count;
    const r = [];
    for (let row = first; row < last; row++) r.push(this._rowHTML(row));
    this.rows.style.transform = `translateY(${first * ROW_H}px)`;
    this.rows.innerHTML = r.join('');
    this._paint();
  }

  _rowHTML(row) {
    const elf = this.elf;
    const base = row * BYTES_PER_ROW;
    const end = Math.min(elf.size, base + BYTES_PER_ROW);
    const kinds = elf.byteKind, names = elf.kindNameById;
    let bytes = '', ascii = '';
    let rowKind = null;
    for (let i = base; i < base + BYTES_PER_ROW; i++) {
      if (i >= end) { bytes += '<i class="hb empty"></i>'; ascii += ' '; continue; }
      const k = names[kinds[i]] || 'other';
      if (rowKind === null) rowKind = k;
      const b = elf.bytes[i];
      bytes += `<i class="hb k-${k}" data-off="${i}" data-k="${k}">${b.toString(16).padStart(2, '0')}</i>`;
      ascii += (b >= 32 && b < 127) ? this._esc(String.fromCharCode(b)) : '<u>·</u>';
    }
    // 本行内新开始的分区 → 显示彩色标签
    let chips = '';
    for (const reg of this.regionsInRow(base, end)) {
      const label = (reg.label || '').slice(0, 28);
      chips += `<span class="hv-chip" data-off="${reg.start}" data-kind="${reg.kind}" title="${this._esc(reg.label)}">${this._esc(label)}</span>`;
    }
    if (!chips) {
      const reg = this.regionAt(base);
      if (reg) chips = `<span class="hv-cont">${this._esc(reg.label || '')}</span>`;
    }
    return `<div class="hv-row" data-row="${row}">
      <span class="hv-gutter k-${rowKind || 'gap'}" style="background:var(--c-${rowKind || 'gap'})"></span>
      <span class="hv-off">${base.toString(16).padStart(this.offW, '0')}</span>
      <span class="hv-bytes">${bytes}</span>
      <span class="hv-ascii">${ascii}</span>
      <span class="hv-struct">${chips}</span>
    </div>`;
  }

  regionsInRow(a, b) {
    const out = [];
    // 分区表按起点有序，二分定位后线性扫描
    const regs = this.elf.regions;
    let lo = 0, hi = regs.length - 1, start = 0;
    while (lo <= hi) { const mid = (lo + hi) >> 1; if (regs[mid].end <= a) lo = mid + 1; else { start = mid; hi = mid - 1; } }
    for (let i = start; i < regs.length && regs[i].start < b; i++) {
      if (regs[i].start >= a) out.push(regs[i]);
    }
    return out.slice(0, 3);
  }

  regionAt(off) {
    const regs = this.elf.regions;
    let lo = 0, hi = regs.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (regs[mid].end <= off) lo = mid + 1;
      else if (regs[mid].start > off) hi = mid - 1;
      else return regs[mid];
    }
    return null;
  }

  /* 应用选择/高亮/悬停样式（只操作当前可视 DOM） */
  _paint() {
    const sel = this.selection, flash = this.flashRange, hr = this.hoverRange;
    const nodes = this.rows.querySelectorAll('.hb[data-off]');
    for (const n of nodes) {
      const o = +n.dataset.off;
      let cls = '';
      if (this.cursor === o) cls += ' cur';
      if (sel && o >= sel.start && o < sel.end) cls += ' sel';
      if (flash && o >= flash.start && o < flash.end) cls += ' flash';
      if (o === this.hover) cls += ' hov';
      else if (hr && o >= hr.start && o < hr.end) cls += ' hovrange';
      // 关键：必须无条件重写 className，否则失去状态的字节能会残留旧高亮（残影）
      n.className = 'hb k-' + n.dataset.k + cls;
    }
    const rows = this.rows.querySelectorAll('.hv-row');
    for (const rowEl of rows) {
      const r = +rowEl.dataset.row;
      const inSel = sel && (r * 16 < sel.end) && ((r + 1) * 16 > sel.start);
      const inHov = hr && (r * 16 < hr.end) && ((r + 1) * 16 > hr.start);
      rowEl.classList.toggle('in-sel', !!inSel);
      rowEl.classList.toggle('in-hov', !inSel && !!inHov);
    }
  }

  /* ---------------- 交互 ---------------- */
  _offFromEvent(e) {
    const t = e.target.closest('.hb[data-off]');
    if (t) return +t.dataset.off;
    const chip = e.target.closest('.hv-chip[data-off]');
    if (chip) return +chip.dataset.off;
    const row = e.target.closest('.hv-row');
    if (row) return +row.dataset.row * 16;
    return -1;
  }

  _onMove(e) {
    const off = this._offFromEvent(e);
    if (off === this.hover) return;
    this.hover = off;
    this._paint();
    if (this.opts.onHover) this.opts.onHover(off, e.shiftKey, e);
    if (this._dragging && off >= 0) {
      this.setSelection(Math.min(this._dragStart, off), Math.max(this._dragStart, off) + 1);
      if (this.opts.onSelect) this.opts.onSelect(this.selection, false);
    }
  }

  _onDown(e) {
    const off = this._offFromEvent(e);
    if (off < 0) return;
    this._dragging = true;
    this._dragStart = off;
    if (e.shiftKey && this.anchor !== undefined && this.anchor >= 0) {
      this.setSelection(Math.min(this.anchor, off), Math.max(this.anchor, off) + 1);
    } else {
      this.anchor = off;
      this.setSelection(off, off + 1);
      this.setCursor(off);
      this.scroll.focus({ preventScroll: true });
    }
    if (this.opts.onSelect) this.opts.onSelect(this.selection, true);
    e.preventDefault();
  }

  /* ---------------- 外部 API ---------------- */
  setSelection(a, b) { this.selection = { start: a, end: b }; this._paint(); }
  setCursor(off) { this.cursor = off; this._paint(); }
  setHover(off) { this.hover = off; this.hoverRange = null; this._paint(); }
  /** 高亮一整段字节（用于悬停字段行、枚举取值、位置区间等） */
  setHoverRange(start, end) {
    this.hover = -1;
    this.hoverRange = (end > start) ? { start: start, end: end } : null;
    this._paint();
  }
  clearHover() { this.hover = -1; this.hoverRange = null; this._paint(); }
  /** 当前可视字节数（用于分页步进） */
  pageBytes() {
    return Math.max(BYTES_PER_ROW, Math.floor(this.scroll.clientHeight / ROW_H) * BYTES_PER_ROW);
  }

  ensureVisible(off) {
    const top = Math.floor(off / BYTES_PER_ROW) * ROW_H;
    const vh = this.scroll.clientHeight;
    if (top < this.scroll.scrollTop) this.scroll.scrollTop = top;
    else if (top + ROW_H > this.scroll.scrollTop + vh) this.scroll.scrollTop = top - vh + ROW_H * 2;
  }

  jumpTo(off, size, opts) {
    opts = opts || {};
    size = size || 1;
    const top = Math.max(0, Math.floor(off / BYTES_PER_ROW) * ROW_H - Math.floor(this.scroll.clientHeight / 2 / ROW_H) * ROW_H + ROW_H);
    const smooth = opts.smooth !== false && Math.abs(top - this.scroll.scrollTop) > ROW_H * 3;
    this.scroll.scrollTo({ top, behavior: smooth ? 'smooth' : 'auto' });
    this.setSelection(off, off + size);
    this.anchor = off;
    this.setCursor(off);
    this.flash(off, size);
    this.update(true);
  }

  flash(off, size) {
    this.flashRange = { start: off, end: off + Math.max(1, size) };
    this._paint();
    clearTimeout(this._flashT);
    this._flashT = setTimeout(() => { this.flashRange = null; this._paint(); }, 1400);
  }

  _esc(s) {
    return String(s === undefined || s === null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  }
}
