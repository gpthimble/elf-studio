/* ============================================================================
 * disasm-dispatch.js — 按架构分派到具体反汇编引擎
 * 与界面无关，浏览器与测试环境（Deno）都能直接调用。
 * ==========================================================================*/
'use strict';

/**
 * @param {object} elf
 * @param {object} sec  代码所在段（用于算文件偏移与段范围）
 * @param {Uint8Array} code 机器码
 * @param {number} vaddr 机器码起始虚拟地址
 * @param {object} opts { aliases, forceC } 两个可选开关，缺省时用常用默认值
 */
function disassemble(elf, sec, code, vaddr, opts) {
  opts = opts || {};
  const aliases = opts.aliases !== undefined ? opts.aliases : true;
  const forceC = opts.forceC || 'auto';
  const symMap = new Map();
  elf.symbols.forEach(function (s) { if (s.st_value && s.st_shndx !== 0) symMap.set(s.st_value, s); });
  const fileBase = sec.sh_offset + (vaddr - sec.sh_addr);
  if (elf.arch === 'riscv') {
    let hasRVC = (elf.ehdr.e_flags & 1) === 1;
    if (!hasRVC && elf.riscvAttrs) {
      hasRVC = elf.riscvAttrs.tags.some(function (t) {
        return t.tag === 5 && typeof t.value === 'string' && /(^|_)c\d/.test(t.value);
      });
    }
    return riscvDisassemble(code, vaddr, {
      bits: elf.is64 ? 64 : 32,
      symbols: symMap,
      aliases: aliases,
      forceC: forceC === 'auto' ? (hasRVC ? 'auto' : 'off') : forceC,
      hasRVC: hasRVC || forceC === 'on',
      fileBase: fileBase,
      sectionRanges: elf.shdrs.filter(function (s) { return s.sh_flags & 0x2; })
        .map(function (s) { return { name: s.name, start: s.sh_addr, end: s.sh_addr + s.sh_size }; })
    });
  }
  if (elf.arch === 'x86-64' || elf.arch === 'x86') {
    return x86Disassemble(code, vaddr, {
      bits: elf.arch === 'x86-64' ? 64 : 32, symbols: symMap, fileBase: fileBase
    });
  }
  return [{
    addr: vaddr, fileOffset: fileBase, size: code.length,
    text: '/* 暂不支持 ' + elf.arch + ' 的指令解码，此段共 ' + code.length + ' 字节 */',
    illegal: '架构未支持'
  }];
}

function renderDisasm() {
  const elf = S.elf;
  const pane = $('#pane-disasm');
  if (!elf.valid) { pane.innerHTML = ''; return; }
  const secs = executableSections(elf);
  if (!secs.length) {
    pane.innerHTML = '<div class="card"><b>没有找到可执行段</b><p class="muted">' +
      '反汇编需要一个带 SHF_EXECINSTR 标志的段（通常是 .text）。该文件里没有这样的段，' +
      '可能是纯数据目标文件或包含了调试信息但被 strip 掉了。</p></div>';
    return;
  }
  if (!S.disasm.sec || !secs.some(function (s) { return s.name === S.disasm.sec; })) {
    const prefer = secs.find(function (s) { return s.name === '.text'; }) || secs[0];
    S.disasm.sec = prefer.name;
    S.disasm.start = prefer.sh_addr;
  }
  const sec = secs.find(function (s) { return s.name === S.disasm.sec; });
  const bits = elf.is64 ? 64 : 32;
  const code = sectionBytes(elf, sec);
  if (!code.length) {
    pane.innerHTML = '<div class="card muted">该段在文件中没有字节。</div>';
    return;
  }
  const startVA = Math.max(sec.sh_addr, Math.min(S.disasm.start || sec.sh_addr, sec.sh_addr + sec.sh_size - 1));
  const skip = startVA - sec.sh_addr;
  const insns = disassemble(elf, sec, code.subarray(skip), startVA);
  S.disasm.byAddr = new Map(insns.map(function (i) { return [i.addr, i]; }));
  const shown = insns.slice(0, S.disasm.limit);

  const lines = shown.map(function (ins) {
    const raw = Array.prototype.slice.call(ins.bytes || []).map(byteHex).join(' ');
    const cls = ['dis-line'];
    if (ins.symbol) cls.push('is-sym');
    if (ins.illegal) cls.push('illegal');
    if (ins.warn) cls.push('warnline');
    if (ins.isReturn || ins.isJump) cls.push('is-jump');
    let comment = '';
    if (ins.symbol) comment += '<span class="tag sym">⟶ ' + esc(ins.symbol) + ':</span> ';
    if (ins.targetSymbol) comment += '<span class="tag target">' + esc(ins.targetSymbol) + '</span>';
    else if (ins.targetSection) comment += '<span class="tag muted">→ ' + esc(ins.targetSection) + '</span>';
    if (ins.resolvedSymbol) comment += '<span class="tag resolved"># ' + hx(ins.resolvedAddress) + ' &lt;' + esc(ins.resolvedSymbol) + '&gt;</span>';
    if (ins.note) comment += '<span class="tag wa">' + esc(ins.note) + '</span>';
    if (ins.illegal && !ins.tail) comment += '<span class="tag err">' + esc(ins.illegal) + '</span>';
    return '<div class="' + cls.join(' ') + '" data-addr="' + ins.addr + '" data-off="' + ins.fileOffset +
      '" data-size="' + (ins.size || 1) + '">' +
      '<span class="d-addr">' + hx(ins.addr, elf.is64 ? 8 : 6) + '</span>' +
      '<span class="d-bytes">' + (S.disasm.showBytes ? raw : '') + '</span>' +
      '<span class="d-text">' + esc(ins.text) + '</span>' +
      '<span class="d-comment">' + comment +
      (ins.tail || ins.illegal ? '' : encodingToggleHTML(ins.addr)) + '</span></div>' +
      '<div class="dis-enc" data-enc-for="' + ins.addr + '" hidden></div>';
  }).join('') || '<div class="muted">该地址范围内没有可用指令。</div>';

  const total = insns.length;
  const compressed = insns.filter(function (i) { return i.size === 2; }).length;
  const illegal = insns.filter(function (i) { return i.illegal && !i.tail; }).length;
  const funcs = elf.symbols.filter(function (s) {
    return s.type === 2 && s.st_shndx !== 0 &&
      (s.st_shndx === sec.index || (s.st_value >= sec.sh_addr && s.st_value < sec.sh_addr + sec.sh_size));
  }).sort(function (a, b) { return a.st_value - b.st_value; });

  const secSel = '<select id="dis-sec">' + secs.map(function (s) {
    return '<option value="' + esc(s.name) + '"' + (s.name === sec.name ? ' selected' : '') + '>' +
      esc(s.name) + '  (' + fmtComma(s.sh_size) + ' B)</option>';
  }).join('') + '</select>';

  const funcSel = funcs.length ? '<select id="dis-func"><option value="">跳转到函数…</option>' +
    funcs.map(function (f) {
      return '<option value="' + f.st_value + '">' + esc(f.name) + '  @ ' + hx(f.st_value) + '</option>';
    }).join('') + '</select>' : '';

  const cSel = elf.arch === 'riscv' ? '<label class="chk">压缩指令 C<select id="dis-c">' +
    '<option value="auto"' + (S.disasm.forceC === 'auto' ? ' selected' : '') + '>自动（依 e_flags / 属性段）</option>' +
    '<option value="on"' + (S.disasm.forceC === 'on' ? ' selected' : '') + '>强制开启</option>' +
    '<option value="off"' + (S.disasm.forceC === 'off' ? ' selected' : '') + '>关闭（按 16 位数据）</option>' +
    '</select></label>' : '';

  pane.innerHTML = '<div class="card"><div class="card-h"><b>反汇编</b>' + secSel + funcSel +
    '<label class="chk"><input type="checkbox" id="dis-bytes"' + (S.disasm.showBytes ? ' checked' : '') + '>显示机器码</label>' +
    '<label class="chk"><input type="checkbox" id="dis-alias"' + (S.disasm.aliases ? ' checked' : '') + '>伪指令别名</label>' +
    cSel + '</div>' +
    '<div class="dis-meta muted small">段 <b>' + esc(sec.name) + '</b> · 虚拟地址 ' + hx(sec.sh_addr, elf.is64 ? 10 : 6) +
    ' · 文件偏移 ' + hx(sec.sh_offset) + ' · ' + fmtComma(sec.sh_size) + ' 字节 · 解析出 ' + fmtComma(total) + ' 条指令' +
    (elf.arch === 'riscv' ? '（16 位压缩指令 ' + fmtComma(compressed) + ' 条' + (illegal ? '，未识别 ' + illegal + ' 条' : '') + '）' : '') +
    (elf.arch === 'riscv' ? '' : '<br>⚠ 当前架构 ' + esc(elf.arch) + ' 使用简化解码器，覆盖常见指令；未覆盖的编码会以 .byte 原样列出，长度仍然准确。') +
    '<button class="mini" id="dis-scroll">从文件偏移 ' + hx(sec.sh_offset + skip) + ' 开始看 Hex</button></div>' +
    '<div class="dis-wrap"><div class="dis-lines">' + lines + '</div>' +
    (insns.length > shown.length ? '<button class="more" id="dis-more">继续加载剩余 ' + fmtComma(insns.length - shown.length) + ' 条指令</button>' : '') +
    '</div></div>';

  $('#dis-sec').addEventListener('change', function (e) {
    const s = secs.find(function (x) { return x.name === e.target.value; });
    S.disasm.sec = s.name; S.disasm.start = s.sh_addr; S.disasm.limit = 400; renderDisasm();
  });
  if ($('#dis-func')) $('#dis-func').addEventListener('change', function (e) {
    if (e.target.value) openDisasmAt(+e.target.value);
  });
  $('#dis-bytes').addEventListener('change', function (e) { S.disasm.showBytes = e.target.checked; renderDisasm(); });
  $('#dis-alias').addEventListener('change', function (e) { S.disasm.aliases = e.target.checked; renderDisasm(); });
  if ($('#dis-c')) $('#dis-c').addEventListener('change', function (e) { S.disasm.forceC = e.target.value; renderDisasm(); });
  if ($('#dis-more')) $('#dis-more').addEventListener('click', function () { S.disasm.limit += 2000; renderDisasm(); });
  $('#dis-scroll').addEventListener('click', function () {
    selectBytes(sec.sh_offset + skip, Math.min(64, code.length - skip), { smooth: true });
  });

  $$('.dis-line', pane).forEach(function (el) {
    el.addEventListener('mouseenter', function () {
      if (S.pinned === null) updateInspector(+el.dataset.off, +el.dataset.size);
      hoverRange(+el.dataset.off, +el.dataset.size);
    });
    el.addEventListener('mouseleave', clearHover);
    el.addEventListener('click', function (e) {
      const encBtn = e.target.closest('.enc-toggle');
      if (encBtn) {                                   // 展开 / 收起位域拆解
        const addr = +encBtn.dataset.enc;
        const box = $('.dis-enc[data-enc-for="' + addr + '"]', pane);
        const insn = S.disasm.byAddr ? S.disasm.byAddr.get(addr) : null;
        if (box && insn) {
          if (box.hidden) { box.innerHTML = insnEncodingBlock(elf, insn); box.hidden = false; }
          else box.hidden = true;
        }
        return;
      }
      selectBytes(+el.dataset.off, +el.dataset.size);      // 左侧 Hex 滚动 + 框选 + 闪烁 + 固定探针
      markDisasmSelected(el);
      const sym = elf.symByAddr.get(+el.dataset.addr);
      setStatus('已选中指令 ' + el.querySelector('.d-text').textContent.trim() +
        '：文件偏移 ' + hx(+el.dataset.off) + '，' + el.dataset.size + ' 字节' +
        '（Hex 已同步高亮）' +
        (sym ? '；该地址是符号 ' + sym.name + ' 的入口（' + stTypeName(sym.type) + '，大小 ' + fmtComma(sym.st_size) + ' 字节）' : ''));
    });
  });
  markDisasmLineForAddress(startVA);
}

/** 反汇编视图跳转到某个虚拟地址（函数入口） */
