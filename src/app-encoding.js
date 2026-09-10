/* ============================================================================
 * app-encoding.js — 指令编码对照面板（二进制 ↔ 助记符）
 *   · 位域色块条：按规范把一条指令切成 opcode / funct3 / rd / rs1 / imm…
 *   · 字段表：每个位区间的二进制、十六进制与含义
 *   · 结论行：这些位是怎么组合出这条助记符和操作数的
 *   用于反汇编面板、.text 段内容预览与符号表函数反汇编。
 * ==========================================================================*/
'use strict';

const RV_FIELD_COLORS = {
  opcode: '#ff6b6b', funct3: '#ffa94d', funct7: '#ffd43b', 'funct7/shamt[5]': '#ffd43b',
  rd: '#4dabf7', rs1: '#51cf66', rs2: '#22b8cf', rs3: '#20c997', 'rd/rs1': '#4dabf7',
  'rd′': '#4dabf7', 'rs1′': '#51cf66', 'rs2′': '#22b8cf',
  csr: '#cc5de8', imm: '#b197fc', rm: '#f783ac', fmt: '#f783ac', aq: '#ffe066', rl: '#ffe066',
  pred: '#94d82d', succ: '#94d82d', fm: '#94d82d', funct4: '#ffa94d', funct5: '#ffa94d',
  funct12: '#ffa94d', op: '#ff6b6b'
};

function fieldColor(name) {
  if (RV_FIELD_COLORS[name]) return RV_FIELD_COLORS[name];
  for (const k of Object.keys(RV_FIELD_COLORS)) if (name.indexOf(k) === 0) return RV_FIELD_COLORS[k];
  return '#8d9bb0';
}

/**
 * 渲染一条指令的「二进制 ↔ 助记符」对照块
 * @param {object} elf
 * @param {object} insn 反汇编结果（需要 addr / bytes / text）
 */
function insnEncodingBlock(elf, insn) {
  const bytes = insn.bytes || new Uint8Array(0);
  if (elf.arch !== 'riscv') {
    return '<div class="ie"><div class="ie-head">当前架构（' + esc(elf.arch) +
      '）暂未提供位域拆解，仅显示机器码与助记符。</div>' +
      '<div class="ie-line"><code>' + Array.prototype.slice.call(bytes).map(byteHex).join(' ') + '</code>' +
      '<span class="ie-text">' + esc(insn.text) + '</span></div></div>';
  }
  let word = 0;
  for (let i = 0; i < bytes.length; i++) word |= bytes[i] << (8 * i);
  word = word >>> 0;
  const info = riscvInsnFields(word, elf.is64, {});
  const total = info.bits;
  // 位域色块条：从高位到低位排列
  const strips = info.fields.slice().sort(function (a, b) { return b.hi - a.hi; }).map(function (f) {
    const c = fieldColor(f.name);
    return '<span class="ie-f" style="flex:' + f.width + ';--fc:' + c + '" title="' +
      esc(f.name + '  [' + f.hi + ':' + f.lo + ']  = ' + f.bin + '  ' + f.meaning) + '">' +
      '<i>' + esc(f.name) + '</i><b class="mono">' + f.bin + '</b></span>';
  }).join('');
  const rows = info.fields.slice().sort(function (a, b) { return b.hi - a.hi; }).map(function (f) {
    const c = fieldColor(f.name);
    return '<tr><td class="mono ie-fname" style="color:' + c + '">' + esc(f.name) + '</td>' +
      '<td class="mono">' + f.hi + ':' + f.lo + '</td>' +
      '<td class="mono">' + f.width + '</td>' +
      '<td class="mono ie-bin">' + f.bin + '</td>' +
      '<td class="mono">' + esc(f.hex) + '</td>' +
      '<td class="ie-mean">' + esc(f.meaning) + '</td></tr>';
  }).join('');
  const byteTxt = Array.prototype.slice.call(bytes).map(byteHex).join(' ');
  const leTxt = Array.prototype.slice.call(bytes).reverse().map(byteHex).join(' ');
  return '<div class="ie">' +
    '<div class="ie-head">' +
    '<span class="pill" style="border-color:' + fieldColor('opcode') + ';color:' + fieldColor('opcode') + '">' + esc(info.format) + '</span>' +
    '<code class="ie-word">' + hex(info.word, total / 4) + '</code>' +
    '<span class="muted">文件中的字节（' + (elf.le ? '小端' : '大端') + '）</span>' +
    '<code>' + byteTxt + '</code>' +
    '<span class="muted">重排为高位在前</span><code>' + leTxt + '</code>' +
    '<span class="ie-text">' + esc(insn.text) + '</span>' +
    '</div>' +
    '<div class="ie-strip">' + strips + '</div>' +
    '<div class="ie-bitnum"><span>' + (total - 1) + '</span><span>位</span><span>0</span></div>' +
    '<table class="grid compact ie-table"><thead><tr><th>字段</th><th>位区间</th><th>宽度</th>' +
    '<th>二进制</th><th>十六进制</th><th>该字段如何影响助记符</th></tr></thead><tbody>' + rows + '</tbody></table>' +
    '<div class="ie-note">助记符 <b>' + esc(insn.text.split(' ')[0]) + '</b> 由 opcode（决定指令大类）与 funct3/funct7（决定具体运算）共同确定，' +
    '操作数则来自 rd / rs1 / rs2 / imm 这些位域。</div>' +
    '</div>';
}

/** 反汇编视图中「展开编码」的按钮 */
function encodingToggleHTML(addr) {
  return '<button class="mini enc-toggle" data-enc="' + addr + '" title="展开该指令的位域拆解（二进制 ↔ 助记符）">位域</button>';
}
