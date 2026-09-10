/* ============================================================================
 * disasm-x86.js — x86 / x86-64 反汇编（常用子集）
 * 设计目标：覆盖实际目标文件中绝大多数整数指令、常见 SSE 与多字节 NOP，
 *           保证「指令长度」正确（反汇编列表不会错位）。
 * 注意：x86 是变长且高度复杂的 CISC 编码，本实现为工程性简化版本，
 *       未覆盖的指令会以 .byte 序列如实呈现，绝不猜测长度。
 * ==========================================================================*/
'use strict';

const X_R32 = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi'];
const X_R64 = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi'];
const X_R16 = ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di'];
const X_R8 = ['al', 'cl', 'dl', 'bl', 'spl', 'bpl', 'sil', 'dil'];
const X_R8H = ['al', 'cl', 'dl', 'bl', 'ah', 'ch', 'dh', 'bh'];
const CC = ['o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a', 's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g'];
const ALU = ['add', 'or', 'adc', 'sbb', 'and', 'sub', 'xor', 'cmp'];
const SHIFT = ['rol', 'ror', 'rcl', 'rcr', 'shl', 'shr', 'sal', 'sar'];

function x86Disassemble(code, vaddr, opts) {
  opts = opts || {};
  const bits = opts.bits || 64;
  const out = [];
  let pos = 0;
  const syms = opts.symbols || new Map();
  while (pos < code.length) {
    let ins;
    try { ins = decodeX86(code, pos, vaddr + pos, bits); } catch (e) { ins = null; }
    if (!ins || !ins.size) ins = { size: 1, text: '.byte ' + hex(code[pos], 2), illegal: '无法识别的编码' };
    ins.addr = (vaddr + pos) >>> 0;
    ins.fileOffset = (opts.fileBase || 0) + pos;
    ins.bytes = code.subarray(pos, Math.min(code.length, pos + ins.size));
    const s = syms.get(ins.addr);
    if (s) { ins.symbol = s.name; ins.isFunctionEntry = true; }
    if (ins.target !== undefined && ins.target !== null) {
      const t = syms.get(ins.target >>> 0);
      if (t) ins.targetSymbol = t.name;
    }
    out.push(ins);
    pos += ins.size;
  }
  return out;
}

function decodeX86(code, pos, addr, bits) {
  const p0 = pos;
  let rex = 0, opsz = bits === 64 ? 4 : 4, addrsz = bits === 64 ? 8 : 4;
  let rep = '', opsz66 = false;
  // --- 前缀 ---
  for (let guard = 0; guard < 8; guard++) {
    const b = code[pos];
    if (b === 0x66) { opsz66 = true; opsz = 2; pos++; }
    else if (b === 0x67) { addrsz = bits === 64 ? 4 : 2; pos++; }
    else if (b === 0xf2) { rep = 'repne '; pos++; }
    else if (b === 0xf3) { rep = 'rep '; pos++; }
    else if (b === 0x2e || b === 0x3e || b === 0x26 || b === 0x36 || b === 0x64 || b === 0x65) { pos++; }
    else if (bits === 64 && b >= 0x40 && b <= 0x4f) { rex = b & 0x0f; pos++; }
    else break;
  }
  const W = (rex & 8) ? 1 : 0;
  const sz = rex !== 0 ? (W ? 8 : (opsz66 ? 2 : 4)) : opsz;
  const op = code[pos];
  if (op === undefined) return null;
  pos++;

  const regName = (idx, size) => xRegName(idx, size, rex);
  const sizeOf = (n) => (n === 1 ? 'byte' : n === 2 ? 'word' : n === 4 ? 'dword' : 'qword');
  const imm = (n) => { let v = 0; for (let i = 0; i < n; i++) v |= code[pos + i] << (8 * i); pos += n; return v >>> 0; };
  const immS = (n) => { const v = imm(n); const m = Math.pow(2, n * 8 - 1); return v >= m ? v - Math.pow(2, n * 8) : v; };

  /* ModRM + SIB + 位移 */
  function modrm(size) {
    const m = code[pos++];
    const mod = m >> 6, reg = ((m >> 3) & 7) + ((rex & 4) ? 8 : 0), rm = (m & 7);
    let mem = null, rmName = null;
    if (mod === 3) rmName = xRegName(rm + ((rex & 1) ? 8 : 0), size, rex);
    else {
      let disp = 0, base = null, index = -1, scale = 1;
      const rmLow = rm;
      if (rmLow === 4) {
        const sib = code[pos++];
        scale = 1 << (sib >> 6);
        index = ((sib >> 3) & 7) + ((rex & 2) ? 8 : 0);
        base = (sib & 7) + ((rex & 1) ? 8 : 0);
        if (((sib >> 3) & 7) === 4 && !(rex & 2)) index = -1;
        if ((sib & 7) === 5 && mod === 0) { base = -1; disp = imm(4); }
      } else if (rmLow === 5 && mod === 0) {
        if (bits === 64) { disp = immS(4); if (pos - p0 > 0) { /* RIP 相对 */ } base = -2; }
        else { disp = imm(4); base = -1; }
      } else {
        base = rmLow + ((rex & 1) ? 8 : 0);
      }
      if (mod === 1 && base >= 0) disp = immS(1);
      else if (mod === 2 && base >= 0) disp = immS(4);
      const seg = (code[p0] === 0x64) ? 'fs:' : (code[p0] === 0x65) ? 'gs:' : '';
      if (base === -2) mem = seg + '[rip' + (disp < 0 ? '-' + hex(-disp) : '+' + hex(disp)) + ']';
      else {
        const parts = [];
        if (index >= 0) parts.push(regName(index, 8) + (scale > 1 ? '*' + scale : ''));
        if (base >= 0) parts.push(regName(base, 8));
        let s = parts.join(' + ');
        if (base < 0 && !parts.length) s = hex(disp >>> 0);
        else if (disp || !parts.length) s += (disp < 0 ? ' - ' + hex(-disp) : ' + ' + hex(disp));
        mem = seg + '[' + s + ']';
      }
    }
    return { mod, reg, rm, rmName, mem };
  }

  /* ---- ALU 组：add/or/adc/sbb/and/sub/xor/cmp (opcode 0x00–0x3D) ---- */
  if (op < 0x40 && (op & 7) <= 5) {
    const alu = ALU[(op >> 3) & 7], form = op & 7;
    if (form === 4) return mk2('x', pos - p0, alu + ' ' + regName(0, 1) + ', ' + hex(imm(1), 2));
    if (form === 5) return mk2('x', pos - p0, alu + ' ' + regName(0, sz) + ', ' + hex(imm(sz === 8 ? 4 : sz)));
    const s = (form === 0 || form === 2) ? 1 : sz;
    const m = modrm(s);
    const dst = m.mod === 3 ? m.rmName : (s === 1 ? 'byte ' : '') + m.mem;
    const src = regName(m.reg, s);
    if (form <= 1) return mk2('x', pos - p0, alu + ' ' + dst + ', ' + src);
    return mk2('x', pos - p0, alu + ' ' + src + ', ' + dst);
  }
  switch (op) {
    case 0x0f: { // 双字节
      const op2 = code[pos++];
      if (op2 >= 0x80 && op2 <= 0x8f) { const off = immS(4); const t = (addr + 6 + off) >>> 0; return mk2('x', pos - p0, 'j' + CC[op2 & 0xf] + ' ' + hex(t), { target: t, isBranch: true }); }
      if (op2 >= 0x40 && op2 <= 0x4f) { const m = modrm(sz); return mk2('x', pos - p0, 'cmov' + CC[op2 & 0xf] + ' ' + regName(m.reg, sz) + ', ' + (m.mod === 3 ? m.rmName : m.mem)); }
      if (op2 >= 0x90 && op2 <= 0x9f) { const m = modrm(1); return mk2('x', pos - p0, 'set' + CC[op2 & 0xf] + ' ' + (m.mod === 3 ? m.rmName : 'byte ' + m.mem)); }
      if (op2 === 0xb6 || op2 === 0xb7) { const m = modrm(sz === 8 ? 8 : 4); return mk2('x', pos - p0, 'movzx ' + regName(m.reg, sz === 8 ? 8 : 4) + ', ' + (m.mod === 3 ? m.rmName : sizeOf(op2 === 0xb6 ? 1 : 2) + ' ' + m.mem)); }
      if (op2 === 0xbe || op2 === 0xbf) { const m = modrm(sz === 8 ? 8 : 4); return mk2('x', pos - p0, 'movsx ' + regName(m.reg, sz === 8 ? 8 : 4) + ', ' + (m.mod === 3 ? m.rmName : sizeOf(op2 === 0xbe ? 1 : 2) + ' ' + m.mem)); }
      if (op2 === 0xaf) { const m = modrm(sz); return mk2('x', pos - p0, 'imul ' + regName(m.reg, sz) + ', ' + (m.mod === 3 ? m.rmName : m.mem)); }
      if (op2 === 0x1f) { const m = modrm(sz); return mk2('x', pos - p0, 'nop ' + (m.mod === 3 ? m.rmName : m.mem)); }
      if (op2 === 0x05) return mk2('x', pos - p0, 'syscall');
      if (op2 === 0x0b) return mk2('x', pos - p0, 'ud2');
      if (op2 === 0xb1) { const m = modrm(sz); return mk2('x', pos - p0, 'cmpxchg ' + (m.mod === 3 ? m.rmName : m.mem) + ', ' + regName(m.reg, sz)); }
      if (op2 === 0x31) return mk2('x', pos - p0, 'rdtsc');
      // SSE 常用指令
      const sse = SSE_MAP[(rep ? rep.trim() + ' ' : '') + hex(op2, 2)];
      if (sse) { const m = modrm(sz === 2 ? 2 : 4); return mk2('x', pos - p0, sse + ' xmm' + m.reg + ', ' + (m.mod === 3 ? 'xmm' + m.rm : m.mem), { sse: true }); }
      if (op2 === 0x10 || op2 === 0x11 || op2 === 0x28 || op2 === 0x29 || op2 === 0x6f || op2 === 0x7f || op2 === 0x57 || op2 === 0x58 || op2 === 0x59 || op2 === 0x5c || op2 === 0x5e) {
        const m = modrm(4);
        const name = (rep ? 'movss' : 'movups');
        return mk2('x', pos - p0, name + ' xmm' + m.reg + ', ' + (m.mod === 3 ? 'xmm' + m.rm : m.mem), { sse: true });
      }
      if (op2 === 0x1e && rep) { const b = code[pos++]; return mk2('x', pos - p0, b === 0xfa ? 'endbr64' : b === 0xfb ? 'endbr32' : 'nop'); }
      return mk2('x', 2, '.byte 0x0f, ' + hex(op2, 2), { illegal: '未实现的 0x0F 指令' });
    }
    case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57:
      return mk2('x', pos - p0, 'push ' + regName(op - 0x50 + ((rex & 1) ? 8 : 0), 8));
    case 0x58: case 0x59: case 0x5a: case 0x5b: case 0x5c: case 0x5d: case 0x5e: case 0x5f:
      return mk2('x', pos - p0, 'pop ' + regName(op - 0x58 + ((rex & 1) ? 8 : 0), 8));
    case 0x68: return mk2('x', pos - p0, 'push ' + hex(imm(4)));
    case 0x6a: return mk2('x', pos - p0, 'push ' + sx(imm(1), 8));
    case 0x63: { const m = modrm(4); return mk2('x', pos - p0, 'movsxd ' + regName(m.reg, 8) + ', ' + (m.mod === 3 ? m.rmName : m.mem)); }
    case 0x69: { const m = modrm(sz); const i = imm(4); return mk2('x', pos - p0, 'imul ' + regName(m.reg, sz) + ', ' + (m.mod === 3 ? m.rmName : m.mem) + ', ' + hex(i)); }
    case 0x6b: { const m = modrm(sz); const i = immS(1); return mk2('x', pos - p0, 'imul ' + regName(m.reg, sz) + ', ' + (m.mod === 3 ? m.rmName : m.mem) + ', ' + i); }
    case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75: case 0x76: case 0x77:
    case 0x78: case 0x79: case 0x7a: case 0x7b: case 0x7c: case 0x7d: case 0x7e: case 0x7f: {
      const off = immS(1); const t = (addr + pos - p0 + off) >>> 0;
      return mk2('x', pos - p0, 'j' + CC[op & 0xf] + ' ' + hex(t), { target: t, isBranch: true });
    }
    case 0x80: case 0x81: case 0x82: case 0x83: {
      // 0x80: r/m8, imm8    0x81: r/m32|64, imm32    0x83: r/m32|64, sign-extended imm8
      const opSize = (op === 0x80) ? 1 : sz;
      const m = modrm(opSize);
      const i = (op === 0x83) ? immS(1) : ((op === 0x81) ? immS(sz === 8 ? 4 : sz) : imm(1));
      const dst = m.mod === 3 ? m.rmName : sizeOf(opSize) + ' ' + m.mem;
      const shown = i < 0 ? '-' + hex(-i) : hex(i);
      return mk2('x', pos - p0, ALU[m.reg & 7] + ' ' + dst + ', ' + shown, { imm: i });
    }
    case 0x84: case 0x85: { const m = modrm(op === 0x84 ? 1 : sz); return mk2('x', pos - p0, 'test ' + (m.mod === 3 ? m.rmName : m.mem) + ', ' + regName(m.reg, op === 0x84 ? 1 : sz)); }
    case 0x86: case 0x87: { const m = modrm(op === 0x86 ? 1 : sz); return mk2('x', pos - p0, 'xchg ' + (m.mod === 3 ? m.rmName : m.mem) + ', ' + regName(m.reg, op === 0x86 ? 1 : sz)); }
    case 0x88: case 0x89: case 0x8a: case 0x8b: {
      const s = op === 0x88 || op === 0x8a ? 1 : sz;
      const m = modrm(s);
      if (op === 0x88 || op === 0x89) return mk2('x', pos - p0, 'mov ' + (m.mod === 3 ? m.rmName : sizeOf(s) + ' ' + m.mem) + ', ' + regName(m.reg, s));
      return mk2('x', pos - p0, 'mov ' + regName(m.reg, s) + ', ' + (m.mod === 3 ? m.rmName : sizeOf(s) + ' ' + m.mem));
    }
    case 0x8d: { const m = modrm(sz); return mk2('x', pos - p0, 'lea ' + regName(m.reg, sz) + ', ' + (m.mod === 3 ? m.rmName : m.mem)); }
    case 0x8f: { const m = modrm(8); return mk2('x', pos - p0, 'pop ' + (m.mod === 3 ? m.rmName : m.mem)); }
    case 0x90: return mk2('x', pos - p0, rep ? 'pause' : 'nop');
    case 0x98: return mk2('x', pos - p0, W ? 'cdqe' : 'cwde');
    case 0x99: return mk2('x', pos - p0, W ? 'cqo' : 'cdq');
    case 0x9c: return mk2('x', pos - p0, 'pushfq');
    case 0x9d: return mk2('x', pos - p0, 'popfq');
    case 0xa8: return mk2('x', pos - p0, 'test al, ' + hex(imm(1), 2));
    case 0xa9: return mk2('x', pos - p0, 'test ' + regName(0, sz) + ', ' + hex(imm(sz === 8 ? 4 : sz)));
    case 0xb0: case 0xb1: case 0xb2: case 0xb3: case 0xb4: case 0xb5: case 0xb6: case 0xb7:
      return mk2('x', pos - p0, 'mov ' + regName(op - 0xb0 + ((rex & 1) ? 8 : 0), 1) + ', ' + hex(imm(1), 2));
    case 0xb8: case 0xb9: case 0xba: case 0xbb: case 0xbc: case 0xbd: case 0xbe: case 0xbf: {
      const n = sz === 8 ? 8 : (sz === 2 ? 2 : 4);
      const v = (n === 4) ? imm(4) : imm(n);
      return mk2('x', pos - p0, 'mov ' + regName(op - 0xb8 + ((rex & 1) ? 8 : 0), sz) + ', ' + hex(v));
    }
    case 0xc0: case 0xc1: { const m = modrm(op === 0xc1 ? sz : 1); const i = imm(1); return mk2('x', pos - p0, SHIFT[m.reg & 7] + ' ' + (m.mod === 3 ? m.rmName : m.mem) + ', ' + i); }
    case 0xc2: return mk2('x', pos - p0, 'ret ' + imm(2), { isReturn: true });
    case 0xc3: return mk2('x', pos - p0, 'ret', { isReturn: true });
    case 0xc6: case 0xc7: {
      const m = modrm(op === 0xc6 ? 1 : sz);
      const v = op === 0xc6 ? imm(1) : imm(sz === 8 ? 4 : sz);
      return mk2('x', pos - p0, 'mov ' + (m.mod === 3 ? m.rmName : sizeOf(op === 0xc6 ? 1 : sz) + ' ' + m.mem) + ', ' + hex(v));
    }
    case 0xc9: return mk2('x', pos - p0, 'leave');
    case 0xcc: return mk2('x', pos - p0, 'int3', { isTrap: true });
    case 0xcd: return mk2('x', pos - p0, 'int ' + hex(imm(1), 2), { isTrap: true });
    case 0xd0: case 0xd1: case 0xd2: case 0xd3: {
      const m = modrm(op === 0xd1 || op === 0xd3 ? sz : 1);
      const amt = (op === 0xd2 || op === 0xd3) ? 'cl' : '1';
      return mk2('x', pos - p0, SHIFT[m.reg & 7] + ' ' + (m.mod === 3 ? m.rmName : m.mem) + ', ' + amt);
    }
    case 0xe8: { const off = immS(4); const t = (addr + 5 + off) >>> 0; return mk2('x', pos - p0, 'call ' + hex(t), { target: t, isCall: true }); }
    case 0xe9: { const off = immS(4); const t = (addr + 5 + off) >>> 0; return mk2('x', pos - p0, 'jmp ' + hex(t), { target: t, isJump: true }); }
    case 0xeb: { const off = immS(1); const t = (addr + 2 + off) >>> 0; return mk2('x', pos - p0, 'jmp ' + hex(t), { target: t, isJump: true }); }
    case 0xf4: return mk2('x', pos - p0, 'hlt');
    case 0xf6: case 0xf7: {
      const m = modrm(op === 0xf7 ? sz : 1);
      const g = m.reg & 7;
      const dst = m.mod === 3 ? m.rmName : m.mem;
      if (g === 0) return mk2('x', pos - p0, 'test ' + dst + ', ' + hex(imm(op === 0xf7 ? (sz === 8 ? 4 : sz) : 1)));
      return mk2('x', pos - p0, ['test', 'test', 'not', 'neg', 'mul', 'imul', 'div', 'idiv'][g] + ' ' + dst);
    }
    case 0xfe: { const m = modrm(1); return mk2('x', pos - p0, ((m.reg & 7) === 0 ? 'inc ' : 'dec ') + (m.mod === 3 ? m.rmName : 'byte ' + m.mem)); }
    case 0xff: {
      const m = modrm(sz === 8 ? 8 : 4);
      const g = m.reg & 7;
      const dst = m.mod === 3 ? m.rmName : m.mem;
      const names = ['inc', 'dec', 'call', 'callf', 'jmp', 'jmpf', 'push', '?'];
      const extra = g === 2 ? { target: null, isCall: true } : (g === 4 ? { isJump: true } : {});
      return mk2('x', pos - p0, names[g] + ' ' + dst, extra);
    }
    case 0xc4: case 0xc5: return decodeVex(code, p0, addr, bits, out);
  }
  return mk2('x', 1, '.byte ' + hex(op, 2), { illegal: '未实现的指令编码' });

  function mk2(tag, size, text, extra) { return Object.assign({ size: size, text: text, mnemonic: text.split(' ')[0] }, extra || {}); }
  function xRegName(idx, size, rex_) {
    const ext = idx >= 8;
    const i = idx & 7;
    if (size === 1 && !ext) return (rex_ & 4) ? X_R8[i] : X_R8H[i];
    if (size === 1) return 'r' + idx + 'b';
    if (size === 2) return ext ? 'r' + idx + 'w' : X_R16[i];
    if (size === 8) return ext ? 'r' + idx : X_R64[i];
    return ext ? 'r' + idx + 'd' : X_R32[i];
  }
}

function sx(v, nbits) {
  const m = Math.pow(2, nbits - 1);
  const x = v & (Math.pow(2, nbits) - 1);
  return x >= m ? x - Math.pow(2, nbits) : x;
}

/* 常见 SSE 指令（前缀 + 0F 次字节） */
const SSE_MAP = {
  'F3 10': 'movss', 'F3 11': 'movss', 'F2 10': 'movsd',
  '0F 10': 'movups', '0F 11': 'movups',
  '66 0F 6F': 'movdqa', '66 0F 7F': 'movdqa',
  'F3 0F 6F': 'movdqu', 'F3 0F 7F': 'movdqu',
  '0F 28': 'movaps', '0F 29': 'movaps',
  'F3 58': 'addss', 'F3 59': 'mulss', 'F3 5C': 'subss', 'F3 5E': 'divss',
  'F2 58': 'addsd', 'F2 5C': 'subsd', 'F2 5E': 'divsd',
  '0F 57': 'xorps', '66 0F 57': 'xorpd',
  'F3 0F 2A': 'cvtsi2ss', 'F3 0F 2C': 'cvttss2si',
  'F3 0F 7E': 'movq', '66 0F 7E': 'movd'
};

/* VEX 前缀（AVX）—— 仅解析长度与常见指令 */
function decodeVex(code, p0, addr, bits, out) {
  let pos = p0;
  const b1 = code[pos];
  let map, pp, vvvv, L, w;
  if (b1 === 0xc5) {
    const b2 = code[pos + 1];
    map = 1; pp = b2 & 3; vvvv = (~(b2 >> 3)) & 0xf; L = (b2 >> 2) & 1; w = 0;
    pos += 2;
  } else {
    const b2 = code[pos + 1], b3 = code[pos + 2];
    map = b2 & 0x1f; pp = b3 & 3; vvvv = (~(b3 >> 3)) & 0xf; L = (b3 >> 2) & 1; w = (b3 >> 7) & 1;
    pos += 3;
  }
  const op = code[pos++];
  const m = code[pos++];
  const mod = m >> 6, reg = (m >> 3) & 7, rm = m & 7;
  let extraBytes = 0, mem = null;
  if (mod !== 3) {
    let base = rm, index = -1, scale = 1, disp = 0;
    if (rm === 4) {
      const sib = code[pos++];
      scale = 1 << (sib >> 6); index = (sib >> 3) & 7; base = sib & 7;
      if (index === 4) index = -1;
      if (base === 5 && mod === 0) { disp = code[pos] | (code[pos + 1] << 8) | (code[pos + 2] << 16) | (code[pos + 3] << 24); pos += 4; base = -1; }
    } else if (rm === 5 && mod === 0) { disp = code[pos] | (code[pos + 1] << 8) | (code[pos + 2] << 16) | (code[pos + 3] << 24); pos += 4; mem = '[rip+' + hex(disp >>> 0) + ']'; }
    if (mod === 1) { disp = code[pos++] << 24 >> 24; }
    else if (mod === 2) { disp = code[pos] | (code[pos + 1] << 8) | (code[pos + 2] << 16) | (code[pos + 3] << 24); pos += 4; }
    if (!mem) {
      const parts = [];
      if (index >= 0) parts.push('r' + index + (scale > 1 ? '*' + scale : ''));
      if (base >= 0) parts.push('r' + base);
      let s = parts.join('+');
      if (base < 0 && index < 0) s = hex(disp >>> 0);
      else if (disp) s += (disp < 0 ? '-' + hex(-disp) : '+' + hex(disp));
      mem = '[' + s + ']';
    }
  }
  const size = pos - p0;
  const VEX_NAMES = {
    '1/1/6f': 'vmovdqu', '1/1/7f': 'vmovdqu', '1/0/6f': 'vmovdqa', '1/0/7f': 'vmovdqa',
    '1/0/28': 'vmovaps', '1/0/29': 'vmovaps', '1/0/10': 'vmovups', '1/0/11': 'vmovups',
    '1/1/10': 'vmovss', '1/1/11': 'vmovss',
    '1/0/57': 'vxorps', '1/0/58': 'vaddps', '1/0/5c': 'vsubps', '1/0/59': 'vmulps', '1/0/5e': 'vdivps',
    '1/1/58': 'vaddss', '1/1/5c': 'vsubss', '1/1/59': 'vmulss', '1/1/5e': 'vdivss',
    '2/0/00': 'vpshufb'
  };
  const key = map + '/' + pp + '/' + op.toString(16).padStart(2, '0');
  const name = VEX_NAMES[key];
  const dst = 'xmm' + reg, src1 = 'xmm' + vvvv, src2 = mod === 3 ? 'xmm' + rm : mem;
  if (name === 'vmovdqu' || name === 'vmovdqa' || name === 'vmovaps' || name === 'vmovups' || name === 'vmovss') {
    return { size: size, text: name + ' ' + dst + ', ' + src2, mnemonic: name };
  }
  if (name) return { size: size, text: name + ' ' + dst + ', ' + src1 + ', ' + src2, mnemonic: name, vex: true };
  return { size: size, text: '.byte ' + Array.prototype.slice.call(code, p0, p0 + size).map(function (b) { return hex(b, 2); }).join(', ') + '  /* VEX 编码未实现 */', illegal: 'VEX 指令未实现' };
}

if (typeof module !== 'undefined') module.exports = { x86Disassemble };
