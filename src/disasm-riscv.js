/* ============================================================================
 * disasm-riscv.js — RISC-V 反汇编引擎 (RV32I/RV64I + M/A/F/D + C + Zicsr/Zifencei
 *                   + 常用 Zba/Zbb/Zbs/Zbc 扩展)
 * 说明：RISC-V 指令长度可变（16/32 位），解码必须逐条判断低 2 位是否为 0b11。
 * ==========================================================================*/
'use strict';

const RV_XREG = ['zero', 'ra', 'sp', 'gp', 'tp', 't0', 't1', 't2', 's0', 's1',
  'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7',
  's2', 's3', 's4', 's5', 's6', 's7', 's8', 's9', 's10', 's11',
  't3', 't4', 't5', 't6'];
const RV_FREG = ['ft0', 'ft1', 'ft2', 'ft3', 'ft4', 'ft5', 'ft6', 'ft7',
  'fs0', 'fs1', 'fa0', 'fa1', 'fa2', 'fa3', 'fa4', 'fa5', 'fa6', 'fa7',
  'fs2', 'fs3', 'fs4', 'fs5', 'fs6', 'fs7', 'fs8', 'fs9', 'fs10', 'fs11',
  'ft8', 'ft9', 'ft10', 'ft11'];
const RV_CSR_NAMES = {
  0x000: 'ustatus', 0x004: 'uie', 0x005: 'utvec', 0x040: 'uscratch', 0x041: 'uepc', 0x042: 'ucause', 0x043: 'utval', 0x044: 'uip',
  0x100: 'sstatus', 0x102: 'sedeleg', 0x103: 'sideleg', 0x104: 'sie', 0x105: 'stvec', 0x106: 'scounteren',
  0x140: 'sscratch', 0x141: 'sepc', 0x142: 'scause', 0x143: 'stval', 0x144: 'sip', 0x180: 'satp',
  0x300: 'mstatus', 0x301: 'misa', 0x302: 'medeleg', 0x303: 'mideleg', 0x304: 'mie', 0x305: 'mtvec', 0x306: 'mcounteren',
  0x310: 'mstatush', 0x340: 'mscratch', 0x341: 'mepc', 0x342: 'mcause', 0x343: 'mtval', 0x344: 'mip', 0x34A: 'mtinst', 0x34B: 'mtval2',
  0x3A0: 'pmpcfg0', 0x3A1: 'pmpcfg1', 0x3A2: 'pmpcfg2', 0x3A3: 'pmpcfg3',
  0x3B0: 'pmpaddr0', 0x3B1: 'pmpaddr1', 0x3B2: 'pmpaddr2', 0x3B3: 'pmpaddr3', 0x3B4: 'pmpaddr4', 0x3B5: 'pmpaddr5', 0x3B6: 'pmpaddr6', 0x3B7: 'pmpaddr7',
  0x001: 'fflags', 0x002: 'frm', 0x003: 'fcsr',
  0xB00: 'mcycle', 0xB02: 'minstret', 0xB80: 'mcycleh', 0xB82: 'minstreth',
  0xC00: 'cycle', 0xC01: 'time', 0xC02: 'instret', 0xC80: 'cycleh', 0xC81: 'timeh', 0xC82: 'instreth',
  0xF11: 'mvendorid', 0xF12: 'marchid', 0xF13: 'mimpid', 0xF14: 'mhartid', 0xF15: 'mconfigptr'
};
const RV_RM = ['rne', 'rtz', 'rdn', 'rup', 'rmm', 'reserved', 'reserved', 'dyn'];
const RV_FMT = ['s', 'd', 'h', 'q'];

const xreg = (n, opts) => (opts && opts.numeric ? 'x' + n : RV_XREG[n]);
const freg = (n, opts) => (opts && opts.numeric ? 'f' + n : RV_FREG[n]);

function sext(v, bits) {
  const m = Math.pow(2, bits - 1);
  return (v >= m) ? v - Math.pow(2, bits) : v;
}
function sx4(v) { return sext(v & 0xf, 4); }

/* ------------------------ 32 位指令立即数抽取 ------------------------ */
function immI(i) { return sext((i >> 20) & 0xfff, 12); }
function immS(i) { return sext((((i >> 25) & 0x7f) << 5) | ((i >> 7) & 0x1f), 12); }
function immB(i) {
  const v = ((i >> 31) & 1) << 12 | ((i >> 7) & 1) << 11 | ((i >> 25) & 0x3f) << 5 | ((i >> 8) & 0xf) << 1;
  return sext(v, 13);
}
function immU(i) { return (i >>> 12) & 0xfffff; }
function immJ(i) {
  const v = ((i >> 31) & 1) << 20 | ((i >> 12) & 0xff) << 12 | ((i >> 20) & 1) << 11 | ((i >> 21) & 0x3ff) << 1;
  return sext(v, 21);
}

/* ------------------------ 16 位压缩指令立即数 ------------------------ */
function cImmAddi4spn(i) { return ((i >> 11) & 0x3) << 4 | ((i >> 7) & 0xf) << 6 | ((i >> 6) & 1) << 2 | ((i >> 5) & 1) << 3; }
function cImmLW(i) { return ((i >> 10) & 0x7) << 3 | ((i >> 6) & 1) << 2 | ((i >> 5) & 1) << 6; }
function cImmLD(i) { return ((i >> 10) & 0x7) << 3 | ((i >> 5) & 0x3) << 6; }
function cImm6(i) { return sext((((i >> 12) & 1) << 5) | ((i >> 2) & 0x1f), 6); }
function cImmAddi16sp(i) {
  const v = ((i >> 12) & 1) << 9 | ((i >> 6) & 1) << 4 | ((i >> 5) & 1) << 6 | ((i >> 3) & 0x3) << 7 | ((i >> 2) & 1) << 5;
  return sext(v, 10);
}
function cImmLui(i) { return sext((((i >> 12) & 1) << 17) | (((i >> 2) & 0x1f) << 12), 18); }
function cImmJ(i) {
  const v = ((i >> 12) & 1) << 11 | ((i >> 11) & 1) << 4 | ((i >> 9) & 0x3) << 8 | ((i >> 8) & 1) << 10 |
    ((i >> 7) & 1) << 6 | ((i >> 6) & 1) << 7 | ((i >> 3) & 0x7) << 1 | ((i >> 2) & 1) << 5;
  return sext(v, 12);
}
function cImmB(i) {
  const v = ((i >> 12) & 1) << 8 | ((i >> 10) & 0x3) << 3 | ((i >> 5) & 0x3) << 6 | ((i >> 3) & 0x3) << 1 | ((i >> 2) & 1) << 5;
  return sext(v, 9);
}
function cImmLWSP(i) { return ((i >> 12) & 1) << 5 | ((i >> 4) & 0x7) << 2 | ((i >> 2) & 0x3) << 6; }
function cImmLDSP(i) { return ((i >> 12) & 1) << 5 | ((i >> 5) & 0x3) << 3 | ((i >> 2) & 0x7) << 6; }
function cImmSWSP(i) { return ((i >> 9) & 0xf) << 2 | ((i >> 7) & 0x3) << 6; }
function cImmSDSP(i) { return ((i >> 10) & 0x7) << 3 | ((i >> 7) & 0x7) << 6; }
function cImmShamt(i) { return (((i >> 12) & 1) << 5) | ((i >> 2) & 0x1f); }
function cShamt(i, bits) { return bits === 32 ? ((i >> 2) & 0x1f) : cImmShamt(i); }

const cRegP = (i) => 8 + ((i >> 2) & 0x7);   // 三位压缩寄存器 → x8..x15
const cRegP2 = (i) => 8 + ((i >> 7) & 0x7);
const cRd = (i) => (i >> 7) & 0x1f;
const cRs2 = (i) => (i >> 2) & 0x1f;

/* --------------------------- 单条指令解码 --------------------------- */
function decodeRiscv(bytes, pos, addr, opts) {
  opts = opts || {};
  const bits = opts.bits || 64;
  const o = (opts.numeric ? { numeric: true } : null);
  const rel = (v) => (v === null ? '' : ((v < 0 ? '-' : '+') + '0x' + Math.abs(v).toString(16)));
  const immHex = (v) => (v < 0 ? '-' + hex(-v) : hex(v));
  const abs = (a) => (a >>> 0);

  if (pos + 2 > bytes.length) return null;
  let half = bytes[pos] | (bytes[pos + 1] << 8);
  if ((half & 0x3) === 0x3) {
    if (pos + 4 > bytes.length) return { size: 4, text: '.byte ...', illegal: '文件末尾不足 4 字节', raw: half };
    const i = (half | (bytes[pos + 2] << 16) | (bytes[pos + 3] << 24)) >>> 0;
    return decodeRiscv32(i, addr, bits, opts, o, rel, immHex, abs);
  }
  // 压缩指令（16 位）
  return decodeRiscvC(half, addr, bits, opts);
}

function mk(size, text, extra) {
  return Object.assign({ size, text, mnemonic: text.split(/\s+/)[0], operands: text.split(/\s+/).slice(1).join(' ') }, extra || {});
}

function decodeRiscv32(i, addr, bits, opts, _o, rel, immHex, abs) {
  const opcode = i & 0x7f;
  const rd = (i >> 7) & 0x1f, rs1 = (i >> 15) & 0x1f, rs2 = (i >> 20) & 0x1f;
  const f3 = (i >> 12) & 0x7, f7 = (i >> 25) & 0x7f;
  const R = (n) => xreg(n, opts), F = (n) => freg(n, opts);
  const aq = (i >> 26) & 1, rl = (i >> 25) & 1;

  switch (opcode) {
    // lui / auipc 的高 20 位立即数（左移 12 位后的值）也带出来，
    // 供「按地址反查引用」把 lui+addi 之类的组合还原成完整地址。
    case 0x37: return mk(4, `lui ${R(rd)}, ${hex(immU(i) << 12)}`, { rd, imm: immU(i) << 12, hi20: true });
    case 0x17: return mk(4, `auipc ${R(rd)}, ${hex(immU(i) << 12)}`, { rd, imm: immU(i) << 12, hi20: true, pcrel: true });
    case 0x6f: {
      const off = immJ(i), tgt = abs(addr + off);
      if (rd === 0 && opts.aliases !== false) return mk(4, `j ${hex(tgt)}`, { rd, target: tgt, isJump: true });
      return mk(4, `jal ${R(rd)}, ${hex(tgt)}`, { rd, target: tgt, isCall: rd === 1, isJump: true });
    }
    case 0x67: {
      const off = immI(i);
      if (rd === 0 && rs1 === 1 && off === 0) return mk(4, 'ret', { isReturn: true, isJump: true });
      if (off === 0 && rd === 0) return mk(4, `jr ${R(rs1)}`, { rs1, rd, isJump: true, isReturn: rs1 === 1 });
      return mk(4, `jalr ${R(rd)}, ${off}, ${R(rs1)}`, { rd, rs1, imm: off, target: null, isCall: rd === 1 || rd === 5, isJump: true });
    }
    case 0x63: {
      const off = immB(i), tgt = abs(addr + off);
      const m = ['beq', 'bne', null, null, 'blt', 'bge', 'bltu', 'bgeu'][f3];
      if (!m) break;
      if (opts.aliases !== false && rs2 === 0 && (m === 'beq' || m === 'bne'))
        return mk(4, `${m === 'beq' ? 'beqz' : 'bnez'} ${R(rs1)}, ${hex(tgt)}`, { rs1, rs2, target: tgt, isBranch: true });
      return mk(4, `${m} ${R(rs1)}, ${R(rs2)}, ${hex(tgt)}`, { rs1, rs2, target: tgt, isBranch: true });
    }
    case 0x03: {
      const off = immI(i);
      const m = ['lb', 'lh', 'lw', 'ld', 'lbu', 'lhu', 'lwu', null][f3];
      if (!m) break;
      if (bits === 32 && (m === 'ld' || m === 'lwu')) break;
      return mk(4, `${m} ${R(rd)}, ${off}(${R(rs1)})`, { rd, rs1, memOffset: off });
    }
    case 0x23: {
      const off = immS(i);
      const m = ['sb', 'sh', 'sw', 'sd', null, null, null, null][f3];
      if (!m) break;
      if (bits === 32 && m === 'sd') break;
      return mk(4, `${m} ${R(rs2)}, ${off}(${R(rs1)})`, { rs1, rs2, memOffset: off });
    }
    case 0x13: {
      const off = immI(i);
      switch (f3) {
        case 0: {
          if (rd === 0 && rs1 === 0 && off === 0) return mk(4, 'nop', { isNop: true });
          if (opts.aliases !== false) {
            if (rd !== 0 && rs1 === 0) return mk(4, `li ${R(rd)}, ${off}`, { rd, imm: off });         // li
            if (rd !== 0 && off === 0) return mk(4, `mv ${R(rd)}, ${R(rs1)}`, { rd, rs1 });            // mv
          }
          return mk(4, `addi ${R(rd)}, ${R(rs1)}, ${off}`, { rd, rs1, imm: off });
        }
        case 2: return mk(4, `slti ${R(rd)}, ${R(rs1)}, ${off}`, { rd, rs1 });
        case 3: return mk(4, `sltiu ${R(rd)}, ${R(rs1)}, ${off}`, { rd, rs1 });
        case 4: return mk(4, `xori ${R(rd)}, ${R(rs1)}, ${off}`, { rd, rs1 });
        case 6: return mk(4, `ori ${R(rd)}, ${R(rs1)}, ${off}`, { rd, rs1 });
        case 7: return mk(4, `andi ${R(rd)}, ${R(rs1)}, ${off}`, { rd, rs1 });
        case 1: {
          if (f7 !== 0) break;
          const sh = (i >> 20) & 0x3f;
          if (bits === 32 && sh > 31) break;
          return mk(4, `slli ${R(rd)}, ${R(rs1)}, ${sh}`, { rd, rs1 });
        }
        case 5: {
          const sh = bits === 32 ? ((i >> 20) & 0x1f) : (((i >> 20) & 0x3f));
          if ((f7 & 0x20) === 0 && (f7 & 0x1f) === 0) return mk(4, `srli ${R(rd)}, ${R(rs1)}, ${sh}`, { rd, rs1 });
          if ((f7 & 0x20) === 0x20 && (f7 & 0x1f) === 0) return mk(4, `srai ${R(rd)}, ${R(rs1)}, ${sh}`, { rd, rs1 });
          if (bits === 64 && (f7 & 0x3f) === 0x30) return mk(4, `rori ${R(rd)}, ${R(rs1)}, ${(((i >> 20) & 0x3f))}`, { rd, rs1 }); // Zbb
          break;
        }
      }
      break;
    }
    case 0x1b: { // RV64 OP-IMM-32
      if (bits !== 64) break;
      const off = immI(i);
      if (f3 === 0) return mk(4, `addiw ${R(rd)}, ${R(rs1)}, ${off}`, { rd, rs1 });
      if (f3 === 1 && f7 === 0) return mk(4, `slliw ${R(rd)}, ${R(rs1)}, ${(i >> 20) & 0x1f}`, { rd, rs1 });
      if (f3 === 5 && f7 === 0) return mk(4, `srliw ${R(rd)}, ${R(rs1)}, ${(i >> 20) & 0x1f}`, { rd, rs1 });
      if (f3 === 5 && f7 === 0x20) return mk(4, `sraiw ${R(rd)}, ${R(rs1)}, ${(i >> 20) & 0x1f}`, { rd, rs1 });
      break;
    }
    case 0x33: {
      const key = (f7 << 3) | f3;
      const simple = {
        0x000: 'add', 0x020: 'sub', 0x001: 'sll', 0x002: 'slt', 0x003: 'sltu',
        0x004: 'xor', 0x005: 'srl', 0x025: 'sra', 0x006: 'or', 0x007: 'and',
        0x008: 'mul', 0x009: 'mulh', 0x00a: 'mulhsu', 0x00b: 'mulhu',
        0x00c: 'div', 0x00d: 'divu', 0x00e: 'rem', 0x00f: 'remu',
        0x207: 'andn', 0x206: 'orn', 0x204: 'xnor', 0x205: 'rol', 0x105: 'ror',
        0x032: 'sh1add', 0x052: 'sh2add', 0x072: 'sh3add',
        0x031: 'bclr', 0x021: 'bset', 0x041: 'binv', 0x061: 'bext',
        0x011: 'bseti', 0x033: 'clmul', 0x013: 'clmulh', 0x023: 'clmulr',
        0x045: 'min', 0x055: 'minu', 0x065: 'max', 0x075: 'maxu', 0x085: 'orc.b',
        0x094: 'rev8', 0x014: 'czero.eqz', 0x024: 'czero.nez'
      };
      const m = simple[key];
      if (m) {
        if ((m === 'orc.b' || m === 'rev8' || m === 'czero.eqz' || m === 'czero.nez') && bits === 32 && m === 'rev8') {
          return mk(4, `rev8 ${R(rd)}, ${R(rs1)}`, { rd, rs1 });
        }
        if (m.startsWith('sh') && rs2 === 0 && !opts.numeric) { /* Zba 形式 sh1add rd,rs1,rs2 */ }
        if (m === 'czero.eqz' || m === 'czero.nez') return mk(4, `${m} ${R(rd)}, ${R(rs1)}, ${R(rs2)}`, { rd, rs1, rs2 });
        return mk(4, `${m} ${R(rd)}, ${R(rs1)}, ${R(rs2)}`, { rd, rs1, rs2 });
      }
      // Zbb 单目/立即数形式
      if (key === 0x181 && rs2 === 0) return mk(4, `clz ${R(rd)}, ${R(rs1)}`, { rd, rs1 });
      if (key === 0x181 && rs2 === 1) return mk(4, `ctz ${R(rd)}, ${R(rs1)}`, { rd, rs1 });
      if (key === 0x181 && rs2 === 2) return mk(4, `cpop ${R(rd)}, ${R(rs1)}`, { rd, rs1 });
      if (key === 0x181 && rs2 === 4) return mk(4, `sext.b ${R(rd)}, ${R(rs1)}`, { rd, rs1 });
      if (key === 0x181 && rs2 === 5) return mk(4, `sext.h ${R(rd)}, ${R(rs1)}`, { rd, rs1 });
      if (key === 0x021 && rs2 === 0 && rd === 0 && rs1 === 0) return mk(4, 'pause', { isNop: true });
      if (bits === 64 && key === 0x1b1 && rs2 === 6) return mk(4, `zext.w ${R(rd)}, ${R(rs1)}`, { rd, rs1 });
      if (bits === 32 && key === 0x021 && rs2 === 0x10) return mk(4, `zext.h ${R(rd)}, ${R(rs1)}`, { rd, rs1 });
      break;
    }
    case 0x3b: { // RV64 OP-32
      if (bits !== 64) break;
      const key = (f7 << 3) | f3;
      const m = {
        0x000: 'addw', 0x020: 'subw', 0x001: 'sllw', 0x005: 'srlw', 0x025: 'sraw',
        0x008: 'mulw', 0x00c: 'divw', 0x00d: 'divuw', 0x00e: 'remw', 0x00f: 'remuw',
        0x002: 'slliw', 0x205: 'rolw', 0x105: 'rorw'
      }[key];
      if (m) return mk(4, `${m} ${R(rd)}, ${R(rs1)}, ${R(rs2)}`, { rd, rs1, rs2 });
      break;
    }
    case 0x0f: {
      if (f3 === 0) {
        const pred = (i >> 24) & 0xf, succ = (i >> 20) & 0xf;
        const fm = (i >> 28) & 0xf;
        const letters = (v) => ['i', 'o', 'r', 'w'].filter((_, k) => v & (8 >> k)).join('') || 'none';
        if (rd === 0 && rs1 === 0 && pred === 0 && succ === 0 && fm === 0) return mk(4, 'fence');
        return mk(4, `fence ${letters(pred)}, ${letters(succ)}`, { pred, succ, fm });
      }
      if (f3 === 1 && rd === 0 && rs1 === 0 && immI(i) === 0) return mk(4, 'fence.i');
      break;
    }
    case 0x73: {
      if (f3 === 0) {
        if (rd === 0 && rs1 === 0) {
          if (i === 0x00000073) return mk(4, 'ecall', { isTrap: true });
          if (i === 0x00100073) return mk(4, 'ebreak', { isTrap: true });
          if (i === 0x00200073) return mk(4, 'uret', { isReturn: true });
          if (i === 0x10200073) return mk(4, 'sret', { isReturn: true });
          if (i === 0x10500073) return mk(4, 'wfi');
          if (i === 0x30200073) return mk(4, 'mret', { isReturn: true });
          if (i === 0x7b200073) return mk(4, 'dret', { isReturn: true });
        }
        break;
      }
      const csr = (i >> 20) & 0xfff;
      const name = RV_CSR_NAMES[csr] || ('csr' + hex(csr));
      if (f3 === 1) return mk(4, `csrrw ${R(rd)}, ${name}, ${R(rs1)}`, { rd, rs1, csr });
      if (f3 === 2) {
        if (opts.aliases !== false && rs1 === 0 && rd !== 0) return mk(4, `csrr ${R(rd)}, ${name}`, { rd, csr });
        return mk(4, `csrrs ${R(rd)}, ${name}, ${R(rs1)}`, { rd, rs1, csr });
      }
      if (f3 === 3) return mk(4, `csrrc ${R(rd)}, ${name}, ${R(rs1)}`, { rd, rs1, csr });
      if (f3 === 5) return mk(4, `csrrwi ${R(rd)}, ${name}, ${rs1}`, { rd, csr });
      if (f3 === 6) return mk(4, `csrrsi ${R(rd)}, ${name}, ${rs1}`, { rd, csr });
      if (f3 === 7) return mk(4, `csrrci ${R(rd)}, ${name}, ${rs1}`, { rd, csr });
      break;
    }
    case 0x2f: { // A 扩展
      if (f3 !== 2 && f3 !== 3) break;
      const suf = f3 === 2 ? 'w' : 'd';
      if (bits === 32 && f3 === 3) break;
      const f5 = (i >> 27) & 0x1f;
      const mod = (aq ? '.aq' : '') + (rl ? '.rl' : '');
      if (f5 === 0x02) return mk(4, `lr.${suf}${mod} ${R(rd)}, (${R(rs1)})`, { rd, rs1 });
      if (f5 === 0x03) return mk(4, `sc.${suf}${mod} ${R(rd)}, ${R(rs2)}, (${R(rs1)})`, { rd, rs1, rs2 });
      const m = { 0x00: 'amoadd', 0x01: 'amoswap', 0x04: 'amoxor', 0x08: 'amoor', 0x0c: 'amoand', 0x10: 'amomin', 0x14: 'amomax', 0x18: 'amominu', 0x1c: 'amomaxu' }[f5];
      if (m) return mk(4, `${m}.${suf}${mod} ${R(rd)}, ${R(rs2)}, (${R(rs1)})`, { rd, rs1, rs2 });
      break;
    }
    case 0x07: { // FP load
      const off = immI(i);
      const m = { 2: 'flw', 3: 'fld', 4: 'flq', 1: 'flh' }[f3];
      if (m) return mk(4, `${m} ${F(rd)}, ${off}(${R(rs1)})`, { rd, rs1, memOffset: off });
      break;
    }
    case 0x27: { // FP store
      const off = immS(i);
      const m = { 2: 'fsw', 3: 'fsd', 4: 'fsq', 1: 'fsh' }[f3];
      if (m) return mk(4, `${m} ${F(rs2)}, ${off}(${R(rs1)})`, { rs1, rs2, memOffset: off });
      break;
    }
    case 0x43: return fpFused('fmadd', i, F, R);
    case 0x47: return fpFused('fmsub', i, F, R);
    case 0x4b: return fpFused('fnmsub', i, F, R);
    case 0x4f: return fpFused('fnmadd', i, F, R);
    case 0x53: return fpOp(i, F, R, bits);
    case 0x57: {
      return mk(4, `# 向量指令 (OP-V) 编码 ${hex(i, 8)}`, { vector: true });
    }
    case 0x0b:
      return mk(4, `# 保留 opcode 0x0b（自定义扩展）编码 ${hex(i, 8)}`, { custom: true });
  }
  return mk(4, `.4byte ${hex(i, 8)}`, { illegal: '无法识别的指令编码', raw: i });
}

function fpFused(m, i, F, R) {
  const rd = (i >> 7) & 0x1f, rs1 = (i >> 15) & 0x1f, rs2 = (i >> 20) & 0x1f, rs3 = (i >> 27) & 0x1f;
  const fmt = (i >> 25) & 0x3, rm = (i >> 12) & 0x7;
  const name = `${m}.${RV_FMT[fmt]}`;
  const tail = rm === 7 ? '' : `, ${RV_RM[rm]}`;
  return mk(4, `${name} ${F(rd)}, ${F(rs1)}, ${F(rs2)}, ${F(rs3)}${tail}`, { rd, rs1, rs2, rs3, fmt });
}

function fpOp(i, F, R, bits) {
  const rd = (i >> 7) & 0x1f, rs1 = (i >> 15) & 0x1f, rs2 = (i >> 20) & 0x1f;
  const f3 = (i >> 12) & 0x7, f7 = (i >> 25) & 0x7f;
  const funct5 = f7 >> 2, fmt = f7 & 3;
  const T = RV_FMT[fmt], rm = RV_RM[f3];
  const tail = f3 === 7 ? '' : `, ${rm}`;
  switch (funct5) {
    case 0x00: return mk(4, `fadd.${T} ${F(rd)}, ${F(rs1)}, ${F(rs2)}${tail}`, { rd, rs1, rs2 });
    case 0x01: return mk(4, `fsub.${T} ${F(rd)}, ${F(rs1)}, ${F(rs2)}${tail}`, { rd, rs1, rs2 });
    case 0x02: return mk(4, `fmul.${T} ${F(rd)}, ${F(rs1)}, ${F(rs2)}${tail}`, { rd, rs1, rs2 });
    case 0x03: return mk(4, `fdiv.${T} ${F(rd)}, ${F(rs1)}, ${F(rs2)}${tail}`, { rd, rs1, rs2 });
    case 0x0b: return mk(4, `fsqrt.${T} ${F(rd)}, ${F(rs1)}${tail}`, { rd, rs1 });
    case 0x04: {
      const m = ['fsgnj', 'fsgnjn', 'fsgnjx'][f3] || 'fsgnj';
      if (rs2 === 0 && (f3 === 0 || f3 === 1)) return mk(4, `${f3 === 0 ? 'fmv' : 'fneg'}.${T} ${F(rd)}, ${F(rs1)}`, { rd, rs1 });
      return mk(4, `${m}.${T} ${F(rd)}, ${F(rs1)}, ${F(rs2)}`, { rd, rs1, rs2 });
    }
    case 0x05: {
      const m = f3 === 0 ? 'fmin' : f3 === 1 ? 'fmax' : 'fminmax';
      return mk(4, `${m}.${T} ${F(rd)}, ${F(rs1)}, ${F(rs2)}`, { rd, rs1, rs2 });
    }
    case 0x08: { // FCVT.{-}.{source}
      const dst = ['w', 'wu', 'l', 'lu'][rs2] || ('rs2=' + rs2);
      return mk(4, `fcvt.${dst}.${T} ${R(rd)}, ${F(rs1)}${tail}`, { rd, rs1 });
    }
    case 0x0a: { // FCVT.{fmt}.{source}
      const src = ['w', 'wu', 'l', 'lu'][rs2] || ('rs2=' + rs2);
      return mk(4, `fcvt.${T}.${src} ${F(rd)}, ${R(rs1)}${tail}`, { rd, rs1 });
    }
    case 0x0c: { // FCVT.{fmt}.{srcregfmt}
      const srcT = RV_FMT[rs2] || ('fmt' + rs2);
      if (rs2 === 0) return mk(4, `fcvt.${T}.${RV_FMT[fmt]} ${F(rd)}, ${F(rs1)}${tail}`, { rd, rs1 });
      return mk(4, `fcvt.${T}.${srcT} ${F(rd)}, ${F(rs1)}${tail}`, { rd, rs1 });
    }
    case 0x14: { // 比较
      const m = ['fle', 'flt', 'feq'][f3] || 'fcmp';
      return mk(4, `${m}.${T} ${R(rd)}, ${F(rs1)}, ${F(rs2)}`, { rd, rs1, rs2 });
    }
    case 0x1c: {
      if (f3 === 0) return mk(4, `fmv.x.${T === 's' ? 'w' : 'd'} ${R(rd)}, ${F(rs1)}`, { rd, rs1 });
      if (f3 === 1) return mk(4, `fclass.${T} ${R(rd)}, ${F(rs1)}`, { rd, rs1 });
      break;
    }
    case 0x1e: {
      if (f3 === 0) return mk(4, `fmv.${T === 's' ? 'w' : 'd'}.x ${F(rd)}, ${R(rs1)}`, { rd, rs1 });
      break;
    }
  }
  return mk(4, `# 未实现的浮点操作 (funct5=${funct5}, fmt=${T}) 编码 ${hex(i, 8)}`, { illegal: '未实现的浮点指令' });
}

/* -------------------------- 压缩指令解码 -------------------------- */
function decodeRiscvC(i, addr, bits, opts) {
  const op = i & 0x3, f3 = (i >> 13) & 0x7;
  const R = (n) => xreg(n, opts);
  const F = (n) => freg(n, opts);
  const abs = (a) => (a >>> 0);
  const is64 = bits === 64;
  const rd = cRd(i), rs2 = cRs2(i), rdp = cRegP(i), rsp2 = cRegP2(i);
  const rd1 = (i >> 7) & 0x1f, rs1p = cRegP2(i);

  if (op === 0) {
    switch (f3) {
      case 0: {
        const u = cImmAddi4spn(i);
        if (u === 0) return mk(2, `.2byte ${hex(i, 4)}`, { illegal: 'C.ADDI4SPN 保留编码（立即数为 0）', raw: i });
        return mk(2, `c.addi4spn ${R(rdp)}, sp, ${u}`, { rd: rdp });
      }
      case 1: return mk(2, `c.fld ${F(rdp)}, ${cImmLD(i)}(${R(rs1p)})`, { rd: rdp });
      case 2: return mk(2, `c.lw ${R(rdp)}, ${cImmLW(i)}(${R(rs1p)})`, { rd: rdp });
      case 3: return is64
        ? mk(2, `c.ld ${R(rdp)}, ${cImmLD(i)}(${R(rs1p)})`, { rd: rdp })
        : mk(2, `c.flw ${F(rdp)}, ${cImmLW(i)}(${R(rs1p)})`, { rd: rdp });
      case 5: return mk(2, `c.fsd ${F(rsp2)}, ${cImmLD(i)}(${R(rs1p)})`, { rs2: rsp2 });
      case 6: return mk(2, `c.sw ${R(rsp2)}, ${cImmLW(i)}(${R(rs1p)})`, { rs2: rsp2 });
      case 7: return is64
        ? mk(2, `c.sd ${R(rsp2)}, ${cImmLD(i)}(${R(rs1p)})`, { rs2: rsp2 })
        : mk(2, `c.fsw ${F(rsp2)}, ${cImmLW(i)}(${R(rs1p)})`, { rs2: rsp2 });
      default: return mk(2, `.2byte ${hex(i, 4)}`, { illegal: 'C0 保留编码', raw: i });
    }
  }
  if (op === 1) {
    switch (f3) {
      case 0: {
        const imm = cImm6(i);
        if (rd === 0) return mk(2, imm === 0 ? 'c.nop' : `c.addi ${R(0)}, ${imm}`, { isNop: imm === 0 });
        return mk(2, `c.addi ${R(rd)}, ${imm}`, { rd });
      }
      case 1: {
        if (is64) {
          const imm = cImm6(i);
          if (rd === 0) return mk(2, `.2byte ${hex(i, 4)}`, { illegal: 'C.ADDIW 保留编码', raw: i });
          return mk(2, `c.addiw ${R(rd)}, ${imm}`, { rd });
        }
        const off = cImmJ(i), tgt = abs(addr + off);
        return mk(2, `c.jal ${hex(tgt)}`, { target: tgt, isCall: true, isJump: true });
      }
      case 2: {
        const imm = cImm6(i);
        if (rd === 0) return mk(2, 'c.nop', { isNop: true });
        return mk(2, `c.li ${R(rd)}, ${imm}`, { rd });
      }
      case 3: {
        if (rd === 2) return mk(2, `c.addi16sp sp, ${cImmAddi16sp(i)}`, {});
        const v = cImmLui(i);
        if (rd === 0) return mk(2, `.2byte ${hex(i, 4)}`, { illegal: 'C.LUI 保留编码', raw: i });
        if (v === 0) return mk(2, `.2byte ${hex(i, 4)}`, { illegal: 'C.LUI 立即数为 0 为提示编码', raw: i });
        return mk(2, `c.lui ${R(rd)}, ${hex(v)}`, { rd });
      }
      case 4: {
        const f2 = (i >> 10) & 0x3;
        const sh = bits === 32 ? ((i >> 2) & 0x1f) : cImmShamt(i);
        if (f2 === 0) return mk(2, `c.srli ${R(rdp)}, ${sh}`, { rd: rdp });
        if (f2 === 1) return mk(2, `c.srai ${R(rdp)}, ${sh}`, { rd: rdp });
        if (f2 === 2) return mk(2, `c.andi ${R(rdp)}, ${cImm6(i)}`, { rd: rdp });
        const sel = ((i >> 12) & 1) << 1 | ((i >> 5) & 1);
        const m = ['c.sub', 'c.xor', 'c.or', 'c.and'][sel];
        return mk(2, `${m} ${R(rdp)}, ${R(rsp2)}`, { rd: rdp, rs2: rsp2 });
      }
      case 5: {
        const off = cImmJ(i), tgt = abs(addr + off);
        return mk(2, `c.j ${hex(tgt)}`, { target: tgt, isJump: true });
      }
      case 6: {
        const off = cImmB(i), tgt = abs(addr + off);
        return mk(2, `c.beqz ${R(rdp)}, ${hex(tgt)}`, { rd: rdp, target: tgt, isBranch: true });
      }
      case 7: {
        const off = cImmB(i), tgt = abs(addr + off);
        return mk(2, `c.bnez ${R(rdp)}, ${hex(tgt)}`, { rd: rdp, target: tgt, isBranch: true });
      }
    }
  }
  if (op === 2) {
    switch (f3) {
      case 0: {
        if (rd === 0) return mk(2, `.2byte ${hex(i, 4)}`, { illegal: 'C.SLLI 保留编码', raw: i });
        return mk(2, `c.slli ${R(rd)}, ${cShamt(i, bits)}`, { rd });
      }
      case 1: return mk(2, `c.fldsp ${F(rd)}, ${cImmLDSP(i)}(sp)`, { rd });
      case 2: {
        if (rd === 0) return mk(2, `.2byte ${hex(i, 4)}`, { illegal: 'C.LWSP 保留编码', raw: i });
        return mk(2, `c.lwsp ${R(rd)}, ${cImmLWSP(i)}(sp)`, { rd });
      }
      case 3: {
        if (rd === 0) return mk(2, `.2byte ${hex(i, 4)}`, { illegal: 'C.LDSP 保留编码', raw: i });
        return is64 ? mk(2, `c.ldsp ${R(rd)}, ${cImmLDSP(i)}(sp)`, { rd })
          : mk(2, `c.flwsp ${F(rd)}, ${cImmLWSP(i)}(sp)`, { rd });
      }
      case 4: {
        const f4 = (i >> 12) & 0xf;
        if (f4 === 8 || f4 === 9) {
          const isJalr = (f4 === 9);
          if (rs2 === 0) {
            if (rd === 0) {
              if (isJalr) return mk(2, 'c.ebreak', { isTrap: true });
              return mk(2, `.2byte ${hex(i, 4)}`, { illegal: 'C.JR 且 rs1=0 为保留编码', raw: i });
            }
            if (isJalr) return mk(2, `c.jalr ${R(rd)}`, { rd, isCall: true, isJump: true });
            if (rd === 1 && opts.aliases !== false) return mk(2, 'ret', { rd, isReturn: true, isJump: true });
            return mk(2, `c.jr ${R(rd)}`, { rd, isJump: true, isReturn: rd === 1 });
          }
          if (rd === 0) {
            // 提示编码 (hint)
            const m = isJalr ? 'c.add' : 'c.mv';
            return mk(2, `${m} ${R(0)}, ${R(rs2)}`, { hint: true });
          }
          return mk(2, `${isJalr ? 'c.add' : 'c.mv'} ${R(rd)}, ${R(rs2)}`, { rd, rs2 });
        }
        return mk(2, `.2byte ${hex(i, 4)}`, { illegal: 'C2-100 保留编码', raw: i });
      }
      case 5: return mk(2, `c.fsdsp ${F(cRs2(i))}, ${cImmSDSP(i)}(sp)`, { rs2 });
      case 6: return mk(2, `c.swsp ${R(cRs2(i))}, ${cImmSWSP(i)}(sp)`, { rs2 });
      case 7: {
        const s2 = (i >> 2) & 0x1f;
        return is64 ? mk(2, `c.sdsp ${R(s2)}, ${cImmSDSP(i)}(sp)`, { rs2: s2 })
          : mk(2, `c.fswsp ${F(s2)}, ${cImmSWSP(i)}(sp)`, { rs2: s2 });
      }
    }
  }
  return mk(2, `.2byte ${hex(i, 4)}`, { illegal: '无法识别的压缩指令', raw: i });
}

/* --------------------------- 线性扫描驱动器 --------------------------- */
/**
 * 对一段代码做线性反汇编扫描。
 * @param {Uint8Array} code 机器码字节
 * @param {number} vaddr 代码起始虚拟地址
 * @param {object} opts { bits, symbols: Map<addr, sym>, aliases:boolean, numeric:boolean, forceC:'auto'|'on'|'off' }
 */
function riscvDisassemble(code, vaddr, opts) {
  opts = opts || {};
  const out = [];
  let pos = 0;
  const lines = opts.symbols || new Map();
  const limit = opts.maxBytes ? Math.min(code.length, opts.maxBytes) : code.length;
  let hiPending = null;        // 待配对的高 20 位装载（lui / auipc）
  while (pos < limit) {
    const addr = (vaddr + pos) >>> 0;
    let insn;
    try {
      insn = decodeRiscv(code, pos, addr, opts);
    } catch (e) {
      insn = { size: 2, text: '.2byte ???', illegal: '解码异常: ' + e.message };
    }
    if (!insn) break;
    if (!insn.size) insn.size = 2;
    insn.addr = addr;
    insn.fileOffset = (opts.fileBase || 0) + pos;
    insn.bytes = code.subarray(pos, Math.min(code.length, pos + insn.size));
    // 指令流中出现的 16 位指令但文件未声明 C 扩展 → 提示
    if (insn.size === 2 && opts.forceC === 'off') {
      insn.text = '.2byte ' + hex(insn.bytes[0] | (insn.bytes[1] << 8), 4);
      insn.illegal = '该文件未声明 C 扩展（e_flags 无 EF_RISCV_RVC），按 16 位数据展示。可在反汇编设置中强制开启压缩指令解析。';
      insn.warn = true;
    } else if (insn.size === 2 && opts.forceC === 'auto' && !opts.hasRVC) {
      insn.warn = true;
      insn.note = '疑似压缩指令，但 e_flags 未声明 RVC（EF_RISCV_RVC）。';
    }
    if (lines.has(addr)) {
      const s = lines.get(addr);
      insn.symbol = s.name;
      insn.isFunctionEntry = true;
    }
    // 还原 lui/auipc + 低 12 位 组合出的完整地址，命中符号时标注出来，
    // 与 objdump 的 “# 80005200 <topofstack>” 行为一致。
    if (insn.hi20) {
      // 上一条高位装载没有与低位配对 → 它自己可能就是完整地址
      if (hiPending) {
        const hp = out[hiPending.index];
        const hitH = lines.get(hiPending.base);
        if (hp && hitH) { hp.resolvedAddress = hiPending.base; hp.resolvedSymbol = hitH.name; }
      }
      hiPending = { rd: insn.rd, base: (insn.pcrel ? (addr + insn.imm) : insn.imm) >>> 0, index: out.length };
    } else if (hiPending) {
      const off = (insn.rs1 === hiPending.rd)
        ? (insn.memOffset !== undefined ? insn.memOffset : insn.imm)
        : null;
      if (off !== undefined && off !== null) {
        const full = (hiPending.base + off) >>> 0;
        const hit = lines.get(full);
        if (hit) {
          insn.resolvedAddress = full;
          insn.resolvedSymbol = hit.name;
          const prev = out[hiPending.index];
          if (prev) { prev.resolvedAddress = full; prev.resolvedSymbol = hit.name; }
        }
        hiPending = null;
      } else if (insn.rd === hiPending.rd) {
        // 同一个寄存器被改写，说明高位装载已经用完 → 若它本身命中符号就标注
        const hp = out[hiPending.index];
        const hitH = lines.get(hiPending.base);
        if (hp && hitH) { hp.resolvedAddress = hiPending.base; hp.resolvedSymbol = hitH.name; }
        hiPending = null;
      }
    }
    const tgt = insn.target;
    if (tgt !== undefined && tgt !== null) {
      const sym = lines.get(tgt >>> 0);
      if (sym) insn.targetSymbol = sym.name;
      else if (opts.sectionRanges) {
        for (const r of opts.sectionRanges) {
          if (tgt >= r.start && tgt < r.end) { insn.targetSection = r.name; break; }
        }
      }
    }
    out.push(insn);
    pos += insn.size;
  }
  if (pos < code.length && !opts.maxBytes) {
    out.push({
      addr: (vaddr + pos) >>> 0, fileOffset: (opts.fileBase || 0) + pos, size: code.length - pos,
      text: `.byte ${Array.from(code.slice(pos, Math.min(code.length, pos + 8))).map(b => hex(b, 2)).join(', ')}` + (code.length - pos > 8 ? ', ...' : ''),
      tail: true, bytes: code.subarray(pos)
    });
  }
  return out;
}

/* ============================================================================
 * 指令编码字段拆解：把一条指令的机器码按规范位域切开，
 * 用于「二进制 ↔ 助记符」的对照面板。
 * 返回 { format, bits, word, fields: [{name, hi, lo, width, value, hex, bin, meaning}] }
 * ==========================================================================*/
const RV_FORMAT_HINT = {
  0x37: 'U 型', 0x17: 'U 型', 0x6f: 'J 型', 0x67: 'I 型',
  0x63: 'B 型', 0x03: 'I 型', 0x23: 'S 型', 0x13: 'I 型', 0x1b: 'I 型',
  0x33: 'R 型', 0x3b: 'R 型', 0x0f: 'I 型', 0x73: 'I 型（SYSTEM）',
  0x2f: 'R 型（AMO）', 0x07: 'I 型', 0x27: 'S 型',
  0x43: 'R4 型', 0x47: 'R4 型', 0x4b: 'R4 型', 0x4f: 'R4 型', 0x53: 'R 型（OP-FP）'
};

/** 把 32 位指令切成规范位域；opts.numeric 用 x0/x1 而不是 ABI 名 */
function riscvInsnFields(word, is64, opts) {
  opts = opts || {};
  const isC = (word & 0x3) !== 0x3;
  if (isC) return riscvCFields(word & 0xffff, opts);
  const w = word >>> 0;
  const bits = (hi, lo) => (w >>> lo) & ((1 << (hi - lo + 1)) - 1);
  const R = (n) => xreg(n, opts);
  const F = (n) => freg(n, opts);
  const opcode = bits(6, 0), funct3 = bits(14, 12), funct7 = bits(31, 25);
  const rd = bits(11, 7), rs1 = bits(19, 15), rs2 = bits(24, 20);
  const F_ = (name, hi, lo, meaning, hexOverride) => ({
    name: name, hi: hi, lo: lo, width: hi - lo + 1,
    value: bits(hi, lo),
    hex: hexOverride !== undefined ? hexOverride : hex(bits(hi, lo), Math.ceil((hi - lo + 1) / 4)),
    bin: bits(hi, lo).toString(2).padStart(hi - lo + 1, '0'),
    meaning: meaning || ''
  });
  const imI = immI(w), imS = immS(w), imB = immB(w), imU = immU(w), imJ = immJ(w);
  const out = [];
  switch (opcode) {
    case 0x37: case 0x17:                                   // U 型
      out.push(F_('imm[31:12]', 31, 12, '高 20 位立即数，指令中左移 12 位 → 值 ' + hex(imU << 12)));
      out.push(F_('rd', 11, 7, R(rd) + '（目标寄存器）'));
      break;
    case 0x6f:                                              // J 型
      out.push(F_('imm[20|10:1|11|19:12]', 31, 12, '被打散的 20 位跳转偏移 → 相对 PC 偏移 ' + imJ));
      out.push(F_('rd', 11, 7, R(rd) + '（返回地址寄存器）'));
      break;
    case 0x63:                                              // B 型
      out.push(F_('imm[12|10:5]', 31, 25, '分支偏移高位（被打散）'));
      out.push(F_('rs2', 24, 20, R(rs2) + '（第二个比较寄存器）'));
      out.push(F_('rs1', 19, 15, R(rs1) + '（第一个比较寄存器）'));
      out.push(F_('funct3', 14, 12, ['beq', 'bne', '—', '—', 'blt', 'bge', 'bltu', 'bgeu'][funct3] + '：决定比较方式'));
      out.push(F_('imm[4:1|11]', 11, 7, '分支偏移低位 → 合成偏移 ' + imB));
      break;
    case 0x03:                                              // 载入 I 型
      out.push(F_('imm[11:0]', 31, 20, '字节偏移 ' + imI));
      out.push(F_('rs1', 19, 15, R(rs1) + '（基址寄存器）'));
      out.push(F_('funct3', 14, 12, ['lb', 'lh', 'lw', 'ld', 'lbu', 'lhu', 'lwu', '—'][funct3] + '：决定载入宽度与符号'));
      out.push(F_('rd', 11, 7, R(rd) + '（目标寄存器）'));
      break;
    case 0x67:                                              // jalr
      out.push(F_('imm[11:0]', 31, 20, '字节偏移 ' + imI));
      out.push(F_('rs1', 19, 15, R(rs1) + '（跳转基址寄存器）'));
      out.push(F_('funct3', 14, 12, '必须为 000'));
      out.push(F_('rd', 11, 7, R(rd) + '（返回地址寄存器）'));
      break;
    case 0x23:                                              // 存储 S 型
      out.push(F_('imm[11:5]', 31, 25, '偏移高位（被打散）'));
      out.push(F_('rs2', 24, 20, R(rs2) + '（被存储的数据寄存器）'));
      out.push(F_('rs1', 19, 15, R(rs1) + '（基址寄存器）'));
      out.push(F_('funct3', 14, 12, ['sb', 'sh', 'sw', 'sd', '—', '—', '—', '—'][funct3] + '：决定存储宽度'));
      out.push(F_('imm[4:0]', 11, 7, '偏移低位 → 合成偏移 ' + imS));
      break;
    case 0x13: case 0x1b: {                                 // OP-IMM
      if (funct3 === 1 || funct3 === 5) {                   // 移位立即数
        out.push(F_('funct7/shamt[5]', 31, 25, (funct3 === 1 ? 'slli' : (funct7 === 0x20 ? 'srai' : 'srli')) + '：区分移位类型'));
        out.push(F_('shamt[4:0]', 24, 20, '移位量 ' + bits(24, 20)));
      } else {
        out.push(F_('imm[11:0]', 31, 20, '带符号立即数 ' + imI));
      }
      out.push(F_('rs1', 19, 15, R(rs1) + '（源寄存器）'));
      out.push(F_('funct3', 14, 12, ['addi', 'slli', 'slti', 'sltiu', 'xori', 'srli/srai', 'ori', 'andi'][funct3] + '：决定运算种类'));
      out.push(F_('rd', 11, 7, R(rd) + '（目标寄存器）'));
      break;
    }
    case 0x33: case 0x3b: {                                 // OP / OP-32
      out.push(F_('funct7', 31, 25, (opcode === 0x33
        ? ({ 0x00: '普通运算', 0x20: '减法/算术右移', 0x01: 'M 扩展（乘除）' }[funct7] || '扩展运算')
        : 'OP-32（RV64 的 32 位运算）')));
      out.push(F_('rs2', 24, 20, R(rs2) + '（第二源寄存器）'));
      out.push(F_('rs1', 19, 15, R(rs1) + '（第一源寄存器）'));
      out.push(F_('funct3', 14, 12, '与 funct7 一起决定助记符'));
      out.push(F_('rd', 11, 7, R(rd) + '（目标寄存器）'));
      break;
    }
    case 0x0f:
      if (funct3 === 0) {
        out.push(F_('fm', 31, 28, '内存屏障模式'));
        out.push(F_('pred', 27, 24, '前驱 I/O/R/W 位'));
        out.push(F_('succ', 23, 20, '后继 I/O/R/W 位'));
        out.push(F_('rs1', 19, 15, '必须为 0'));
        out.push(F_('rd', 11, 7, '必须为 0'));
      } else {
        out.push(F_('imm[11:0]', 31, 20, '必须为 0'));
        out.push(F_('funct3', 14, 12, '001 = fence.i（指令缓存同步）'));
      }
      break;
    case 0x73:                                              // SYSTEM / CSR
      if (funct3 === 0) {
        out.push(F_('funct12', 31, 20, ({ 0x000: 'ecall', 0x001: 'ebreak', 0x102: 'sret', 0x302: 'mret', 0x105: 'wfi' }[bits(31, 20)] || '系统指令')));
        out.push(F_('rs1/rd', 19, 7, '通常为 0'));
      } else {
        const csr = bits(31, 20);
        out.push(F_('csr', 31, 20, (RV_CSR_NAMES[csr] || ('csr' + hex(csr))) + '：控制状态寄存器编号'));
        out.push(F_('rs1/uimm', 19, 15, ['csrrw', 'csrrs', 'csrrc', '', 'csrrwi', 'csrrsi', 'csrrci'][funct3 - 1] + ' 的操作数'));
        out.push(F_('funct3', 14, 12, ['—', 'csrrw', 'csrrs', 'csrrc', '—', 'csrrwi', 'csrrsi', 'csrrci'][funct3] + '：CSR 操作类型'));
        out.push(F_('rd', 11, 7, R(rd) + '（读出的旧值）'));
      }
      break;
    case 0x2f: {                                            // AMO
      out.push(F_('funct5', 31, 27, '原子操作类型（amoadd/amoswap/lr/sc…）'));
      out.push(F_('aq', 26, 26, 'Acquire 语义'));
      out.push(F_('rl', 25, 25, 'Release 语义'));
      out.push(F_('rs2', 24, 20, R(rs2) + (funct3 === 2 ? '（比较值）' : '（操作数）')));
      out.push(F_('rs1', 19, 15, R(rs1) + '（内存地址）'));
      out.push(F_('funct3', 14, 12, funct3 === 2 ? '010 = .w（32 位）' : '011 = .d（64 位）'));
      out.push(F_('rd', 11, 7, R(rd) + '（读出的旧值）'));
      break;
    }
    case 0x07: case 0x27:                                   // 浮点载入 / 存储
      if (opcode === 0x07) {
        out.push(F_('imm[11:0]', 31, 20, '字节偏移 ' + imI));
        out.push(F_('rs1', 19, 15, R(rs1) + '（基址）'));
        out.push(F_('funct3', 14, 12, ['—', 'flh', 'flw', 'fld', 'flq'][funct3] || '—'));
        out.push(F_('rd', 11, 7, F(rd) + '（浮点目标寄存器）'));
      } else {
        out.push(F_('imm[11:5]', 31, 25, '偏移高位'));
        out.push(F_('rs2', 24, 20, F(rs2) + '（浮点源寄存器）'));
        out.push(F_('rs1', 19, 15, R(rs1) + '（基址）'));
        out.push(F_('funct3', 14, 12, ['—', 'fsh', 'fsw', 'fsd', 'fsq'][funct3] || '—'));
        out.push(F_('imm[4:0]', 11, 7, '偏移低位 → 合成 ' + imS));
      }
      break;
    case 0x43: case 0x47: case 0x4b: case 0x4f:             // 融合乘加
      out.push(F_('rs3', 31, 27, F(bits(31, 27)) + '（第三源寄存器）'));
      out.push(F_('fmt', 26, 25, ['单精度 .s', '双精度 .d', '半精度 .h', '四精度 .q'][bits(26, 25)]));
      out.push(F_('rs2', 24, 20, F(rs2)));
      out.push(F_('rs1', 19, 15, F(rs1)));
      out.push(F_('rm', 14, 12, '舍入模式 ' + RV_RM[funct3]));
      out.push(F_('rd', 11, 7, F(rd)));
      break;
    case 0x53:                                              // OP-FP
      out.push(F_('funct7', 31, 25, '高位 + 精度位：决定 fadd/fmul/fcvt…'));
      out.push(F_('rs2', 24, 20, '第二操作数 / 转换源格式'));
      out.push(F_('rs1', 19, 15, F(rs1)));
      out.push(F_('funct3', 14, 12, '舍入模式 ' + RV_RM[funct3]));
      out.push(F_('rd', 11, 7, F(rd)));
      break;
    default:
      out.push(F_('opcode', 6, 0, '未识别的操作码'));
  }
  out.push(F_('opcode', 6, 0, (RV_FORMAT_HINT[opcode] || '') + '；低 2 位 = 11 表示 32 位指令'));
  return {
    format: (RV_FORMAT_HINT[opcode] || '自定义') + ' · 32 位',
    bits: 32, word: w, fields: out
  };
}

/** 压缩（16 位）指令的字段拆解 */
function riscvCFields(half, opts) {
  const i = half & 0xffff;
  const bits = (hi, lo) => (i >>> lo) & ((1 << (hi - lo + 1)) - 1);
  const R = (n) => xreg(n, opts);
  const F_ = (name, hi, lo, meaning) => ({
    name: name, hi: hi, lo: lo, width: hi - lo + 1, value: bits(hi, lo),
    hex: hex(bits(hi, lo), Math.ceil((hi - lo + 1) / 4)),
    bin: bits(hi, lo).toString(2).padStart(hi - lo + 1, '0'), meaning: meaning || ''
  });
  const op = i & 3, f3 = (i >> 13) & 7;
  const out = [];
  const QUAD = { 0: '象限 0', 1: '象限 1', 2: '象限 2' };
  const names = {
    0: { 0: 'C.ADDI4SPN', 1: 'C.FLD', 2: 'C.LW', 3: 'C.LD', 5: 'C.FSD', 6: 'C.SW', 7: 'C.SD' },
    1: { 0: 'C.NOP/C.ADDI', 1: 'C.ADDIW/C.JAL', 2: 'C.LI', 3: 'C.ADDI16SP/C.LUI', 4: 'C.SRLI/C.SRAI/C.ANDI/C.SUB…', 5: 'C.J', 6: 'C.BEQZ', 7: 'C.BNEZ' },
    2: { 0: 'C.SLLI', 1: 'C.FLDSP', 2: 'C.LWSP', 3: 'C.LDSP', 4: 'C.JR/C.MV/C.ADD/C.EBREAK', 5: 'C.FSDSP', 6: 'C.SWSP', 7: 'C.SDSP' }
  };
  out.push(F_('funct3', 15, 13, (names[op] && names[op][f3]) || '—'));
  if (op === 2 && f3 === 4) {
    out.push(F_('funct4', 15, 12, '1000 = JR/MV，1001 = JALR/ADD'));
    out.push(F_('rd/rs1', 11, 7, R((i >> 7) & 0x1f)));
    out.push(F_('rs2', 6, 2, R((i >> 2) & 0x1f)));
  } else if (op === 2 || (op === 1 && (f3 === 0 || f3 === 2 || f3 === 3 || f3 === 1))) {
    out.push(F_('imm/bit12', 12, 12, '立即数最高位（符号位）'));
    out.push(F_('rd/rs1', 11, 7, R((i >> 7) & 0x1f)));
    out.push(F_('imm[4:0]', 6, 2, '低位立即数 / 移位量'));
  } else if (op === 0) {
    out.push(F_('imm[5:4|9:6|2|3]', 12, 5, '被打散的偏移/立即数'));
    out.push(F_('rd′', 4, 2, R(8 + ((i >> 2) & 7)) + '（压缩寄存器 x8–x15）'));
  } else {
    out.push(F_('imm[12:10]', 12, 10, '偏移高位'));
    out.push(F_('rs1′', 9, 7, R(8 + ((i >> 7) & 7)) + '（压缩寄存器）'));
    out.push(F_('imm[6:2]', 6, 2, '偏移低位'));
  }
  out.push(F_('op', 1, 0, QUAD[op] + '（' + op.toString(2).padStart(2, '0') + '）：低 2 位 ≠ 11 即为 16 位压缩指令'));
  return { format: '压缩（C 扩展）· 16 位', bits: 16, word: i, fields: out };
}

if (typeof module !== 'undefined') module.exports = { riscvDisassemble, decodeRiscv, riscvInsnFields };
