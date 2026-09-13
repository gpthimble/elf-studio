/* ============================================================================
 * app-refscan.js — 按地址反查引用
 *
 * 重定位表能精确表达「谁引用了谁」，但它只存在于未链接完的目标文件里。
 * 已经链接好的可执行文件（或使用链接脚本的裸机程序）里，地址早已写死，
 * 重定位项可能全部消失——此时只能从指令与数据中把地址找回来：
 *
 *   1. 指令中的直接目标：jal / 条件分支 的目标地址等于符号地址
 *   2. 高 20 位 + 低 12 位配对：lui/auipc 装载高位，随后同基址寄存器的
 *      addi/ld/st/jalr 提供低 12 位，两者合成完整地址
 *   3. 数据中的指针：数据段里 4/8 字节的字面值等于符号地址
 * ==========================================================================*/
'use strict';

/** 某段的完整反汇编（按段缓存，与其它面板共用 elf._disCache） */
function sectionInsnsCached(elf, sec) {
  elf._disCache = elf._disCache || new Map();
  if (elf._disCache.has(sec.index)) return elf._disCache.get(sec.index);
  const code = sectionBytes(elf, sec);
  const list = code.length ? disassemble(elf, sec, code, sec.sh_addr) : [];
  elf._disCache.set(sec.index, list);
  return list;
}

/** 这条指令是否「以 rd 为基址/源寄存器」使用它，并给出了 12 位偏移 */
function insnUsesBase(ins, rd) {
  if (ins.rs1 !== rd) return null;
  if (ins.memOffset !== undefined && ins.memOffset !== null) return ins.memOffset;
  if (ins.imm !== undefined && ins.imm !== null) return ins.imm;
  return null;
}

/**
 * 扫描「谁引用了这个地址」。
 * @param {object} elf
 * @param {number} target 目标虚拟地址
 * @returns {Array} 引用列表，每项含 kind / addr / fileOffset / size / text / detail
 */
function scanAddressReferences(elf, target) {
  const out = [];
  if (!elf || !elf.valid || !target) return out;
  const isCode = (s) => (s.sh_flags & 0x4) !== 0;
  const isAlloc = (s) => (s.sh_flags & 0x2) !== 0;

  for (const sec of elf.shdrs) {
    if (sec.index === 0 || sec.sh_size === 0) continue;
    if (isCode(sec)) {
      const insns = sectionInsnsCached(elf, sec);
      let pending = null;                       // 待配对的 lui / auipc
      // 高位装载「本身即完整地址」只在它没有与后续低位配成对时才成立：
      // 例如 auipc t0,0x4 的中间值可能恰好等于另一个符号的地址，
      // 而紧随其后的 addi t0,t0,-8 才把它调整到真正的目标。
      const flushHi20 = () => {
        if (pending && pending.base === (target >>> 0)) {
          out.push({
            kind: 'hi20', addr: pending.ins.addr, fileOffset: pending.ins.fileOffset,
            size: pending.ins.size,
            text: pending.ins.text, detail: '低 12 位为 0，一条指令即为完整地址'
          });
        }
      };
      for (let i = 0; i < insns.length; i++) {
        const ins = insns[i];
        // ① 直接跳转 / 分支目标
        if (ins.target === target && (ins.isJump || ins.isBranch || ins.isCall)) {
          out.push({
            kind: 'branch', addr: ins.addr, fileOffset: ins.fileOffset, size: ins.size,
            text: ins.text, detail: '跳转/分支目标就是该地址'
          });
        }
        // ② 高 20 位装载
        if (ins.hi20) {
          flushHi20();
          const base = ins.pcrel ? ((ins.addr + ins.imm) >>> 0) : (ins.imm >>> 0);
          pending = { rd: ins.rd, base: base, ins: ins, age: 0 };
          continue;
        }
        // ③ 与高 20 位配对：同基址寄存器的 12 位偏移
        if (pending) {
          pending.age++;
          const off = insnUsesBase(ins, pending.rd);
          if (off !== null) {
            const full = (pending.base + off) >>> 0;
            if (full === (target >>> 0)) {
              out.push({
                kind: 'pair', addr: ins.addr, fileOffset: ins.fileOffset, size: ins.size,
                text: ins.text,
                pairAddr: pending.ins.addr, pairFileOffset: pending.ins.fileOffset,
                pairText: pending.ins.text,
                detail: hx(pending.ins.addr) + ' 的 ' + pending.ins.text.trim() +
                  '（高 20 位）与本条的低 12 位 ' + off + ' 合成 ' + hx(full)
              });
            }
            pending = null;                       // 一条高位只配一次低位
            continue;
          }
          // 同一个寄存器被其它指令改写 → 配对失效
          if (ins.rd === pending.rd && ins.rs1 !== pending.rd) { flushHi20(); pending = null; }
          else if (pending.age > 8) { flushHi20(); pending = null; }
        }
      }
      flushHi20();
    } else if (sec.sh_type === 8) {
      continue;                                   // NOBITS 没有文件字节
    } else if (isAlloc(sec)) {
      // ④ 数据中的指针
      const bytes = sectionBytes(elf, sec);
      const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      const sizes = elf.is64 ? [8] : [4];
      for (const size of sizes) {
        for (let o = 0; o + size <= bytes.length; o += size) {
          const v = size === 8 ? Number(dv.getBigUint64(o, elf.le)) : dv.getUint32(o, elf.le);
          if (v !== (target >>> 0)) continue;
          out.push({
            kind: 'data', addr: sec.sh_addr + o, fileOffset: sec.sh_offset + o, size: size,
            text: hx(v) + '（' + size + ' 字节字面值）',
            detail: '位于 ' + sec.name + ' 的 +' + hx(o) + '，是一个指向该地址的指针'
          });
        }
      }
    }
  }
  return out;
}

const REF_KIND_LABEL = {
  branch: '跳转/分支',
  hi20: '高位装载',
  pair: '高低位配对',
  data: '数据指针'
};
