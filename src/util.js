/* ============================================================================
 * util.js — 纯函数工具（不依赖 DOM，便于在 Node/Deno 中直接测试）
 * ==========================================================================*/
'use strict';

function esc(s) {
  return String(s === undefined || s === null ? '' : s).replace(/[&<>"]/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
  });
}

function hx(n, pad) {
  if (n === null || n === undefined || isNaN(n)) return '—';
  const s = Math.abs(Math.trunc(n)).toString(16);
  return (n < 0 ? '-0x' : '0x') + s.padStart(pad || 0, '0');
}

function byteHex(b) { return b.toString(16).padStart(2, '0').toUpperCase(); }

function fmtSize(n) {
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(n < 10240 ? 1 : 0) + ' KiB';
  return (n / 1048576).toFixed(2) + ' MiB';
}

function fmtComma(n) {
  return (n === null || n === undefined || !isFinite(n)) ? '—' : Number(n).toLocaleString('en-US');
}

function kindName(k) { return (typeof KIND_LABEL !== 'undefined' && KIND_LABEL[k]) || k; }

/* ---------------------------------------------------------------------------
 * 字节组的多字节序解读
 * 从一个字节偏移开始，把后面的字节按「文件字节序」和「相反的字节序」分别解读成
 * 人类易读的数值，用于比对 LSB/MSB 两种读法下的差异。
 * 64 位整数用 BigInt 精确保留，避免超出 Number 精度后显示成近似值。
 * ------------------------------------------------------------------------- */
function interpretBytes(bytes, off, fileLE) {
  const out = { off: off, remaining: Math.max(0, bytes.length - off), rows: [], string: '' };
  if (off < 0 || off >= bytes.length) return out;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const avail = bytes.length - off;
  const f = (v) => (typeof v === 'bigint' ? v.toString() : String(v));
  const fx = (v) => (typeof v === 'bigint' ? v.toString(16) : Number(v).toString(16));
  const add = (name, size, prim, comp) => out.rows.push({
    name: name, size: size,
    prim: f(prim), comp: f(comp),
    primHex: '0x' + fx(prim), compHex: '0x' + fx(comp)
  });
  const F32 = (le) => { const v = dv.getFloat32(off, le); return isFinite(v) ? Number(v.toPrecision(7)) : String(v); };
  const F64 = (le) => { const v = dv.getFloat64(off, le); return isFinite(v) ? Number(v.toPrecision(10)) : String(v); };

  if (avail >= 1) add('u8', 1, bytes[off], bytes[off]);
  if (avail >= 2) add('u16', 2, dv.getUint16(off, fileLE), dv.getUint16(off, !fileLE));
  if (avail >= 4) {
    add('u32', 4, dv.getUint32(off, fileLE), dv.getUint32(off, !fileLE));
    add('i32', 4, dv.getInt32(off, fileLE), dv.getInt32(off, !fileLE));
    out.rows.push({
      name: 'f32', size: 4, prim: F32(fileLE), comp: F32(!fileLE),
      primHex: '', compHex: ''
    });
  }
  if (avail >= 8) {
    add('u64', 8, dv.getBigUint64(off, fileLE), dv.getBigUint64(off, !fileLE));
    add('i64', 8, dv.getBigInt64(off, fileLE), dv.getBigInt64(off, !fileLE));
    out.rows.push({ name: 'f64', size: 8, prim: F64(fileLE), comp: F64(!fileLE), primHex: '', compHex: '' });
  }
  // 以该字节开始的 C 字符串（常用于 .strtab / .dynstr / .rodata）
  let s = '';
  for (let i = off; i < Math.min(bytes.length, off + 40); i++) {
    const c = bytes[i];
    if (c === 0) break;
    if (c < 32 || c > 126) { s = ''; break; }
    s += String.fromCharCode(c);
  }
  out.string = s.length >= 3 ? s : '';
  return out;
}

/* ---------------------------------------------------------------------------
 * 字节组视图：把一个「字段大小的字节组」整理成便于和枚举值对照的几种形态
 *   · 原始字节（文件中的存储顺序）
 *   · 按另一字节序重排后的字节（例如小端文件里 05 00 00 00 → 00 00 00 05）
 *   · 两种字节序各自的数值（十进制 + 十六进制）
 *   · 二进制位串与置位列表（按位枚举的对照依据）
 * 超出文件末尾的部分按 0 补齐，并给出实际可用字节数。
 * ------------------------------------------------------------------------- */
function groupView(bytes, off, size, fileLE) {
  const avail = Math.max(0, Math.min(size, bytes.length - off));
  const raw = [];
  for (let i = 0; i < size; i++) raw.push(off + i < bytes.length ? bytes[off + i] : 0);
  const buf = new Uint8Array(size);
  for (let i = 0; i < size; i++) buf[i] = raw[i];
  const dv = new DataView(buf.buffer);
  const one = (big) => (size === 8 ? dv.getBigUint64(0, !big) : dv.getUint32(0, !big));
  // fileLE=true 表示「文件是小端」→ 主值 = 小端解读
  const prim = size === 8 ? dv.getBigUint64(0, fileLE) : (size === 4 ? dv.getUint32(0, fileLE) : (size === 2 ? dv.getUint16(0, fileLE) : buf[0]));
  const comp = size === 8 ? dv.getBigUint64(0, !fileLE) : (size === 4 ? dv.getUint32(0, !fileLE) : (size === 2 ? dv.getUint16(0, !fileLE) : buf[0]));
  const hexWidth = size * 2;
  const pad = (v) => {
    const h = (typeof v === 'bigint' ? v : BigInt(v)).toString(16);
    return '0x' + h.padStart(hexWidth, '0');
  };
  // 位串：按「数值」展开，MSB → LSB，每 8 位一组
  let bits = (typeof prim === 'bigint' ? prim : BigInt(prim)).toString(2).padStart(size * 8, '0');
  const grouped = bits.match(/.{8}/g).join(' ');
  const setBits = [];
  for (let i = 0; i < bits.length; i++) if (bits[i] === '1') setBits.push(size * 8 - 1 - i);
  return {
    size: size, avail: avail, fileLE: fileLE,
    rawHex: raw.map(function (b) { return b.toString(16).padStart(2, '0').toUpperCase(); }).join(' '),
    swappedHex: raw.slice().reverse().map(function (b) { return b.toString(16).padStart(2, '0').toUpperCase(); }).join(' '),
    prim: prim.toString(), primHex: pad(prim),
    comp: comp.toString(), compHex: pad(comp),
    bits: grouped, setBits: setBits
  };
}
