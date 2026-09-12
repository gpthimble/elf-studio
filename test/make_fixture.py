#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
构造测试用的 RISC-V ELF 文件（本机没有 RISC-V 工具链，因此手工按规范拼装字节）。
生成：
  test/fixtures/hello-riscv64.elf  ELF64 / ET_EXEC / RV64GC
  test/fixtures/hello-riscv32.elf  ELF32 / ET_EXEC / RV32IMC
  test/fixtures/not-an-elf.bin     非 ELF 数据（用于错误路径测试）
"""
import os, struct

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fixtures')
os.makedirs(OUT, exist_ok=True)

# ---------------------------------------------------------------- 汇编助记器
def R(op, f3, f7, rd, rs1, rs2):
    return (f7 << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op

def I(op, f3, rd, rs1, imm):
    return ((imm & 0xfff) << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op

def S(op, f3, rs1, rs2, imm):
    return (((imm >> 5) & 0x7f) << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | ((imm & 0x1f) << 7) | op

def B(op, f3, rs1, rs2, imm):
    b12 = (imm >> 12) & 1; b11 = (imm >> 11) & 1
    b10_5 = (imm >> 5) & 0x3f; b4_1 = (imm >> 1) & 0xf
    return (b12 << 31) | (b10_5 << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | (b4_1 << 8) | (b11 << 7) | op

def U(op, rd, imm20):
    return ((imm20 & 0xfffff) << 12) | (rd << 7) | op

def J(op, rd, imm):
    b20 = (imm >> 20) & 1; b10_1 = (imm >> 1) & 0x3ff
    b11 = (imm >> 11) & 1; b19_12 = (imm >> 12) & 0xff
    return (b20 << 31) | (b19_12 << 12) | (b11 << 20) | (b10_1 << 21) | (rd << 7) | op

# 常用指令
def addi(rd, rs1, imm):  return I(0x13, 0, rd, rs1, imm)
def addiw(rd, rs1, imm): return I(0x1b, 0, rd, rs1, imm)
def slli(rd, rs1, sh):   return I(0x13, 1, rd, rs1, sh)
def srli(rd, rs1, sh):   return I(0x13, 5, rd, rs1, sh)
def srai(rd, rs1, sh):   return I(0x13, 5, rd, rs1, sh) | (0x20 << 25)
def andi(rd, rs1, imm):  return I(0x13, 7, rd, rs1, imm)
def ori(rd, rs1, imm):   return I(0x13, 6, rd, rs1, imm)
def xori(rd, rs1, imm):  return I(0x13, 4, rd, rs1, imm)
def sltiu(rd, rs1, imm): return I(0x13, 3, rd, rs1, imm)
def lui(rd, imm20):      return U(0x37, rd, imm20)
def auipc(rd, imm20):    return U(0x17, rd, imm20)
def jal(rd, off):        return J(0x6f, rd, off)
def jalr(rd, rs1, off):  return I(0x67, 0, rd, rs1, off)
def beq(a, b, off):      return B(0x63, 0, a, b, off)
def bne(a, b, off):      return B(0x63, 1, a, b, off)
def blt(a, b, off):      return B(0x63, 4, a, b, off)
def bge(a, b, off):      return B(0x63, 5, a, b, off)
def lb(rd, rs1, o):      return I(0x03, 0, rd, rs1, o)
def lw(rd, rs1, o):      return I(0x03, 2, rd, rs1, o)
def ld(rd, rs1, o):      return I(0x03, 3, rd, rs1, o)
def lbu(rd, rs1, o):     return I(0x03, 4, rd, rs1, o)
def sb(rs2, rs1, o):     return S(0x23, 0, rs1, rs2, o)
def sw(rs2, rs1, o):     return S(0x23, 2, rs1, rs2, o)
def sd(rs2, rs1, o):     return S(0x23, 3, rs1, rs2, o)
def add(rd, rs1, rs2):   return R(0x33, 0, 0x00, rd, rs1, rs2)
def sub(rd, rs1, rs2):   return R(0x33, 0, 0x20, rd, rs1, rs2)
def mul(rd, rs1, rs2):   return R(0x33, 0, 0x01, rd, rs1, rs2)
def div(rd, rs1, rs2):   return R(0x33, 4, 0x01, rd, rs1, rs2)
def rem(rd, rs1, rs2):   return R(0x33, 6, 0x01, rd, rs1, rs2)
def ecall():             return 0x00000073
def ebreak():            return 0x00100073
def ret():               return 0x00008067
def nop():               return 0x00000013
def fence_i():           return 0x0000100f
def csrrs(rd, csr, rs1): return I(0x73, 2, rd, rs1, csr)
def mret():              return 0x30200073
def wfi():               return 0x10500073
def c_addi(rd, imm):     return 0x0001 | (rd << 7) | (((imm >> 5) & 1) << 12) | (((imm & 0x1f) << 2))
def c_li(rd, imm):       return 0x4001 | (rd << 7) | (((imm >> 5) & 1) << 12) | (((imm & 0x1f) << 2))
def c_addi16sp(imm):
    f = (((imm >> 9) & 1) << 12) | (((imm >> 4) & 1) << 6) | (((imm >> 6) & 1) << 5) | (((imm >> 7) & 3) << 3) | (((imm >> 5) & 1) << 2)
    return 0x6101 | f
def c_mv(rd, rs2):       return 0x8002 | (rd << 7) | (rs2 << 2)
def c_jr(rs1):           return 0x8002 | (rs1 << 7)
def c_ret():             return 0x8082
def c_sdsp(rs2, imm):
    f = (((imm >> 3) & 7) << 10) | (((imm >> 6) & 7) << 7)
    return 0xe002 | f | (rs2 << 2)
def c_ldsp(rd, imm):
    f = (((imm >> 5) & 1) << 12) | (((imm >> 3) & 3) << 5) | (((imm >> 6) & 7) << 2)
    return 0x6002 | (rd << 7) | f
def c_swsp(rs2, imm):
    f = (((imm >> 2) & 0xf) << 9) | (((imm >> 6) & 3) << 7)
    return 0xc002 | f | (rs2 << 2)
def c_lwsp(rd, imm):
    f = (((imm >> 5) & 1) << 12) | (((imm >> 2) & 7) << 4) | (((imm >> 6) & 3) << 2)
    return 0x4002 | (rd << 7) | f

# ---------------------------------------------------------------- 程序内容
def build_text(is64):
    """返回 (字节, 每条指令的期望反汇编文本, strlen 的字节偏移, 各标签偏移)"""
    insns = []
    marks = {}

    def emit(word, text):
        insns.append([word, text])
        return len(insns) - 1

    # ---------------- main (使用压缩指令，贴近真实 GCC -Os 输出) ----------------
    emit(c_addi16sp(-32), 'c.addi16sp sp, -32')                    # 建立栈帧
    emit(c_sdsp(1, 24) if is64 else c_swsp(1, 24), 'c.sdsp ra, 24(sp)' if is64 else 'c.swsp ra, 24(sp)')
    emit(c_sdsp(8, 16) if is64 else c_swsp(8, 16), 'c.sdsp s0, 16(sp)' if is64 else 'c.swsp s0, 16(sp)')
    emit(addi(10, 0, 1), 'li a0, 1')                               # 伪指令 li
    emit(auipc(11, 0x1), 'auipc a1, 0x1000')                       # la a1, msg（pcrel 高 20 位）
    emit(addi(11, 11, -12), 'addi a1, a1, -12')                    # la a1, msg（pcrel 低 12 位）
    i_call = emit(jal(1, 0), '<call-strlen>')                      # 调用 strlen，偏移稍后回填
    emit(addi(12, 0, 42), 'li a2, 42')
    emit(mul(12, 12, 10), 'mul a2, a2, a0')                        # M 扩展：乘法
    emit(c_ldsp(1, 24) if is64 else c_lwsp(1, 24), 'c.ldsp ra, 24(sp)' if is64 else 'c.lwsp ra, 24(sp)')
    emit(addi(2, 2, 32), 'addi sp, sp, 32')
    emit(ret(), 'ret')

    # ---------------- strlen ----------------
    marks['strlen'] = len(insns)
    emit(addi(13, 0, 0), 'li a3, 0')
    marks['loop'] = len(insns)
    emit(add(14, 10, 13), 'add a4, a0, a3')
    emit(lbu(15, 14, 0), 'lbu a5, 0(a4)')
    i_beq = emit(beq(15, 0, 0), '<beqz>')
    emit(addi(13, 13, 1), 'addi a3, a3, 1')
    i_j = emit(jal(0, 0), '<j-loop>')
    marks['done'] = len(insns)
    emit(addi(10, 13, 0), 'mv a0, a3')                             # 伪指令 mv
    emit(jalr(0, 1, 0), 'ret')
    if is64:
        emit(addiw(10, 10, 0), 'addiw a0, a0, 0')
        emit(sd(10, 2, 0), 'sd a0, 0(sp)')
        emit(ld(10, 2, 0), 'ld a0, 0(sp)')
    else:
        emit(sw(10, 2, 0), 'sw a0, 0(sp)')
        emit(lw(10, 2, 0), 'lw a0, 0(sp)')
    emit(csrrs(10, 0xf14, 0), 'csrr a0, mhartid')
    emit(ebreak(), 'ebreak')

    # 计算各指令地址（16 位压缩指令占 2 字节）
    offs, addr, strlen_at = [], 0, None
    for idx, (w, _) in enumerate(insns):
        if idx == marks['strlen']:
            strlen_at = addr
        offs.append(addr)
        addr += 2 if (w & 3) != 3 else 4
    insns[i_call][0] = jal(1, strlen_at - offs[i_call])
    insns[i_call][1] = 'jal ra, ' + hex(0x10000 + strlen_at)
    insns[i_beq][0] = beq(15, 0, offs[marks['done']] - offs[i_beq])
    insns[i_beq][1] = 'beqz a5, ' + hex(0x10000 + offs[marks['done']])
    insns[i_j][0] = jal(0, offs[marks['loop']] - offs[i_j])
    insns[i_j][1] = 'j ' + hex(0x10000 + offs[marks['loop']])

    out = bytearray()
    for w, _ in insns:
        if (w & 3) != 3:
            out += struct.pack('<H', w & 0xffff)
        else:
            out += struct.pack('<I', w & 0xffffffff)
    return bytes(out), [t for _, t in insns], strlen_at

# ---------------------------------------------------------------- ELF 构造
def build_elf(bits, path, textbytes, text_asm, entry, strlen_at):
    is64 = bits == 64
    WORD = 8 if is64 else 4
    EHDR = 64 if is64 else 52
    PHDR = 56 if is64 else 32
    SHDR = 64 if is64 else 40
    SYM = 24 if is64 else 16

    # 段/节区布局（制造页对齐空隙，用于演示"未映射空隙"配色）
    text_off, text_addr = 0x1000, 0x10000
    rodata_off, rodata_addr = 0x2000, 0x11000
    data_off, data_addr = 0x3000, 0x12000
    bss_addr = 0x12100
    msg = b'Hello, RISC-V!\n\x00'
    data_bytes = struct.pack('<QQ', 0xdeadbeefcafebabe, 0x1122334455667788)
    # .riscv.attributes 编码：'A' + uleb(厂商名长度) + 厂商名 + 若干 (tag, uleb 值)
    #   Tag_arch = 5（字符串值，长度为「含结尾 NUL 的字节数」）; Tag_unaligned_access = 6
    isa = b'rv64i2p1_m2p0_a2p1_c2p0_zicsr2p0' if is64 else b'rv32i2p1_m2p0_c2p0_zicsr2p0'
    attr = (b'A' + bytes([6]) + b'riscv' + bytes([5, len(isa) + 1]) + isa + bytes([0]) +
            bytes([6, 0]) + bytes([0]))
    comment = b'GCC: (GNU) 13.2.0\x00'
    notes = struct.pack('<III', 4, 4, 3) + b'GNU\x00' + bytes([1, 2, 3, 4])  # .note.gnu.build-id

    # 符号表内容（先定符号，再排布数据节区偏移）
    cursor = 0x3100
    note_off = cursor; cursor += len(notes)
    attr_off = cursor; cursor = (cursor + len(attr) + 3) & ~3
    attr_off2 = attr_off
    comment_off = cursor; cursor += len(comment)
    sym_off = (cursor + 7) & ~7
    strtab = bytearray(b'\x00')
    def addstr(s):
        o = len(strtab); strtab.extend(s.encode() + b'\x00'); return o
    n_main = addstr('main'); n_strlen = addstr('strlen'); n_msg = addstr('msg')
    n_data = addstr('data_block'); n_file = addstr('hello.c'); n_helper = addstr('helper_local')
    shstrtab = bytearray(b'\x00')
    def shstr(s):
        o = len(shstrtab); shstrtab.extend(s.encode() + b'\x00'); return o
    secnames = ['.text', '.rodata', '.data', '.bss', '.note.gnu.build-id', '.riscv.attributes', '.comment', '.symtab', '.strtab', '.shstrtab']
    shname_off = {n: shstr(n) for n in secnames}
    # 符号表
    STB_LOCAL, STB_GLOBAL, STT_FUNC, STT_OBJECT, STT_FILE, STT_NOTYPE = 0, 1, 2, 1, 4, 0
    def sym(name_off, info, other, shndx, value, size):
        if is64:
            return struct.pack('<IBBHQQ', name_off, info, other, shndx, value, size)
        return struct.pack('<IIIBBH', name_off, value, size, info, other, shndx)
    syms = []
    syms.append(sym(0, 0, 0, 0, 0, 0))                                          # 空符号（必须存在）
    syms.append(sym(n_file, (STB_LOCAL << 4) | STT_FILE, 0, 0xfff1, 0, 0))      # 源文件名
    syms.append(sym(n_helper, (STB_LOCAL << 4) | STT_FUNC, 0, 1, text_addr + strlen_at + 0x1a, 4))
    first_global = len(syms)
    syms.append(sym(n_main, (STB_GLOBAL << 4) | STT_FUNC, 0, 1, text_addr, strlen_at))
    syms.append(sym(n_strlen, (STB_GLOBAL << 4) | STT_FUNC, 0, 1, text_addr + strlen_at, len(textbytes) - strlen_at))
    syms.append(sym(n_msg, (STB_GLOBAL << 4) | STT_OBJECT, 0, 2, rodata_addr, len(msg)))
    syms.append(sym(n_data, (STB_GLOBAL << 4) | STT_OBJECT, 2, 3, data_addr, len(data_bytes)))
    symtab = b''.join(syms)
    strtab_off = sym_off + len(symtab)

    shstrtab_off = strtab_off + len(strtab)
    shoff = (shstrtab_off + len(shstrtab) + 7) & ~7

    # ---- 段头表 ----
    sections = []
    def sec(name, type_, flags, addr, off, size, link, info, align, entsize):
        sections.append(dict(name=name, type=type_, flags=flags, addr=addr, offset=off,
                             size=size, link=link, info=info, align=align, entsize=entsize))
    SHF_WRITE, SHF_ALLOC, SHF_EXEC = 1, 2, 4
    sec('', 0, 0, 0, 0, 0, 0, 0, 0, 0)                                            # 0 NULL
    sec('.text', 1, SHF_ALLOC | SHF_EXEC, text_addr, text_off, len(textbytes), 0, 0, 4, 0)
    sec('.rodata', 1, SHF_ALLOC, rodata_addr, rodata_off, len(msg), 0, 0, 8, 0)
    sec('.data', 1, SHF_ALLOC | SHF_WRITE, data_addr, data_off, len(data_bytes), 0, 0, 8, 0)
    sec('.bss', 8, SHF_ALLOC | SHF_WRITE, bss_addr, data_off + len(data_bytes), 0x100, 0, 0, 8, 0)
    sec('.note.gnu.build-id', 7, SHF_ALLOC, 0x13000, note_off, len(notes), 0, 0, 4, 0)
    sec('.riscv.attributes', 0x70000003, 0, 0, attr_off2, len(attr), 0, 0, 1, 0)
    sec('.comment', 1, 0x30, 0, comment_off, len(comment), 0, 0, 1, 1)
    sec('.symtab', 2, 0, 0, sym_off, len(symtab), 9, first_global, WORD, SYM)
    sec('.strtab', 3, 0, 0, strtab_off, len(strtab), 0, 0, 1, 0)
    sec('.shstrtab', 3, 0, 0, shstrtab_off, len(shstrtab), 0, 0, 1, 0)

    def pack_shdr(s):
        if is64:
            return struct.pack('<IIQQQQIIQQ', shname_off.get(s['name'], 0) if s['name'] else 0, s['type'], s['flags'],
                               s['addr'], s['offset'], s['size'], s['link'], s['info'], s['align'], s['entsize'])
        return struct.pack('<IIIIIIIIII', shname_off.get(s['name'], 0) if s['name'] else 0, s['type'], s['flags'],
                           s['addr'], s['offset'], s['size'], s['link'], s['info'], s['align'], s['entsize'])

    # ---- 程序头表 ----
    PT_LOAD, PT_GNU_STACK, PT_GNU_RELRO, PT_NOTE, PT_PHDR = 1, 0x6474e551, 0x6474e552, 4, 6
    PF_X, PF_W, PF_R = 1, 2, 4
    phdrs = [
        (PT_PHDR, PF_R, EHDR, text_addr - 0x1000 + EHDR, 0, 4 * PHDR, 4 * PHDR, 8),
        (PT_LOAD, PF_R | PF_X, 0, 0x10000, 0x10000, 0x2000, 0x2000, 0x1000),
        (PT_LOAD, PF_R | PF_W, 0x2000, 0x11000, 0x11000, 0x1200, 0x1300, 0x1000),
        (PT_NOTE, PF_R, note_off, 0x13000, 0x13000, len(notes), len(notes), 4),
        (PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 0, 0, 0x10),
        (PT_GNU_RELRO, PF_R, 0x2000, 0x11000, 0x11000, 0x1000, 0x1000, 1),
    ]
    def pack_phdr(p):
        t, fl, off, va, pa, fsz, msz, al = p
        if is64:
            return struct.pack('<IIQQQQQQ', t, fl, off, va, pa, fsz, msz, al)
        return struct.pack('<IIIIIIII', t, off, va, pa, fsz, msz, fl, al)

    e_flags = 0x5 if is64 else 0x3   # EF_RISCV_RVC(1) | FLOAT_ABI_DOUBLE(4) / FLOAT_ABI_SINGLE(2)
    total = shoff + len(sections) * SHDR
    buf = bytearray(total)

    def put(off, data):
        buf[off:off + len(data)] = data

    put(text_off, textbytes)
    put(rodata_off, msg)
    put(data_off, data_bytes)
    put(note_off, notes)
    put(attr_off2, attr)
    put(comment_off, comment)
    put(sym_off, symtab)
    put(strtab_off, bytes(strtab))
    put(shstrtab_off, bytes(shstrtab))
    for i, s in enumerate(sections):
        put(shoff + i * SHDR, pack_shdr(s))
    for i, p in enumerate(phdrs):
        put(EHDR + i * PHDR, pack_phdr(p))

    # ---- ELF 头 ----
    ident = bytearray(16)
    ident[0:4] = b'\x7fELF'
    ident[4] = 1 if bits == 32 else 2
    ident[5] = 1        # little endian
    ident[6] = 1        # version
    ident[7] = 3        # ELFOSABI_LINUX
    ident[8] = 0
    if is64:
        eh = struct.pack('<16sHHIQQQIHHHHHH', bytes(ident), 2, 243, 1, entry, EHDR, shoff,
                         e_flags, EHDR, PHDR, len(phdrs), SHDR, len(sections), 10)
    else:
        eh = struct.pack('<16sHHIIIIIHHHHHH', bytes(ident), 2, 243, 1, entry, EHDR, shoff,
                         e_flags, EHDR, PHDR, len(phdrs), SHDR, len(sections), 10)
    put(0, eh)

    with open(path, 'wb') as f:
        f.write(bytes(buf))
    return dict(size=len(buf), sections=[s['name'] for s in sections], first_global=first_global,
                text_addr=text_addr, strtab_off=strtab_off, sym_off=sym_off)


def main():
    for bits in (64, 32):
        text, asm, strlen_at = build_text(bits == 64)
        path = os.path.join(OUT, 'hello-riscv%d.elf' % bits)
        info = build_elf(bits, path, text, asm, 0x10000, strlen_at)
        print('%s  %d 字节, %d 个段, .text %d 字节' % (path, info['size'], len(info['sections']), len(text)))
    make_big()
    make_x86()
    with open(os.path.join(OUT, 'not-an-elf.bin'), 'wb') as f:
        f.write(b'This is definitely not an ELF file, just some plain text bytes.\n' * 4)
    # 记录期望的反汇编文本（供 Deno 测试对照）
    text, asm, _ = build_text(True)
    with open(os.path.join(OUT, 'expected-riscv64.txt'), 'w') as f:
        f.write('\n'.join(asm) + '\n')
    print('fixtures 生成完成 →', OUT)


def make_x86():
    """用本机 clang 交叉编译出一个真实的 x86-64 ELF 目标文件（ET_REL），
       并用 llvm-objdump 记录指令边界作为「金标准」，
       用于交叉验证 x86 反汇编器的指令长度解码是否正确。"""
    import shutil, subprocess
    clang = shutil.which('clang')
    objdump = shutil.which('llvm-objdump') or '/Library/Developer/CommandLineTools/usr/bin/llvm-objdump'
    if not clang or not os.path.exists(objdump):
        print('跳过 x86 夹具：未找到 clang / llvm-objdump')
        return
    cs = os.path.join(OUT, 'x86-64-sample.c')
    with open(cs, 'w') as f:
        f.write('int helper(int x) { return x * 3 + 1; }\n'
                'int compute(int a, int b) {\n'
                '  int s = 0;\n'
                '  for (int i = 0; i < a; i++) s += helper(i) ^ b;\n'
                '  return s - (b << 2);\n'
                '}\n'
                'long sum_bytes(const unsigned char *p, long n) {\n'
                '  long s = 0;\n'
                '  while (n--) s += *p++;\n'
                '  return s;\n'
                '}\n')
    obj = os.path.join(OUT, 'x86-64-sample.o')
    cmd = [clang, '-target', 'x86_64-unknown-linux-gnu', '-c', '-O1', '-ffreestanding', '-o', obj, cs]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print('跳过 x86 夹具：clang 编译失败\n' + r.stderr[:400])
        return
    gold = os.path.join(OUT, 'x86-64-sample.disasm.txt')
    with open(gold, 'w') as f:
        subprocess.run([objdump, '-d', '--no-show-raw-insn', obj], stdout=f, stderr=subprocess.DEVNULL)
    print('%s  %d 字节（真实 clang 产物），金标准：%s' % (obj, os.path.getsize(obj), os.path.basename(gold)))


def make_big():
    """生成一个较大的、结构完整的 ELF（约 130 KB）：
       200 个函数 / 400+ 符号 / 40+ 段 / 重定位表 / .dynamic，
       用于验证大文件滚动性能与各面板在真实规模下的表现。"""
    import random
    random.seed(42)
    NFUNC, PER_FUNC = 200, 34

    # ---------------- .text：200 个函数，混用压缩与 32 位指令 ----------------
    code = bytearray()
    entry = []
    for f in range(NFUNC):
        entry.append(len(code))
        code += struct.pack('<H', c_addi16sp(-48))            # 16 位压缩：建立栈帧
        code += struct.pack('<H', c_sdsp(1, 40))              # 16 位压缩：保存 ra
        code += struct.pack('<I', lui(5, 0x12345 + f))
        for k in range(PER_FUNC - 4):
            r = random.random()
            if r < 0.18:
                code += struct.pack('<I', addi(10 + (k % 8), 11, random.randint(-2048, 2047)))
            elif r < 0.36:
                code += struct.pack('<I', add(12, 10, 11))
            elif r < 0.50:
                code += struct.pack('<I', lw(13, 2, 4 * (k % 16)))
            elif r < 0.62:
                code += struct.pack('<I', sw(13, 2, 4 * (k % 16)))
            elif r < 0.74:
                code += struct.pack('<I', beq(13, 14, 8))
            elif r < 0.86:
                code += struct.pack('<I', slli(15, 15, k % 32))
            else:
                code += struct.pack('<H', c_li(9, (k % 30) - 15))
        code += struct.pack('<H', c_ldsp(1, 40))
        code += struct.pack('<I', addi(2, 2, 48))
        code += struct.pack('<I', ret())
    text = bytes(code)

    rodata = b''.join(('str_%04d: 用于测试的字符串常量 #%d\x00' % (i, i)).encode('utf-8') for i in range(200))
    data = bytes(random.getrandbits(8) for _ in range(4096))
    debug_info = bytes(random.getrandbits(8) for _ in range(30000))
    debug_line = bytes(random.getrandbits(8) for _ in range(12000))

    EHDR, PHDR, SHDR, SYM = 64, 56, 64, 24
    text_off, text_addr = 0x1000, 0x10000
    rodata_off, rodata_addr = 0x8000, 0x20000
    data_off, data_addr = 0xC000, 0x30000
    dbg_off = 0xD000
    line_off = dbg_off + len(debug_info)
    attr_off = line_off + len(debug_line)
    isa = b'rv64i2p1_m2p0_a2p1_c2p0_zicsr2p0'
    attr = b'A' + bytes([6]) + b'riscv' + bytes([5, len(isa) + 1]) + isa + bytes([0]) + bytes([6, 0]) + bytes([0])
    note_off = (attr_off + len(attr) + 3) & ~3
    notes = struct.pack('<III', 4, 12, 3) + b'GNU\x00' + bytes([0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C])
    comment_off = note_off + len(notes)
    comment = b'GCC: (GNU) 13.2.0\x00'

    # ---------------- 符号表 ----------------
    sym_off = (comment_off + len(comment) + 7) & ~7
    strtab = bytearray(b'\x00')

    def addstr(s):
        o = len(strtab)
        strtab.extend(s.encode() + b'\x00')
        return o

    n_file = addstr('big.c')
    fname_off = [addstr('func_%04d' % i) for i in range(NFUNC)]
    lbl_off = [addstr('lbl_%04d' % i) for i in range(NFUNC)]
    n_str = addstr('str_blob')
    n_data = addstr('data_blob')
    n_arr = addstr('jump_table')
    n_undef = addstr('puts')

    syms = [struct.pack('<IBBHQQ', 0, 0, 0, 0, 0, 0),
            struct.pack('<IBBHQQ', n_file, (0 << 4) | 4, 0, 0xfff1, 0, 0)]
    for i in range(NFUNC):                                    # 局部标签
        syms.append(struct.pack('<IBBHQQ', lbl_off[i], 0 | 0, 0, 1, text_addr + entry[i], 8))
    first_global = len(syms)
    for i in range(NFUNC):                                    # 全局函数
        syms.append(struct.pack('<IBBHQQ', fname_off[i], (1 << 4) | 2, 0, 1, text_addr + entry[i], 0x100))
    syms.append(struct.pack('<IBBHQQ', n_str, (1 << 4) | 1, 0, 2, rodata_addr, len(rodata)))
    syms.append(struct.pack('<IBBHQQ', n_data, (1 << 4) | 1, 2, 3, data_addr, len(data)))
    syms.append(struct.pack('<IBBHQQ', n_arr, (1 << 4) | 1, 0, 4, data_addr + 0x800, 0x100))
    syms.append(struct.pack('<IBBHQQ', n_undef, (1 << 4) | 2, 0, 0, 0, 0))     # 未定义（外部调用）
    undef_idx = len(syms) - 1
    symtab = b''.join(syms)
    strtab_off = sym_off + len(symtab)

    # ---------------- 重定位表 ----------------
    rela_text = bytearray()
    for i in range(0, NFUNC, 10):
        r_off = text_addr + entry[i] + 8
        sym_idx = first_global + (i + 1) % NFUNC
        rtype = (18, 23, 19)[i % 3]          # R_RISCV_CALL / PCREL_HI20 / CALL_PLT
        rela_text += struct.pack('<QQq', r_off, (sym_idx << 32) | rtype, 0)
    # 外部调用：引用未定义符号 puts（这类「需要重定位的引用」最典型的场景）
    ext_idx = [0, 3, 7]
    for i, fi in enumerate(ext_idx):
        r_off = text_addr + entry[fi] + 8
        rela_text += struct.pack('<QQq', r_off, (undef_idx << 32) | 19, 0)   # R_RISCV_CALL_PLT
    rela_dyn = bytearray()
    for i in range(16):
        rela_dyn += struct.pack('<QQq', data_addr + i * 8, 3, 0x100 + i * 8)   # R_RISCV_RELATIVE
    rela_text_off = strtab_off + len(strtab)
    rela_dyn_off = rela_text_off + len(rela_text)

    # ---------------- .dynamic 与 .dynstr ----------------
    dyn_off = (rela_dyn_off + len(rela_dyn) + 7) & ~7
    dynstr = b'\x00libc.so.6\x00str_blob\x00'
    dynamic = b''.join([
        struct.pack('<QQ', 1, 1),                # DT_NEEDED -> "libc.so.6"
        struct.pack('<QQ', 5, 0x50000),          # DT_STRTAB
        struct.pack('<QQ', 6, 0x51000),          # DT_SYMTAB
        struct.pack('<QQ', 10, len(dynstr)),     # DT_STRSZ
        struct.pack('<QQ', 0, 0),                # DT_NULL
    ])
    dynstr_off = dyn_off + len(dynamic)

    # ---------------- 段表 ----------------
    shstrtab = bytearray(b'\x00')

    def shstr(s):
        o = len(shstrtab)
        shstrtab.extend(s.encode() + b'\x00')
        return o

    extra = ['.debug_extra_%02d' % i for i in range(30)]
    names = ['', '.text', '.rodata', '.data', '.bss', '.debug_info', '.debug_line',
             '.riscv.attributes', '.note.gnu.build-id', '.comment',
             '.rela.text', '.rela.dyn', '.dynamic', '.dynstr', '.symtab', '.strtab', '.shstrtab'] + extra
    name_off = {n: (shstr(n) if n else 0) for n in names}
    shstrtab_len = len(shstrtab)
    shstrtab_off = dynstr_off + len(dynstr)
    shoff = (shstrtab_off + shstrtab_len + 7) & ~7

    idx = {n: i for i, n in enumerate(names)}
    secdefs = [(0, 0, 0, 0, 0, 0, 0, 0),
               (idx['.text'], 1, 6, text_addr, text_off, len(text), 4, 0),
               (0, 1, 2, rodata_addr, rodata_off, len(rodata), 16, 0),
               (0, 1, 3, data_addr, data_off, len(data), 16, 0),
               (0, 8, 3, 0x31000, data_off + len(data), 0x2000, 16, 0),
               (0, 1, 0, 0, dbg_off, len(debug_info), 1, 0),
               (0, 1, 0, 0, line_off, len(debug_line), 1, 0),
               (0, 0x70000003, 0, 0, attr_off, len(attr), 1, 0),
               (0, 7, 2, 0, note_off, len(notes), 4, 0),
               (0, 1, 0x30, 0, comment_off, len(comment), 1, 1),
               (idx['.rela.text'], 4, 0, 0, rela_text_off, len(rela_text), 8, 24),
               (idx['.rela.dyn'], 4, 0, 0, rela_dyn_off, len(rela_dyn), 8, 24),
               (idx['.dynamic'], 6, 3, 0x40000, dyn_off, len(dynamic), 8, 16),
               (idx['.dynstr'], 3, 2, 0x50000, dynstr_off, len(dynstr), 1, 0),
               (idx['.symtab'], 2, 0, 0, sym_off, len(symtab), 8, 24),
               (idx['.strtab'], 3, 0, 0, strtab_off, len(strtab), 1, 0),
               (idx['.shstrtab'], 3, 0, 0, shstrtab_off, shstrtab_len, 1, 0)]
    # 段位序：把名字数组顺序与索引对齐（前 17 项与 names 前 17 项一一对应）
    secs = []
    for i, n in enumerate(names):
        if i < len(secdefs):
            secs.append(secdefs[i])
        else:
            secs.append((0, 1, 0, 0, dbg_off + (i * 350) % 8000, 700, 1, 0))
    # 修正 sh_name / sh_link / sh_info
    fixed = []
    for i, item in enumerate(secs):
        stype = item[1]
        link = 0
        info = 0
        if stype == 2:                     # .symtab -> .strtab
            link, info = idx['.strtab'], first_global
        elif stype == 4 and i == idx['.rela.text']:
            link, info = idx['.symtab'], idx['.text']
        elif stype == 4:
            link = idx['.symtab']
        elif stype == 6:
            link = idx['.dynstr']
        fixed.append((name_off[names[i]], stype, item[2], item[3], item[4], item[5], link, info, item[6], item[7]))
    nsec = len(fixed)
    total = shoff + nsec * SHDR
    buf = bytearray(total)

    def put(off, dta):
        buf[off:off + len(dta)] = dta

    put(text_off, text); put(rodata_off, rodata); put(data_off, data)
    put(dbg_off, debug_info); put(line_off, debug_line); put(attr_off, attr)
    put(note_off, notes); put(comment_off, comment)
    put(sym_off, symtab); put(strtab_off, bytes(strtab))
    put(rela_text_off, bytes(rela_text)); put(rela_dyn_off, bytes(rela_dyn))
    put(dyn_off, dynamic); put(dynstr_off, dynstr)
    put(shstrtab_off, bytes(shstrtab))
    for i, s in enumerate(fixed):
        put(shoff + i * SHDR, struct.pack('<IIQQQQIIQQ', *s))

    phdrs = [(1, 5, 0, text_addr, text_addr, 0x8000, 0x8000, 0x1000),
             (1, 4, 0x8000, rodata_addr, rodata_addr, 0x3000, 0x3000, 0x1000),
             (1, 6, 0xC000, data_addr, data_addr, 0x1000, 0x3000, 0x1000),
             (2, 6, dyn_off, 0x40000, 0x40000, len(dynamic), len(dynamic), 8),
             (0x6474e551, 6, 0, 0, 0, 0, 0, 0x10)]
    for i, p in enumerate(phdrs):
        put(EHDR + i * PHDR, struct.pack('<IIQQQQQQ', *p))

    ident = bytearray(16)
    ident[0:4] = b'\x7fELF'
    ident[4] = 2; ident[5] = 1; ident[6] = 1; ident[7] = 3
    put(0, struct.pack('<16sHHIQQQIHHHHHH', bytes(ident), 3, 243, 1, text_addr + entry[0],
                       EHDR, shoff, 0x5, EHDR, PHDR, len(phdrs), SHDR, nsec, idx['.shstrtab']))

    path = os.path.join(OUT, 'big-riscv64.elf')
    with open(path, 'wb') as f:
        f.write(bytes(buf))
    print('%s  %d 字节, %d 个段, %d 个符号, %d 个重定位, .text %d 字节 / %d 个函数' %
          (path, len(buf), nsec, len(syms), len(rela_text) // 24 + len(rela_dyn) // 24, len(text), NFUNC))


if __name__ == '__main__':
    main()
