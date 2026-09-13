#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把 src/ 下的 HTML 骨架、CSS、JS 打包成单文件 elf-studio.html。
单文件形式可以直接双击用浏览器打开（无需本地服务器），也便于分发。

用法：
    python3 build.py            # 生成 elf-studio.html
    python3 build.py --demo     # 同时把示例 ELF 以 base64 内嵌进产物
"""
import base64, os, sys, time

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(ROOT, 'src')

# JS 拼接顺序（后者依赖前者，全部为普通脚本，共享同一作用域）
JS_FILES = [
    'util.js',          # 纯工具函数
    'elf-const.js',     # 常量、枚举字典、字段文档
    'elf-enums.js',     # 枚举取值解码
    'elf-parse.js',     # ELF 解析器
    'disasm-riscv.js',  # RISC-V 反汇编
    'disasm-x86.js',    # x86/x86-64 反汇编（简化）
    'disasm-dispatch.js',  # 按架构分派反汇编
    'hexview.js',       # 多色块 Hex 视图
    'app-core.js',      # 状态、探针、概览面板
    'app-panels.js',    # 各结构面板
    'app-symbols.js',   # 符号表项解析与引用关系面板
    'app-refscan.js',   # 按地址反查引用（已链接文件）
    'app-relocs.js',    # 重定位项解析与引用链路面板
    'app-encoding.js',  # 指令位域对照面板（二进制 ↔ 助记符）
    'app-disasm.js',    # 反汇编视图
]


def read(name, folder=SRC):
    with open(os.path.join(folder, name), 'r', encoding='utf-8') as f:
        return f.read()


def build(embed_demo=True, out_name='elf-studio.html'):
    shell = read('shell.html')
    css = read('style.css')

    js_parts = []
    for name in JS_FILES:
        js_parts.append('/* ===== src/%s ===== */\n' % name + read(name))
    js = '\n'.join(js_parts)

    demo = ''
    if embed_demo:
        fixture = os.path.join(ROOT, 'test', 'fixtures', 'hello-riscv64.elf')
        if os.path.exists(fixture):
            with open(fixture, 'rb') as f:
                b64 = base64.b64encode(f.read()).decode('ascii')
            demo = ('/* 内置示例：手工构造的 RV64 可执行文件（见 test/make_fixture.py），'
                    '用于零依赖体验全部功能 */\nwindow.DEMO_ELF_BASE64 = "%s";' % b64)

    html = shell.replace('/*__CSS__*/', css)
    html = html.replace('/*__DEMO__*/', demo)
    html = html.replace('/*__JS__*/', js)

    out = os.path.join(ROOT, out_name)
    with open(out, 'w', encoding='utf-8') as f:
        f.write(html)
    # 同一份内容再写一份 index.html：GitHub Pages / 任意静态托管都能直接以根路径访问
    index = os.path.join(ROOT, 'index.html')
    if os.path.abspath(index) != os.path.abspath(out):
        with open(index, 'w', encoding='utf-8') as f:
            f.write(html)
    kb = os.path.getsize(out) / 1024.0
    print('已生成 %s 与 index.html （%.1f KB，%s）' % (out, kb, time.strftime('%H:%M:%S')))
    return out


if __name__ == '__main__':
    build(embed_demo=('--no-demo' not in sys.argv))
