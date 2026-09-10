#!/bin/sh
# 一键完整验证：生成夹具 → 单元测试 → 语法/ID 检查 → 构建单文件产物
set -e
cd "$(dirname "$0")/.."

DENO="${DENO:-deno}"
command -v "$DENO" >/dev/null 2>&1 || DENO=/opt/homebrew/bin/deno

echo "① 生成测试夹具（含手工构造的 RISC-V ELF 与 clang 交叉编译的 x86-64 ELF）"
python3 test/make_fixture.py

echo
echo "② 运行单元测试（ELF 解析 / RISC-V 反汇编 / x86 反汇编 / 枚举字典）"
"$DENO" run --allow-read test/run_tests.js

echo
echo "③ 语法与 DOM 引用检查"
"$DENO" run --allow-read test/syntax_check.js

echo
echo "④ 打包单文件产物"
python3 build.py
