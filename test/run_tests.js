/* Deno 测试：在无浏览器环境下校验 ELF 解析器与 RISC-V 反汇编器
 * 运行： deno run --allow-read test/run_tests.js
 */
const files = [
  'src/util.js',
  'src/elf-const.js',
  'src/elf-enums.js',
  'src/elf-parse.js',
  'src/disasm-riscv.js',
  'src/disasm-x86.js',
  'src/app-symbols.js'
];

let src = '';
for (const f of files) src += await Deno.readTextFile(f) + '\n';

const harness = `
let PASS = 0, FAIL = 0;
const failures = [];
function eq(actual, expected, label) {
  if (String(actual) === String(expected)) { PASS++; }
  else { FAIL++; failures.push(label + '\\n    期望: ' + expected + '\\n    实际: ' + actual); }
}
function ok(cond, label) { if (cond) PASS++; else { FAIL++; failures.push(label); } }
globalThis.__report = () => ({ PASS, FAIL, failures });
`;

const tests = await Deno.readTextFile('test/tests.js');
const runner = new Function(src + harness + tests + '\nreturn __report();');
const r = runner();

console.log(`\n通过 ${r.PASS} 项，失败 ${r.FAIL} 项`);
if (r.failures.length) {
  console.log('\n失败明细:');
  for (const f of r.failures) console.log('  ✗ ' + f);
  Deno.exit(1);
} else {
  console.log('全部通过 ✅');
}
