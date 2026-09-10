/* 语法体检：把全部脚本按构建顺序拼接后交给 JS 引擎解析，
 * 可以捕获括号不匹配、重复声明、非法 token 等问题。
 * 运行： deno run --allow-read test/syntax_check.js
 */
const FILES = [
  'src/util.js', 'src/elf-const.js', 'src/elf-enums.js', 'src/elf-parse.js',
  'src/disasm-riscv.js', 'src/disasm-x86.js',
  'src/hexview.js', 'src/app-core.js', 'src/app-panels.js', 'src/app-encoding.js', 'src/app-disasm.js'
];

let src = '';
for (const f of FILES) src += await Deno.readTextFile(f) + '\n';

try {
  new Function(src);
  console.log('语法检查通过：' + FILES.length + ' 个脚本，共 ' + src.split('\n').length + ' 行');
} catch (e) {
  console.error('语法错误：' + e.message);
  const m = /<anonymous>:(\d+)/.exec(e.stack || '');
  if (m) {
    const line = +m[1];
    const lines = src.split('\n');
    for (let i = Math.max(0, line - 3); i < Math.min(lines.length, line + 2); i++)
      console.error((i + 1) + (i + 1 === line ? ' >>> ' : '     ') + lines[i]);
  }
  Deno.exit(1);
}

/* 额外检查：ID 引用一致性（JS 里用到的 #id 必须在 HTML 骨架中存在） */
const shell = await Deno.readTextFile('src/shell.html');
const ids = new Set(Array.from(shell.matchAll(/id="([^"]+)"/g)).map(m => m[1]));
const dynamic = new Set(['ov-bar', 'ov-window', 'dict-table', 'dis-sec', 'dis-func', 'dis-bytes',
  'dis-alias', 'dis-c', 'dis-more', 'dis-scroll', 'sym-table', 'sym-type', 'sym-bind', 'sym-q',
  'ins-unpin', 'dict-locate', 'ins-enum-open', 'ep-flash']);   // 由 innerHTML 动态创建
const used = new Set();
for (const f of FILES) {
  const code = await Deno.readTextFile(f);
  for (const m of code.matchAll(/\$\('#([a-zA-Z0-9_-]+)'\)/g)) used.add(m[1]);
  for (const m of code.matchAll(/getElementById\('#?([a-zA-Z0-9_-]+)'\)/g)) used.add(m[1]);
}
const missing = Array.from(used).filter(id => !ids.has(id) && !dynamic.has(id));
if (missing.length) {
  console.error('以下 id 在 shell.html 中不存在：' + missing.join(', '));
  Deno.exit(1);
}
console.log('ID 引用检查通过（静态 ' + ids.size + ' 个 id，脚本引用 ' + used.size + ' 个）');
