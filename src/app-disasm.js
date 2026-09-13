/* ============================================================================
 * app-disasm.js — 反汇编视图：指令流、符号标注、与 Hex 视图双向联动
 * ==========================================================================*/
'use strict';

function executableSections(elf) {
  return elf.shdrs.filter(function (s) {
    return s.index !== 0 && s.sh_type !== 8 && s.sh_size > 0 &&
      ((s.sh_flags & 0x4) || /^\.(text|init|fini|plt|iplt)/.test(s.name));
  });
}

function openDisasmAt(vaddr, sym, secName) {
  const elf = S.elf;
  if (!elf) return;
  const r = vaddrToOffset(elf, vaddr);
  if (secName && elf.sectionByName.get(secName)) S.disasm.sec = secName;
  else if (r && r.section) S.disasm.sec = r.section.name;
  else {
    const sec = elf.shdrs.find(function (s) {
      return (s.sh_flags & 0x4) && vaddr >= s.sh_addr && vaddr < s.sh_addr + s.sh_size;
    });
    if (sec) S.disasm.sec = sec.name;
  }
  S.disasm.start = vaddr;
  S.disasm.limit = 400;
  switchTab('disasm');
  renderDisasm();
  setTimeout(function () {
    const el = $('.dis-line[data-addr="' + vaddr + '"]');
    if (el) {
      el.scrollIntoView({ block: 'center', behavior: 'smooth' });
      markDisasmLineForAddress(vaddr);
    }
  }, 60);
  if (r) selectBytes(r.offset, 4, { smooth: true });
  setStatus('反汇编定位：' + (sym ? sym.name + ' ' : '') + hx(vaddr));
}

function markDisasmLineForAddress(addr) {
  const el = $('.dis-line[data-addr="' + addr + '"]');
  if (el) markDisasmSelected(el);
}

/** Hex 视图选中变化 → 反向高亮反汇编中对应的指令行 */
function markDisasmLineForOffset(off) {
  const pane = $('#pane-disasm');
  if (!pane || !pane.classList.contains('on')) return;
  const el = $('.dis-line[data-off="' + off + '"]');
  if (el) markDisasmSelected(el);
}

/** 统一「当前选中指令」的外观：同一条指令在两侧保持一致的高亮 */
function markDisasmSelected(el) {
  const pane = el.closest('#pane-disasm') || document;
  $$('.dis-line.sel, .dis-line.hl', pane).forEach(function (x) { x.classList.remove('sel', 'hl'); });
  el.classList.add('sel', 'hl');
  S.disasm.selectedAddr = +el.dataset.addr;
}

/* ---------------------------- 启动 ----------------------------
 * 放在脚本最后：此时所有函数与类都已定义完毕，boot() 可以安全装配界面。
 */
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
else boot();
