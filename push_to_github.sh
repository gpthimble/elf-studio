#!/bin/sh
# ============================================================================
# 把本项目推送到 GitHub，并开启 GitHub Pages 供任何人直接在线使用。
#
# 前置条件：
#   1) 已安装 GitHub CLI（brew install gh）
#   2) 已登录（gh auth login）——必须是本人操作，脚本不会代你输入凭据
#
# 用法：
#   sh push_to_github.sh [仓库名] [public|private]
#   默认： 仓库名 elf-studio，可见性 public
#   （GitHub Pages 在私有仓库上需要付费计划，因此默认 public）
# ============================================================================
set -e
cd "$(dirname "$0")"

REPO_NAME="${1:-elf-studio}"
VISIBILITY="${2:-public}"

command -v gh >/dev/null 2>&1 || {
  echo "未找到 gh。请先执行：brew install gh && gh auth login" >&2
  exit 1
}
gh auth status >/dev/null 2>&1 || {
  echo "gh 尚未登录。请先执行：gh auth login" >&2
  exit 1
}

OWNER="$(gh api user --jq .login)"
echo "① 账号：$OWNER"

if [ ! -d .git ]; then
  echo "② 初始化本地仓库"
  git init -b main >/dev/null
  git add -A
  git -c user.name="${GIT_AUTHOR_NAME:-$(gh api user --jq .name 2>/dev/null || echo "$OWNER")}" \
      -c user.email="${GIT_AUTHOR_EMAIL:-$OWNER@users.noreply.github.com}" \
      commit -m "ELF Studio：RISC-V ELF 结构可视化分析器（首版）" >/dev/null
fi
echo "② 本地提交：$(git rev-parse --short HEAD)"

if gh repo view "$OWNER/$REPO_NAME" >/dev/null 2>&1; then
  echo "③ 远端仓库已存在，直接推送"
  git remote get-url origin >/dev/null 2>&1 || git remote add origin "https://github.com/$OWNER/$REPO_NAME.git"
  git push -u origin main
else
  echo "③ 创建仓库 $OWNER/$REPO_NAME（$VISIBILITY）并推送"
  gh repo create "$REPO_NAME" "--$VISIBILITY" --source=. --remote=origin \
     --description "纯前端 ELF 结构可视化分析器：多色块 Hex、字节级探针、枚举字典、RISC-V 反汇编与指令位域对照" \
     --push
fi

echo "④ 开启 GitHub Pages（分支 main / 根目录）"
if gh api "repos/$OWNER/$REPO_NAME/pages" >/dev/null 2>&1; then
  gh api -X PUT "repos/$OWNER/$REPO_NAME/pages" \
     -f "source[branch]=main" -f "source[path]=/" >/dev/null || true
else
  gh api -X POST "repos/$OWNER/$REPO_NAME/pages" \
     -f "source[branch]=main" -f "source[path]=/" >/dev/null || true
fi

URL="https://$OWNER.github.io/$REPO_NAME/"
echo
echo "完成 ✅"
echo "  仓库地址：https://github.com/$OWNER/$REPO_NAME"
echo "  在线使用：$URL        （首次部署需要 1–2 分钟生效）"
echo
echo "提示：以后更新后，重新执行 python3 build.py && git add -A && git commit -m 更新 && git push 即可自动重新部署。"
