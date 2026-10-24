#!/usr/bin/env bash
set -euo pipefail
[ "$(uname -s)" = Linux ] || { echo "此脚本仅适用于 Linux。"; exit 1; }
SOURCE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${XDG_DATA_HOME:-$HOME/.local/share}/ClaudeGuard"
mkdir -p "$TARGET"
[ "$SOURCE_DIR" != "$TARGET" ] || { echo "请从源码目录运行安装器。"; exit 1; }
python3 -m venv "$TARGET/venv"
"$TARGET/venv/bin/python" -m pip install -r "$SOURCE_DIR/portable/requirements.txt"
cp -R "$SOURCE_DIR/portable" "$SOURCE_DIR/src" "$SOURCE_DIR/native" "$SOURCE_DIR/scripts" "$TARGET/"
mkdir -p "$HOME/.local/bin" "${XDG_DATA_HOME:-$HOME/.local/share}/applications"
# Use Python to quote paths without treating them as shell source.
"$TARGET/venv/bin/python" - "$TARGET" "$HOME/.local/bin/claudeguard" <<'PY'
import sys,shlex
from pathlib import Path
root=Path(sys.argv[1])
launcher=Path(sys.argv[2])
launcher.write_text('#!/bin/sh\nexec '+shlex.quote(str(root/'venv/bin/python'))+' '+shlex.quote(str(root/'portable/main.py'))+' "$@"\n')
launcher.chmod(0o755)
PY
"$TARGET/venv/bin/python" - "$TARGET" "${XDG_DATA_HOME:-$HOME/.local/share}/applications/claudeguard.desktop" <<'PY'
import sys
from pathlib import Path
root=Path(sys.argv[1])
def quote(value):
    return '"'+str(value).replace('\\','\\\\').replace('"','\\"').replace('`','\\`').replace('$','\\$').replace('%','%%')+'"'
Path(sys.argv[2]).write_text('[Desktop Entry]\nType=Application\nName=ClaudeGuard\nComment=出口 IP 白名单保护\nExec='+quote(root/'venv/bin/python')+' '+quote(root/'portable/main.py')+' gui\nTerminal=false\nCategories=Utility;\n')
PY
echo "安装完成。运行 $HOME/.local/bin/claudeguard gui 设置白名单、检测方式和原始程序路径。"
echo "需要图形界面时，请确保系统已安装 tkinter（Debian/Ubuntu 通常为 python3-tk）。"
echo "登录自启动可在设置窗口开启，也可运行 claudeguard autostart enable。"
