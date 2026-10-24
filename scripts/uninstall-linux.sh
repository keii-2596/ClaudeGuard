#!/usr/bin/env bash
set -euo pipefail
TARGET="${XDG_DATA_HOME:-$HOME/.local/share}/ClaudeGuard"
if [ -x "$TARGET/venv/bin/python" ] && [ -f "$TARGET/portable/main.py" ]; then
    "$TARGET/venv/bin/python" "$TARGET/portable/main.py" autostart disable
    "$TARGET/venv/bin/python" "$TARGET/portable/main.py" stop
    "$TARGET/venv/bin/python" "$TARGET/portable/main.py" network remove
fi
rm -f "$HOME/.local/bin/claudeguard" "${XDG_DATA_HOME:-$HOME/.local/share}/applications/claudeguard.desktop"
# Keep user configuration so a reinstall does not lose the whitelist.
rm -rf "$TARGET"
echo "程序已卸载，IP 白名单配置已保留。"
