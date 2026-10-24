#!/usr/bin/env bash
#
# ClaudeGuard installer.
#
# Works two ways from the SAME file:
#   • One-liner:   bash -c "$(curl -fsSL https://raw.githubusercontent.com/keii-2596/ClaudeGuard/main/install.sh)"
#   • Local:       ./install.sh   (from a git checkout or unpacked archive)
#
# When run via curl|bash there's no local source tree, so the script first
# fetches the repo, then compiles the Swift menu bar app + C helper NATIVELY on
# this Mac (Apple Silicon or Intel). Locally-compiled binaries carry no
# quarantine flag, so Gatekeeper never blocks them — no Apple Developer account,
# no code-signing, no notarization required.
set -euo pipefail

# Which repo the one-liner pulls from. Override without editing:
#   CLAUDEGUARD_REPO=you/ClaudeGuard bash -c "$(curl -fsSL .../install.sh)"
REPO="${CLAUDEGUARD_REPO:-keii-2596/ClaudeGuard}"
BRANCH="${CLAUDEGUARD_BRANCH:-main}"

INSTALL_DIR="$HOME/.local/share/ClaudeGuard"
APP_BUNDLE="$INSTALL_DIR/ClaudeGuard.app"
PLIST_PATH="$HOME/Library/LaunchAgents/com.claudeguard.daemon.plist"
CONFIG_DIR="$HOME/.config/claudeguard"
# Root privileged-helper: a LaunchDaemon (no sudoers, no setuid). The binary
# lives in a root-owned dir so it can't be swapped, and it runs only when the
# trigger file below is touched.
HELPER_SYS_DIR="/Library/Application Support/ClaudeGuard"
HELPER_PLIST="/Library/LaunchDaemons/com.claudeguard.helper.plist"
LEGACY_SUDOERS="/etc/sudoers.d/claudeguard"   # removed on upgrade from old versions

# --- Pretty output ----------------------------------------------------------
if [ -t 1 ]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GRN=$'\033[32m'
    YLW=$'\033[33m'; CYN=$'\033[36m'; RST=$'\033[0m'
else
    BOLD=; DIM=; RED=; GRN=; YLW=; CYN=; RST=
fi
info() { printf '%s %s\n' "${CYN}==>${RST}" "$*"; }
ok()   { printf '%s %s\n' "${GRN}✓${RST}"   "$*"; }
warn() { printf '%s %s\n' "${YLW}⚠${RST}"   "$*"; }
die()  { printf '%s %s\n' "${RED}✗${RST}"   "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

printf '%s\n' "${BOLD}${CYN}"
cat <<'BANNER'
   ____ _                 _        ____                     _
  / ___| | __ _ _   _  __| | ___  / ___|_   _  __ _ _ __ __| |
 | |   | |/ _` | | | |/ _` |/ _ \| |  _| | | |/ _` | '__/ _` |
 | |___| | (_| | |_| | (_| |  __/| |_| | |_| | (_| | | | (_| |
  \____|_|\__,_|\__,_|\__,_|\___| \____|\__,_|\__,_|_|  \__,_|
BANNER
printf '%s\n' "        VPN-whitelist guard for Claude on macOS${RST}"
printf '\n'

[ "$(uname -s)" = "Darwin" ] || die "ClaudeGuard is macOS-only."

# --- Bootstrap: fetch source when piped from curl (no local tree) -----------
_src="${BASH_SOURCE[0]:-}"
if [ -n "$_src" ] && [ -f "$_src" ]; then
    SOURCE_DIR="$(cd "$(dirname "$_src")" && pwd)"
else
    SOURCE_DIR=""
fi

if [ -z "$SOURCE_DIR" ] || [ ! -f "$SOURCE_DIR/src/main.swift" ]; then
    info "Fetching ClaudeGuard from ${BOLD}github.com/$REPO${RST} (branch $BRANCH)…"
    BOOT_TMP="$(mktemp -d)"
    trap 'rm -rf "$BOOT_TMP"' EXIT
    if have git; then
        git clone --depth 1 --branch "$BRANCH" "https://github.com/$REPO.git" \
            "$BOOT_TMP/ClaudeGuard" >/dev/null 2>&1 || die "git clone failed (is $REPO correct and public?)"
        SOURCE_DIR="$BOOT_TMP/ClaudeGuard"
    else
        curl -fsSL "https://codeload.github.com/$REPO/tar.gz/refs/heads/$BRANCH" \
            | tar -xz -C "$BOOT_TMP" || die "download failed (is $REPO correct and public?)"
        SOURCE_DIR="$BOOT_TMP/${REPO##*/}-$BRANCH"
    fi
    [ -f "$SOURCE_DIR/src/main.swift" ] || die "fetched archive is missing src/main.swift"
    ok "Source ready."
fi

LOGO_PNG="$SOURCE_DIR/assets/AppIcon.png"

# --- Prerequisite: Xcode Command Line Tools (clang + swiftc) ----------------
# Required to compile on-device. If missing, launch Apple's installer and wait.
if ! have clang || ! have swiftc; then
    warn "Xcode Command Line Tools required (clang + swiftc)."
    info "Launching Apple's installer — click ${BOLD}Install${RST} in the popup."
    xcode-select --install >/dev/null 2>&1 || true
    printf '%s' "${DIM}    waiting for the tools to finish installing"
    while ! (have clang && have swiftc); do printf '.'; sleep 5; done
    printf '%s\n' "${RST}"
    ok "Command Line Tools ready."
fi

# --- 1. Stage source into the install dir -----------------------------------
info "Installing to ${BOLD}$INSTALL_DIR${RST}"
mkdir -p "$INSTALL_DIR/bin" "$INSTALL_DIR/src"
/usr/bin/rsync -a --exclude '__pycache__' --exclude '*.pyc' --exclude '.DS_Store' \
    "$SOURCE_DIR/src/" "$INSTALL_DIR/src/"
for f in "$SOURCE_DIR/bin/"*; do
    [ "$(basename "$f")" = "hosts-helper" ] && continue   # compiled below, never shipped
    cp -R "$f" "$INSTALL_DIR/bin/"
done

# --- 2. Compile the native binaries -----------------------------------------
# A previous install may have left a root-owned setuid hosts-helper behind; as a
# regular user we can only remove-then-recreate (dir write perm governs unlink).
info "Compiling privileged hosts helper (C)…"
rm -f "$INSTALL_DIR/bin/hosts-helper" 2>/dev/null || sudo rm -f "$INSTALL_DIR/bin/hosts-helper"
clang -O2 "$SOURCE_DIR/src/hosts_helper.c" -o "$INSTALL_DIR/bin/hosts-helper"

info "Compiling native menu bar app (Swift)…"
swiftc -O "$SOURCE_DIR/src/main.swift" -o "$INSTALL_DIR/bin/ClaudeGuardMenuBar"

chmod +x "$INSTALL_DIR/bin/claudeguard" "$INSTALL_DIR/bin/ClaudeGuardMenuBar" \
         "$INSTALL_DIR/src/cli_wrapper.py" "$INSTALL_DIR/src/app_launcher.py" \
         "$INSTALL_DIR/src/helper.py"

# --- 3. Build the .app bundle (icon + Info.plist) ---------------------------
info "Creating ClaudeGuard.app bundle…"
mkdir -p "$APP_BUNDLE/Contents/MacOS" "$APP_BUNDLE/Contents/Resources"

if [ -f "$LOGO_PNG" ]; then
    ICONSET_DIR="/tmp/AppIcon.iconset"; rm -rf "$ICONSET_DIR"; mkdir -p "$ICONSET_DIR"
    for pair in "16:icon_16x16" "32:icon_16x16@2x" "32:icon_32x32" "64:icon_32x32@2x" \
                "128:icon_128x128" "256:icon_128x128@2x" "256:icon_256x256" \
                "512:icon_256x256@2x" "512:icon_512x512" "1024:icon_512x512@2x"; do
        sz="${pair%%:*}"; nm="${pair#*:}"   # split without relying on word-splitting (bash+zsh safe)
        sips -z "$sz" "$sz" "$LOGO_PNG" --out "$ICONSET_DIR/$nm.png" >/dev/null 2>&1
    done
    iconutil -c icns "$ICONSET_DIR" -o "$APP_BUNDLE/Contents/Resources/AppIcon.icns"
    rm -rf "$ICONSET_DIR"
else
    warn "assets/AppIcon.png not found — bundle will use the default icon."
fi

cat > "$APP_BUNDLE/Contents/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key><string>ClaudeGuardMenuBar</string>
    <key>CFBundleIconFile</key><string>AppIcon</string>
    <key>CFBundleIdentifier</key><string>com.claudeguard.app</string>
    <key>CFBundleName</key><string>ClaudeGuard</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>LSUIElement</key><true/>
</dict>
</plist>
EOF

cp "$INSTALL_DIR/bin/ClaudeGuardMenuBar" "$APP_BUNDLE/Contents/MacOS/ClaudeGuardMenuBar"
mkdir -p "$HOME/Applications"
ln -sf "$APP_BUNDLE" "$HOME/Applications/ClaudeGuard.app"

# --- 4. Symlink the manager CLI ---------------------------------------------
info "Installing the 'claudeguard' manager…"
mkdir -p "$HOME/.local/bin" "$CONFIG_DIR"
ln -sf "$INSTALL_DIR/bin/claudeguard" "$HOME/.local/bin/claudeguard"
[ -w "/usr/local/bin" ] && ln -sf "$INSTALL_DIR/bin/claudeguard" "/usr/local/bin/claudeguard"

# --- 5. Hook the `claude` CLI + locate Claude Desktop ------------------------
# Delegated to src/integrity.py, the same code the daemon runs on a timer, so a
# fresh install and a later self-heal can't disagree about where Claude lives.
info "Hooking the 'claude' command…"
REPAIR_OUT="$(cd "$INSTALL_DIR" && python3 -c "
import sys
sys.path.insert(0, '.')
from src.config import ConfigManager
from src.integrity import repair

report = repair(ConfigManager())
print('REAL_CLI=' + (report['real_cli'] or ''))
for change in report['changed']:
    print('CHANGED=' + change)
for note in report['notes']:
    print('NOTE=' + note)
" 2>&1)" || REPAIR_OUT=""

REAL_CLAUDE="$(printf '%s\n' "$REPAIR_OUT" | sed -n 's/^REAL_CLI=//p')"
printf '%s\n' "$REPAIR_OUT" | sed -n 's/^CHANGED=//p' | while IFS= read -r line; do ok "$line"; done
printf '%s\n' "$REPAIR_OUT" | sed -n 's/^NOTE=//p'    | while IFS= read -r line; do warn "$line"; done

if [ -n "$REAL_CLAUDE" ]; then
    ok "Real Claude CLI: $REAL_CLAUDE"
else
    warn "Could not find the real 'claude' CLI. If you use Claude Code, run later:"
    warn "    claudeguard set-cli-path /path/to/real/claude"
fi

# --- 6. LaunchAgent (autostart at login) ------------------------------------
info "Registering login-autostart LaunchAgent…"
mkdir -p "$HOME/Library/LaunchAgents"
cat > "$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.claudeguard.daemon</string>
    <key>ProgramArguments</key>
    <array><string>$INSTALL_DIR/bin/ClaudeGuardMenuBar</string></array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
    <key>StandardOutPath</key><string>/tmp/claudeguard.log</string>
    <key>StandardErrorPath</key><string>/tmp/claudeguard.err</string>
</dict>
</plist>
EOF
pkill -f "ClaudeGuardMenuBar" 2>/dev/null || true
launchctl unload "$PLIST_PATH" 2>/dev/null || true
launchctl load "$PLIST_PATH" 2>/dev/null || true

# --- 7. Root network helper via a LaunchDaemon (no sudoers) ------------------
# The user-session daemon has no root; it stages the desired /etc/hosts + pf
# rule in ~/.config/claudeguard/pending and touches a trigger file. This root
# LaunchDaemon watches that trigger and applies the vetted files. Needs your
# password ONCE now (to place the root-owned binary + plist); never again.
info "Installing the root network helper (LaunchDaemon — needs your password once)…"

# Private staging dir + trigger file the helper watches (must exist before load).
mkdir -p "$CONFIG_DIR/pending"
chmod 700 "$CONFIG_DIR/pending"
[ -f "$CONFIG_DIR/pending/request" ] || : > "$CONFIG_DIR/pending/request"

HELPER_PLIST_BODY="<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
    <key>Label</key><string>com.claudeguard.helper</string>
    <key>ProgramArguments</key>
    <array>
        <string>$HELPER_SYS_DIR/hosts-helper</string>
        <string>$CONFIG_DIR</string>
    </array>
    <key>WatchPaths</key>
    <array><string>$CONFIG_DIR/pending/request</string></array>
    <key>StandardOutPath</key><string>/tmp/claudeguard-helper.log</string>
    <key>StandardErrorPath</key><string>/tmp/claudeguard-helper.err</string>
</dict>
</plist>"

install_root_helper() {   # $1 = sudo prefix ("" when already root)
    local S="$1"
    $S mkdir -p "$HELPER_SYS_DIR"
    $S cp "$INSTALL_DIR/bin/hosts-helper" "$HELPER_SYS_DIR/hosts-helper"
    $S chown root:wheel "$HELPER_SYS_DIR" "$HELPER_SYS_DIR/hosts-helper"
    $S chmod 755 "$HELPER_SYS_DIR/hosts-helper"     # root-owned, not user-writable
    printf '%s\n' "$HELPER_PLIST_BODY" | $S tee "$HELPER_PLIST" >/dev/null
    $S chown root:wheel "$HELPER_PLIST"
    $S chmod 644 "$HELPER_PLIST"
    $S launchctl bootout system "$HELPER_PLIST" 2>/dev/null || true
    $S launchctl bootstrap system "$HELPER_PLIST" 2>/dev/null \
        || $S launchctl load -w "$HELPER_PLIST" 2>/dev/null || true
}

if [ "$(id -u)" -eq 0 ]; then
    rm -f "$LEGACY_SUDOERS" 2>/dev/null || true
    install_root_helper ""
else
    sudo rm -f "$LEGACY_SUDOERS" 2>/dev/null || true   # drop old NOPASSWD entry if upgrading
    install_root_helper "sudo"
fi
# The compiled copy in the user dir is never executed now; drop it.
rm -f "$INSTALL_DIR/bin/hosts-helper" 2>/dev/null || true

# --- 8. First-run: offer to whitelist the current public IP -----------------
# Best done while you're connected to your VPN right now.
CUR_IP="$(cd "$INSTALL_DIR" && python3 -c 'import sys; sys.path.insert(0,"."); from src.ip_checker import stun_public_ip; print(stun_public_ip() or "")' 2>/dev/null || true)"
if [ -n "$CUR_IP" ] && [ -r /dev/tty ]; then
    printf '\n%sYour current public IP is %s%s%s.\n' "$BOLD" "$CYN" "$CUR_IP" "$RST"
    printf '%sWhitelist it now? Only say yes if you are on your VPN right now. [y/N] %s' "$BOLD" "$RST"
    read -r ans < /dev/tty || ans=""
    case "$ans" in
        [Yy]*) "$INSTALL_DIR/bin/claudeguard" add-ip "$CUR_IP" >/dev/null 2>&1 && ok "Whitelisted $CUR_IP" ;;
        *)     info "Skipped. Add your VPN IP later: ${BOLD}claudeguard add-ip <IP>${RST}" ;;
    esac
fi

printf '\n%s\n' "${GRN}${BOLD}🎉 ClaudeGuard installed & running.${RST}"
printf '%s\n' "   Look for the shield in your macOS menu bar."
printf '%s\n' "   ${DIM}Manage it:${RST} ${BOLD}claudeguard status${RST}  ·  ${BOLD}claudeguard add-ip <IP>${RST}"
if ! printf '%s' "$PATH" | tr ':' '\n' | grep -qx "$HOME/.local/bin"; then
    printf '%s\n' "   ${YLW}Note:${RST} add ~/.local/bin to your PATH to use 'claudeguard' directly:"
    printf '%s\n' "         ${DIM}echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.zshrc${RST}"
fi
