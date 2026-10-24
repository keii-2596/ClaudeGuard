"""Keeps ClaudeGuard attached to Claude across reinstalls, updates and moves.

Every hook we own points at something Anthropic's installers rewrite under us:
the `claude` shim (a reinstall drops the real binary back on top of it), the
version-stamped path we hand off to, and Claude Desktop's bundle id. Pinning any
of them means the guard silently detaches while the menu bar still says 🟢 — so
everything here is discovered, and `repair()` re-attaches what came loose.
"""
import glob
import os
import re
import subprocess

HOME = os.path.expanduser("~")
INSTALL_DIR = os.path.join(HOME, ".local", "share", "ClaudeGuard")

# We create the shim in PRIMARY unconditionally; in the others we only replace a
# `claude` that already existed, never invent one where there was none.
PRIMARY_LINK_DIR = os.path.join(HOME, ".local", "bin")
CLI_LINK_DIRS = [PRIMARY_LINK_DIR, "/opt/homebrew/bin", "/usr/local/bin"]

# Match on the shared prefix — the exact id has already changed once.
DESKTOP_BUNDLE_PREFIX = "com.anthropic.claude"
DESKTOP_BUNDLE_IDS = ["com.anthropic.claudefordesktop", "com.anthropic.claudefor-mac"]


# --- our own wrapper --------------------------------------------------------

def wrapper_path():
    """The cli_wrapper.py shims point at: the installed copy, else this checkout."""
    installed = os.path.join(INSTALL_DIR, "src", "cli_wrapper.py")
    if os.path.isfile(installed):
        return installed
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), "cli_wrapper.py")


def is_our_wrapper(path):
    """True if `path` is a ClaudeGuard shim rather than a real Claude binary.

    Never hand off to ourselves: a wrapper pointing at a wrapper is a fork bomb,
    which is what a naive "first `claude` on PATH" fallback produces once our
    shim is installed."""
    if not path:
        return False
    try:
        real = os.path.realpath(path)
    except OSError:
        return False
    if os.path.basename(real) == "cli_wrapper.py":
        return True
    try:
        # The size guard means we never read the real CLI (a ~200 MB binary).
        if os.path.isfile(real) and os.path.getsize(real) < 200_000:
            with open(real, "rb") as f:
                if b"ClaudeGuard" in f.read(4096):
                    return True
    except OSError:
        pass
    return False


# --- real `claude` CLI discovery -------------------------------------------

def _version_key(text):
    return tuple(int(n) for n in re.findall(r"\d+", text)) or (0,)


def _cask_binaries():
    """Homebrew casks, newest first. This is what still finds the real binary
    after we've taken over /opt/homebrew/bin/claude."""
    found = []
    for root in ("/opt/homebrew/Caskroom/claude-code", "/usr/local/Caskroom/claude-code"):
        found.extend(glob.glob(os.path.join(root, "*", "claude")))
    return sorted(found, key=lambda p: _version_key(os.path.basename(os.path.dirname(p))),
                  reverse=True)


def _native_binaries():
    patterns = [
        os.path.join(HOME, ".local", "share", "claude", "versions", "*", "claude"),
        os.path.join(HOME, ".local", "share", "claude", "*", "claude"),
        os.path.join(HOME, ".local", "share", "claude", "claude"),
        os.path.join(HOME, ".claude", "local", "claude"),
        os.path.join(HOME, ".claude", "local", "node_modules", ".bin", "claude"),
    ]
    found = []
    for pattern in patterns:
        found.extend(sorted(glob.glob(pattern), key=_version_key, reverse=True))
    return found


def _path_binaries():
    dirs = list(CLI_LINK_DIRS)
    dirs += [d for d in os.environ.get("PATH", "").split(":") if d]
    dirs += [os.path.join(HOME, ".bun", "bin"), os.path.join(HOME, ".volta", "bin"), "/usr/bin"]
    seen, found = set(), []
    for d in dirs:
        if not d or d in seen:
            continue
        seen.add(d)
        found.append(os.path.join(d, "claude"))
    return found


def _usable_real_cli(path):
    if not path:
        return None
    try:
        real = os.path.realpath(path)
    except OSError:
        return None
    if not os.path.isfile(real) or not os.access(real, os.X_OK):
        return None
    if is_our_wrapper(real):
        return None
    return real


def discover_real_cli(config=None):
    """The real `claude` binary, or None.

    The configured path wins while it resolves, so an explicit `set-cli-path`
    sticks and the hand-off target doesn't jitter between installs; the rest is
    the recovery order for when an upgrade has deleted it."""
    candidates = []
    if config is not None:
        candidates.append(config.config.get("real_claude_cli_path"))
    candidates += _cask_binaries() + _native_binaries() + _path_binaries()
    for candidate in candidates:
        real = _usable_real_cli(candidate)
        if real:
            return real
    return None


# --- Claude Desktop discovery ----------------------------------------------

def _mdfind(query):
    try:
        res = subprocess.run(["/usr/bin/mdfind", query], capture_output=True, text=True, timeout=5)
    except Exception:
        return []
    return [line for line in res.stdout.splitlines() if line.strip().endswith(".app")]


def discover_desktop_app(config=None):
    """Claude.app, or None. Falls back to Spotlight so a copy kept outside
    /Applications is still found."""
    candidates = []
    if config is not None:
        candidates.append(config.config.get("real_claude_app_path"))
    candidates += ["/Applications/Claude.app", os.path.join(HOME, "Applications", "Claude.app")]
    for candidate in candidates:
        if candidate and os.path.isdir(candidate):
            return candidate
    for bundle_id in DESKTOP_BUNDLE_IDS:
        for hit in _mdfind(f"kMDItemCFBundleIdentifier == '{bundle_id}'"):
            if os.path.isdir(hit):
                return hit
    for hit in _mdfind(f"kMDItemCFBundleIdentifier == '{DESKTOP_BUNDLE_PREFIX}*'"):
        if os.path.isdir(hit) and os.path.basename(hit) != "ClaudeGuard.app":
            return hit
    return None


def desktop_update_paths():
    """Claude Desktop's auto-update state. Globbed, not keyed on a literal bundle
    id — a stale one matches nothing and turns the freeze into a silent no-op."""
    paths = glob.glob(os.path.join(HOME, "Library", "Caches", "com.anthropic.claude*.ShipIt"))
    paths += glob.glob(os.path.join(HOME, "Library", "Application Support", "Claude", "app-update.yml"))
    return paths


# --- repair -----------------------------------------------------------------

def _relink(wrapper, link):
    tmp = link + ".claudeguard.tmp"
    try:
        if os.path.lexists(tmp):
            os.remove(tmp)
        os.symlink(wrapper, tmp)
        os.replace(tmp, link)   # atomic: `claude` is never briefly missing
        return True
    except OSError:
        try:
            if os.path.lexists(tmp):
                os.remove(tmp)
        except OSError:
            pass
        return False


def repair_cli(config, relink=True):
    """Re-point the config at a real `claude`, then re-hook the shims.

    Order is the whole trick: a reinstall leaves the real binary at exactly the
    path we want to claim, so claiming it before discovering it would erase our
    only handle on it and break `claude` for good."""
    report = {"real_cli": None, "changed": [], "notes": []}

    real = discover_real_cli(config)
    report["real_cli"] = real
    if real:
        if config.config.get("real_claude_cli_path") != real:
            config.config["real_claude_cli_path"] = real
            config.save_config()
            report["changed"].append(f"原始 Claude Code 路径已更新：{real}")
    else:
        report["notes"].append("未找到原始 Claude Code 程序，请先安装，"
                               "或运行 claudeguard set-cli-path <path> 指定路径。")

    if not relink:
        return report

    wrapper = wrapper_path()
    if not os.path.isfile(wrapper):
        report["notes"].append(f"启动检查脚本缺失：{wrapper}，请重新安装 ClaudeGuard。")
        return report

    for link_dir in CLI_LINK_DIRS:
        link = os.path.join(link_dir, "claude")
        exists = os.path.lexists(link)

        if not exists:
            if link_dir != PRIMARY_LINK_DIR:
                continue
            try:
                os.makedirs(link_dir, exist_ok=True)
            except OSError:
                report["notes"].append(f"无法创建目录：{link_dir}")
                continue
        elif is_our_wrapper(link) and os.path.realpath(link) == os.path.realpath(wrapper):
            continue

        if exists and not real:
            # Taking the name over now would leave no working `claude` at all;
            # leaving it alone merely leaves it unguarded.
            report["notes"].append(f"未找到原始程序，已保留现有启动入口：{link}")
            continue

        if exists and not os.path.islink(link) and not is_our_wrapper(link):
            # A real binary copied in, not a symlink — replacing it would destroy
            # the install.
            report["notes"].append(f"{link} 是程序文件，已保留原文件，请另行接入启动检查。")
            continue

        if _relink(wrapper, link):
            report["changed"].append(f"已恢复启动检查：{link}")
        elif not exists:
            report["notes"].append(f"无法写入启动入口：{link}")
        else:
            report["notes"].append(f"没有权限替换启动入口：{link}")

    return report


def repair_desktop(config):
    report = {"desktop_app": None, "changed": [], "notes": []}
    app = discover_desktop_app(config)
    report["desktop_app"] = app
    if app:
        if config.config.get("real_claude_app_path") != app:
            config.config["real_claude_app_path"] = app
            config.save_config()
            report["changed"].append(f"Claude 桌面端路径已更新：{app}")
    else:
        report["notes"].append("未找到 Claude 桌面端，暂不启用桌面端保护。")
    return report


def repair(config):
    """Full self-heal. Cheap enough to run on a timer — a handful of stat calls
    unless something is actually broken."""
    cli = repair_cli(config)
    desktop = repair_desktop(config)
    return {
        "real_cli": cli["real_cli"],
        "desktop_app": desktop["desktop_app"],
        "changed": cli["changed"] + desktop["changed"],
        "notes": cli["notes"] + desktop["notes"],
    }


def cli_hook_status():
    """(intercepted, details) for `claudeguard doctor` — what a `claude` typed in
    a shell would actually reach."""
    details = []
    intercepted = True
    path_dirs = [d for d in os.environ.get("PATH", "").split(":") if d]
    for link_dir in CLI_LINK_DIRS:
        link = os.path.join(link_dir, "claude")
        if not os.path.lexists(link):
            continue
        ours = is_our_wrapper(link)
        on_path = link_dir in path_dirs
        details.append({"path": link, "guarded": ours, "on_path": on_path})
        if on_path and not ours:
            intercepted = False
    if not details:
        intercepted = False
    return intercepted, details
