#!/usr/bin/env python3
"""Pre-flight interceptor for the `claude` CLI. Checks the verdict before
launch and keeps re-checking for the lifetime of the session; kills it if the
IP leaves the whitelist. Hands off to the real `claude` when allowed."""
import sys
import os
import subprocess
import signal
import threading
import time

# Importable via the install symlink too.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..")))

from src.config import ConfigManager
from src.proxy_config import cli_environment
from src.brain import get_verdict
from src.integrity import discover_real_cli, is_our_wrapper, repair_cli
from src.network_guard import sync_hosts_file

# Sessions use the configured cadence; advanced policies also probe the exit.

def force_restore_terminal():
    """Undo Claude's TUI state. Exiting the alternate screen (\\033[?1049l) is
    the key part — without it anything we print lands in Claude's discarded
    buffer and is never seen."""
    try:
        sys.stdout.write(
            "\033[?1049l"                                   # exit alternate screen
            "\033[?1000l\033[?1002l\033[?1003l\033[?1006l"  # disable mouse tracking
            "\033[?2004l"                                   # disable bracketed paste
            "\033[?25h"                                     # show cursor
            "\033[0m"                                       # reset colors
        )
        sys.stdout.flush()
    except Exception:
        pass
    os.system("stty sane 2>/dev/null")

def handle_signal(signum, frame):
    force_restore_terminal()
    sys.exit(130 if signum == signal.SIGINT else 143)

def print_block_banner(ip, err, verb):
    current_ip_str = ip if ip else "未获取"
    print(f"\033[91m", file=sys.stderr)
    print(f"==================================================", file=sys.stderr)
    print(f" 🚫 [ClaudeGuard] {verb}", file=sys.stderr)
    print(f"==================================================", file=sys.stderr)
    print(f" 当前出口： {current_ip_str}", file=sys.stderr)
    print(f" 状态：出口未通过检查，禁止启动", file=sys.stderr)
    if err:
        print(f" 原因： {err}", file=sys.stderr)
    print(f"--------------------------------------------------", file=sys.stderr)
    print(f" 本次启动已取消，请检查出口 IP 和白名单设置。", file=sys.stderr)
    print(" 运行 claudeguard status 查看出口和拦截原因。", file=sys.stderr)
    print(f"\033[0m", file=sys.stderr)

def main():
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        try:
            signal.signal(sig, handle_signal)
        except Exception:
            pass

    config = ConfigManager()
    try:
        os.environ.update(cli_environment(config.config, os.environ))
    except ValueError as exc:
        force_restore_terminal()
        print(f"[ClaudeGuard] 已阻止启动：{exc}", file=sys.stderr)
        sys.exit(1)

    if not config.protection_enabled:
        run_real_claude(config)
        return

    # Restore the terminal BEFORE printing: force_restore_terminal() flips the
    # screen buffer, so printing first would wipe the message we just wrote.
    if not config.allowed_ips and config.config.get("access_mode", "whitelist") == "whitelist":
        force_restore_terminal()
        print("\033[91m[ClaudeGuard] 🚫 尚未设置 IP 白名单，已阻止启动。\033[0m", file=sys.stderr)
        print("请运行 claudeguard add-ip <出口IP> 添加允许使用的出口。", file=sys.stderr)
        sys.exit(1)

    # Fail closed: only a confirmed "allowed" launches.
    verdict, ip, err = get_verdict(config)
    if verdict != "allowed":
        force_restore_terminal()
        if verdict == "offline":
            print_block_banner(ip, err or "暂时无法确认出口 IP，请检查网络和代理设置。", "已阻止启动 Claude Code")
        else:
            print_block_banner(ip, err, "已阻止启动 Claude Code")
        sys.exit(1)

    # We're hooked on *this* PATH entry, but a reinstall may have taken over the
    # others. Re-hook them while we know where the real binary is.
    try:
        repair_cli(config)
    except Exception:
        pass

    sync_hosts_file(block_claude_domains=False, block_update_domains=config.block_auto_updates, config=config)
    run_real_claude(config)

def monitor_and_enforce(config, proc, stop_event, block_info):
    """Re-checks the verdict for the child's lifetime; kills it on a confirmed
    "blocked". The banner is NOT printed here (Claude owns the TUI and would
    swallow it) — we stash details in block_info and let the main thread print
    after Claude exits. On "offline" we do nothing: no point killing a session
    over a Wi-Fi blip."""
    while not stop_event.wait(config.check_interval):
        if proc.poll() is not None:
            return  # child already exited on its own

        config.config = config.load_config()
        if not config.protection_enabled:
            continue

        verdict, ip, err = get_verdict(config)
        if verdict != "blocked":
            continue

        block_info["blocked"] = True
        block_info["ip"] = ip
        block_info["err"] = err
        try:
            proc.terminate()
            for _ in range(10):
                if proc.poll() is not None:
                    break
                time.sleep(0.1)
            if proc.poll() is None:
                proc.kill()
        except Exception:
            pass
        return

def run_real_claude(config):
    # The recorded path is version-stamped on Homebrew, so an update deletes it.
    # Re-discover when it's gone — or when it points back at this wrapper, which
    # would fork-bomb the machine.
    real_path = config.real_claude_cli
    if not os.path.exists(real_path) or is_our_wrapper(real_path):
        real_path = discover_real_cli(config)
        if real_path:
            config.config["real_claude_cli_path"] = real_path
            config.save_config()

    if not real_path or not os.path.exists(real_path):
        force_restore_terminal()
        print("[ClaudeGuard] 未找到原始 Claude Code 程序。", file=sys.stderr)
        print("  请运行 claudeguard doctor 重新查找，", file=sys.stderr)
        print("  或用 claudeguard set-cli-path /path/to/real/claude 手动指定路径。", file=sys.stderr)
        sys.exit(1)

    env = cli_environment(config.config, os.environ)
    if config.block_auto_updates:
        env["DISABLE_AUTO_UPDATE"] = "1"
        env["CLAUDE_DISABLE_AUTO_UPDATE"] = "1"

    if config.model_override_enabled and config.default_model and "--model" not in sys.argv:
        args = [real_path, "--model", config.default_model] + sys.argv[1:]
    else:
        args = [real_path] + sys.argv[1:]

    stop_event = threading.Event()
    block_info = {"blocked": False, "ip": None, "err": None}
    rc = 0

    try:
        proc = subprocess.Popen(args, env=env)
        if config.protection_enabled:
            monitor = threading.Thread(target=monitor_and_enforce, args=(config, proc, stop_event, block_info), daemon=True)
            monitor.start()
        proc.wait()
        rc = proc.returncode
    except KeyboardInterrupt:
        rc = 130
    except Exception:
        rc = 1
    finally:
        stop_event.set()
        force_restore_terminal()

    # Show the banner AFTER the terminal is restored. Two blocked paths:
    #   1. monitor caught it and killed the session (block_info set);
    #   2. Claude quit on its own the instant the network was cut, before the
    #      next tick (block_info unset) — caught by re-verifying on any abnormal
    #      exit. Clean exits (rc == 0) skip the check, so healthy sessions pay
    #      nothing and never see a spurious banner.
    banner_ip, banner_err = None, None
    if block_info["blocked"]:
        banner_ip, banner_err = block_info["ip"], block_info["err"]
    elif config.protection_enabled and rc != 0:
        config.config = config.load_config()
        verdict, ip, err = get_verdict(config)
        if verdict == "blocked":
            banner_ip, banner_err = ip, err

    if banner_ip is not None:
        print_block_banner(banner_ip, banner_err, "出口未通过访问检查，Claude Code 已停止运行")
        sys.exit(1)

    sys.exit(rc)

if __name__ == "__main__":
    main()
