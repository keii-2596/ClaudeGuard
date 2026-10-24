#!/usr/bin/env python3
import sys
import os
import subprocess

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..")))

from src.config import ConfigManager
from src.brain import get_verdict
from src.integrity import discover_desktop_app
from src.network_guard import sync_hosts_file

def launch_claude_desktop():
    config = ConfigManager()

    if not config.protection_enabled:
        open_real_app(config)
        return

    if not config.allowed_ips:
        show_mac_alert(
            "ClaudeGuard 已拦截",
            "尚未设置 IP 白名单，已阻止启动 Claude 桌面端。\n\n请运行 claudeguard add-ip <出口IP> 添加允许使用的出口。"
        )
        sys.exit(1)

    # Fail closed — only "allowed" launches; "blocked"/"offline" both refuse.
    verdict, ip, err = get_verdict(config, timeout=2.0)

    if verdict != "allowed":
        if verdict == "offline":
            show_mac_alert(
                "ClaudeGuard 已拦截",
                "暂时无法确认出口 IP，已取消启动 Claude 桌面端。\n\n请检查网络和代理设置后重试。"
            )
        else:
            ip_str = ip if ip else "未获取"
            err_msg = f"\n原因：{err}" if err else ""
            show_mac_alert(
                "ClaudeGuard 已拦截",
                f"当前出口未通过白名单检查，已阻止启动 Claude 桌面端。\n\n当前出口：{ip_str}{err_msg}\n\n请检查出口 IP 和白名单设置。"
            )
        sys.exit(1)

    # IP is valid! Unblock domain and start app
    sync_hosts_file(block_claude_domains=False, block_update_domains=config.block_auto_updates, config=config)
    open_real_app(config)

def open_real_app(config):
    # Re-discover if the recorded location is stale (app moved or reinstalled).
    app_path = config.real_claude_app
    if not os.path.exists(app_path):
        app_path = discover_desktop_app(config)
        if app_path:
            config.config["real_claude_app_path"] = app_path
            config.save_config()

    if app_path and os.path.exists(app_path):
        subprocess.run(["open", "-a", app_path], check=False)
    else:
        show_mac_alert("ClaudeGuard 启动失败", "未找到 Claude 桌面端，请运行 claudeguard doctor 检查安装位置。")

def show_mac_alert(title, message):
    script = f'display alert "{title}" message "{message}" as critical buttons {{"知道了"}} default button "知道了"'
    subprocess.run(["osascript", "-e", script], check=False)

if __name__ == "__main__":
    launch_claude_desktop()
