#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
import sys
import psutil

# Redirected Windows consoles default to a legacy code page on many systems.
if sys.platform == "win32":
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from portable.config import Settings
from src import policy
from portable.platforms import autostart, stop_tree
from portable.runtime import check, daemon, daemon_process, launch, start_daemon


def main():
    parser = argparse.ArgumentParser(description="ClaudeGuard Windows/Linux 中文版")
    parser.add_argument("--config", type=Path, help="配置文件路径")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("gui", "daemon", "start", "stop", "status", "check"):
        sub.add_parser(name)
    edit = sub.add_parser("set", help="修改配置")
    edit.add_argument("key", choices=("ip_check_mode", "cli_path", "desktop_path", "http_proxy", "check_interval", "cli_http_proxy_enabled", "protection_enabled", "access_mode", "risk_threshold", "risk_cache_ttl", "detect_ip_change"))
    edit.add_argument("value")
    for name in ("add-ip", "remove-ip"):
        sub.add_parser(name).add_argument("ip")
    sub.add_parser("ack-ip-change", help="确认当前出口并解除跳变拦截")
    sub.add_parser("autostart").add_argument("action", choices=("enable", "disable"))
    run = sub.add_parser("run", help="检查出口后启动并监控程序")
    run.add_argument("target", choices=("cli", "desktop"))
    run.add_argument("args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    settings = Settings(args.config)
    try:
        if args.command == "gui":
            from portable.gui import show
            show(settings)
        elif args.command == "daemon":
            daemon(settings)
        elif args.command == "start":
            start_daemon(settings)
            print("已请求启动后台守护，可用 status 查看运行情况。")
        elif args.command == "stop":
            process = daemon_process(settings)
            if process:
                stop_tree(process)
            print("后台守护已停止。")
        elif args.command in ("status", "check"):
            result = check(settings.load(), settings.path.parent)
            result["daemon_running"] = daemon_process(settings) is not None
            print(json.dumps(result, ensure_ascii=False, indent=2))
            if args.command == "check":
                return 0 if result["state"] in ("allowed", "disabled") else 1
        elif args.command == "ack-ip-change":
            data = settings.load()
            observed = policy.detect(policy.settings(data))
            print(json.dumps(observed, ensure_ascii=False))
            if input("确认信任这些出口？输入 yes 继续：").strip() != "yes":
                print("已取消。")
                return 1
            result = policy.check(data, settings.path.parent, acknowledge=True, expected_ips=observed)
            if result.get('jump_acknowledged'):
                print('已解除跳变拦截，继续检查访问规则。')
            print(result['reason'])
            return 0 if result['state'] == 'allowed' else 1
        elif args.command == "run":
            return launch(settings, args.target, args.args)
        elif args.command == "autostart":
            python = Path(sys.executable)
            if sys.platform == "win32" and python.with_name("pythonw.exe").exists():
                python = python.with_name("pythonw.exe")
            autostart(python, Path(__file__).resolve(), settings.path.resolve(), args.action == "enable")
            print("登录自启动设置已更新。")
        else:
            data = settings.load()
            if args.command == "set":
                value = args.value
                if args.key in ("check_interval", "risk_threshold", "risk_cache_ttl"):
                    value = float(value)
                if args.key in ("protection_enabled", "detect_ip_change", "cli_http_proxy_enabled"):
                    if value not in ("true", "false"):
                        raise ValueError("请填写 true 或 false")
                    value = value == "true"
                data[args.key] = value
            elif args.command == "add-ip":
                data["allowed_ips"] = sorted(set(data["allowed_ips"] + [args.ip]))
            else:
                data["allowed_ips"] = [ip for ip in data["allowed_ips"] if ip != args.ip]
            settings.save(data)
            print("配置已保存。")
    except (ValueError, OSError, RuntimeError, psutil.Error) as exc:
        print(f"操作失败：{exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
