import copy
import ipaddress
import json
import os
from pathlib import Path
import tempfile
import sys
from src import policy

DEFAULTS = {
    **policy.DEFAULTS,
    "allowed_ips": [], "ip_check_mode": "both", "protection_enabled": True,
    "check_interval": 3, "cli_path": "", "desktop_path": "",
    "http_proxy": "",
}


def default_path():
    if os.name == "nt":
        return Path(os.environ.get("APPDATA", Path.home() / "AppData/Roaming")) / "ClaudeGuard/config.json"
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "claudeguard/config.json"


class Settings:
    def __init__(self, path=None):
        self.path = Path(path) if path else default_path()

    def load(self):
        data = copy.deepcopy(DEFAULTS)
        if self.path.exists():
            parsed = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(parsed, dict):
                raise ValueError("配置文件内容必须是 JSON 对象")
            data.update(parsed)
        if data["ip_check_mode"] == "auto":
            data["ip_check_mode"] = "both"
        self.validate(data)
        return data

    @staticmethod
    def validate(data):
        policy.settings(data)
        if data["ip_check_mode"] not in ("http", "stun", "both"):
            raise ValueError("检测方式只能是 http、stun 或 both")
        if type(data["protection_enabled"]) is not bool:
            raise ValueError("protection_enabled 必须是 true 或 false")
        interval = data["check_interval"]
        if isinstance(interval, bool) or not isinstance(interval, (int, float)) or not 1 <= interval <= 60:
            raise ValueError("检测间隔须在 1～60 秒之间")
        if not isinstance(data["allowed_ips"], list):
            raise ValueError("allowed_ips 必须是 IP 或 CIDR 网段列表")
        for ip in data["allowed_ips"]:
            ipaddress.ip_network(ip, strict=False)
        for field in ("cli_path", "desktop_path", "http_proxy"):
            if not isinstance(data[field], str):
                raise ValueError(f"{field} 必须是字符串")
        proxy = data["http_proxy"]
        if proxy and not proxy.startswith(("http://", "https://")):
            raise ValueError("代理地址须以 http:// 或 https:// 开头")
        for field in ("cli_path", "desktop_path"):
            name = Path(data[field]).name.lower()
            if data[field] and (os.path.realpath(data[field]) == os.path.realpath(sys.executable)
                               or name in ("node", "node.exe", "bash", "sh", "cmd.exe", "powershell.exe", "pwsh.exe", "env")
                               or name.startswith("python")):
                raise ValueError("请指定 Claude 原生程序，不能填写通用解释器或命令行工具")
            # Batch files need a shell and cannot safely preserve arbitrary CLI arguments.
            if Path(data[field]).suffix.lower() in (".cmd", ".bat", ".ps1"):
                raise ValueError("请指定原生可执行文件，不支持 cmd、bat 或 ps1 启动脚本")

    def save(self, data):
        self.validate(data)
        atomic_json(self.path, data)


def atomic_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=path.name, dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
