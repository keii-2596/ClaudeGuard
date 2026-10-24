import json
import os
import sys
import copy
from src.policy import DEFAULTS as POLICY_DEFAULTS, atomic_json, settings as policy_settings

CONFIG_DIR = os.path.expanduser("~/.config/claudeguard")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")

DEFAULT_CONFIG = {
    **POLICY_DEFAULTS,
    "allowed_ips": [],
    "ip_check_mode": "both",
    "protection_enabled": True,
    "block_auto_updates": True,
    "model_override_enabled": False,
    "default_model": "claude-opus-4-8",
    "check_interval": 3,
    "blocked_domains": [
        "claude.com",
        "www.claude.com",
        "app.claude.com",
        "api.claude.com",
        "auth.claude.com",
        "claude.ai",
        "www.claude.ai",
        "app.claude.ai",
        "claude.usercontent.com",
        "anthropic.com",
        "www.anthropic.com",
        "console.anthropic.com",
        "api.anthropic.com",
        "stats.anthropic.com",
        "auth.anthropic.com",
        "assets-proxy.anthropic.com",
        "cdn.anthropic.com"
    ],
    "update_domains": [
        "desktop-app-updates.anthropic.com"
    ],
    "real_claude_cli_path": "/opt/homebrew/bin/claude",
    "real_claude_app_path": "/Applications/Claude.app"
}

class ConfigManager:
    def __init__(self, path=CONFIG_PATH):
        self.path = path
        self.config = self.load_config()

    def load_config(self):
        if not os.path.exists(self.path):
            self.ensure_dir()
            self.save_config(copy.deepcopy(DEFAULT_CONFIG))
            return copy.deepcopy(DEFAULT_CONFIG)
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
                # Fill missing default keys
                for k, v in DEFAULT_CONFIG.items():
                    if k not in data:
                        data[k] = v
                return data
        except Exception as e:
            print(f"[ClaudeGuard] 配置读取失败，将使用默认设置：{e}")
            return copy.deepcopy(DEFAULT_CONFIG)

    def save_config(self, data=None):
        if data is not None:
            self.config = data
        self.ensure_dir()
        atomic_json(self.path, self.config)

    def ensure_dir(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)

    @property
    def allowed_ips(self):
        return self.config.get("allowed_ips", [])

    @allowed_ips.setter
    def allowed_ips(self, ips):
        self.config["allowed_ips"] = list(set(ips))
        self.save_config()

    def add_ip(self, ip):
        ip = ip.strip()
        if ip and ip not in self.config["allowed_ips"]:
            self.config["allowed_ips"].append(ip)
            self.save_config()

    def remove_ip(self, ip):
        ip = ip.strip()
        if ip in self.config["allowed_ips"]:
            self.config["allowed_ips"].remove(ip)
            self.save_config()

    @property
    def protection_enabled(self):
        return self.config.get("protection_enabled", True)

    @protection_enabled.setter
    def protection_enabled(self, val):
        self.config["protection_enabled"] = bool(val)
        self.save_config()

    @property
    def block_auto_updates(self):
        return self.config.get("block_auto_updates", True)

    @block_auto_updates.setter
    def block_auto_updates(self, val):
        self.config["block_auto_updates"] = bool(val)
        self.save_config()

    @property
    def check_interval(self):
        try:
            return policy_settings(self.config)["check_interval"]
        except ValueError:
            return 3

    @property
    def model_override_enabled(self):
        return self.config.get("model_override_enabled", False)

    @model_override_enabled.setter
    def model_override_enabled(self, val):
        self.config["model_override_enabled"] = bool(val)
        self.save_config()

    @property
    def default_model(self):
        return self.config.get("default_model", "claude-opus-4-8")

    @default_model.setter
    def default_model(self, val):
        self.config["default_model"] = str(val).strip()
        self.save_config()

    @property
    def real_claude_cli(self):
        return self.config.get("real_claude_cli_path", "/opt/homebrew/bin/claude")

    @property
    def real_claude_app(self):
        return self.config.get("real_claude_app_path", "/Applications/Claude.app")

    @property
    def ip_check_mode(self):
        mode = self.config.get("ip_check_mode", "both")
        return "both" if mode == "auto" else mode

    @ip_check_mode.setter
    def ip_check_mode(self, value):
        if value not in ("both", "http", "stun"):
            raise ValueError("ip_check_mode 只能设为 both、http 或 stun")
        self.config["ip_check_mode"] = value
        self.save_config()
