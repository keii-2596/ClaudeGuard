import os
import subprocess

from src.integrity import desktop_update_paths


def apply_auto_update_lock(block_updates):
    """Lock/unlock Claude Desktop's auto-update state (chmod + chflags uchg).

    Paths are discovered, not hard-coded: they're keyed on a bundle id that has
    already been renamed once, and a stale one doesn't error — it silently
    matches nothing, so the freeze stops freezing while the UI still says it's
    on."""
    try:
        targets = desktop_update_paths()
        if not targets:
            return True, "未找到 Claude 桌面端的更新文件，无需锁定"

        for path in targets:
            recursive = ["-R"] if os.path.isdir(path) else []
            if block_updates:
                subprocess.run(["chmod"] + recursive + ["444", path], check=False)
                subprocess.run(["chflags"] + recursive + ["uchg", path], check=False)
            else:
                subprocess.run(["chflags"] + recursive + ["nouchg", path], check=False)
                subprocess.run(["chmod"] + recursive + ["755" if os.path.isdir(path) else "644", path],
                               check=False)

        return True, f"已处理 {len(targets)} 处自动更新文件"
    except Exception as e:
        return False, f"修改自动更新设置失败：{e}"
