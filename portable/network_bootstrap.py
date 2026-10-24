"""Wait for enrollment before executing any target code (Linux only)."""
import os
import sys

fd = int(sys.argv[1])
permission = os.read(fd, 1)
os.close(fd)
if permission != b'1':
    raise SystemExit('ClaudeGuard 未确认系统网络限制，已取消启动')
os.execvpe(sys.argv[2], sys.argv[2:], os.environ)
