#!/usr/bin/env python3
"""Small JSON bridge for the native macOS menu bar application."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src import policy
if sys.platform == "win32":
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('action', choices=('evaluate', 'check', 'ack'))
    args = parser.parse_args()
    try:
        request = json.load(sys.stdin)
        data = request['data']
        if args.action == 'evaluate':
            result = policy.evaluate(data, request.get('ips', {}), args.config.parent)
        else:
            result = policy.check(data, args.config.parent, acknowledge=args.action == 'ack', expected_ips=request.get('expected_ips'))
    except Exception:
        result = {'state': 'blocked', 'reason': '策略检查失败，暂不放行', 'error': '策略请求或配置无效', 'detected_ips': {}, 'scores': {}}
    print(json.dumps(result, ensure_ascii=False, allow_nan=False))


if __name__ == '__main__':
    main()
