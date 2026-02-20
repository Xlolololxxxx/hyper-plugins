#!/usr/bin/env python3
import json
import os
import sys
import importlib


def main():
    if len(sys.argv) < 2:
        print(json.dumps({'ok': False, 'error': 'missing parser arg'}))
        return 2

    parser = sys.argv[1]
    source = os.environ.get('JC_SOURCE_DIR')
    if source and source not in sys.path:
        sys.path.insert(0, source)

    try:
        mod_name = f'jc.parsers.{parser}'
        parser_mod = importlib.import_module(mod_name)
    except Exception as e:
        print(json.dumps({'ok': False, 'error': f'jc parser import failed: {e}', 'parser': parser}))
        return 3

    if len(sys.argv) >= 3:
        with open(sys.argv[2], 'r', encoding='utf-8', errors='replace') as f:
            raw = f.read()
    else:
        raw = sys.stdin.read()

    try:
        data = parser_mod.parse(raw, quiet=True)
        print(json.dumps({'ok': True, 'parser': parser, 'data': data}, ensure_ascii=False))
        return 0
    except Exception as e:
        print(json.dumps({'ok': False, 'parser': parser, 'error': str(e)}, ensure_ascii=False))
        return 4


if __name__ == '__main__':
    raise SystemExit(main())
