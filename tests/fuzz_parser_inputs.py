"""Source-checkout wrapper for APKLab's bounded parser mutation smoke test."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apklab.fuzzing import run_smoke


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Run bounded synthetic AXML/AAPT/DEX/ZIP parser mutation smoke tests')
    parser.add_argument('--seed', type=int, default=20261114,
                        help='Deterministic mutation seed')
    parser.add_argument('--cases', type=int, default=256,
                        help='Cases per parser (1-10000)')
    parser.add_argument('--max-input-mib', type=int, default=1,
                        help='Per-input cap (1-8 MiB)')
    args = parser.parse_args(argv)
    try:
        result = run_smoke(args.seed, args.cases,
                           args.max_input_mib * 1024 * 1024)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if result['seed_failures'] or result['unexpected_exceptions'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
