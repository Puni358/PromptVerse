"""CLI:  python -m bankguard "Transfer $200 to savings"      (or pipe lines on stdin)"""
import argparse
import json
import sys

from .firewall import Config, Firewall


def main() -> int:
    p = argparse.ArgumentParser(prog="bankguard", description="Banking prompt-injection firewall")
    p.add_argument("message", nargs="?", help="message to check (omit to read one message per stdin line)")
    p.add_argument("--source", default="user", choices=["user", "document", "tool", "web"])
    p.add_argument("--strict", action="store_true", help="block anything that is not a recognised banking request")
    p.add_argument("--compact", action="store_true", help="one-line JSON")
    args = p.parse_args()

    fw = Firewall(Config(strict_intent=args.strict))
    msgs = [args.message] if args.message is not None else [l.rstrip("\n") for l in sys.stdin if l.strip()]
    rc = 0
    for m in msgs:
        v = fw.check(m, source=args.source)
        print(json.dumps(v, ensure_ascii=False, indent=None if args.compact else 2))
        rc = rc or (1 if v["status"] == "blocked" else 0)
    return rc


if __name__ == "__main__":
    sys.exit(main())
