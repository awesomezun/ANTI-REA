"""Poll untrusted report intake only. No model, executable, or command launches.

Stop with Ctrl-C or .runs/defense-loop/STOP. The scheduled defender agent is a
separate orchestrator; this watcher never builds or publishes an artifact.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from antirea.exchange import Exchange, ExchangeBusy, ExchangeError  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--incoming", type=Path)
    parser.add_argument("--outbound", type=Path, required=True)
    parser.add_argument("--project", default="ledger")
    parser.add_argument("--interval", type=float, default=10)
    parser.add_argument("--stable-seconds", type=float, default=5)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    if not 0.1 <= args.interval <= 60:
        parser.error("interval must be 0.1..60 seconds")
    try:
        exchange = Exchange(args.root, args.incoming or args.root / "rea-analysis-reports", args.outbound,
                            project=args.project, stable_seconds=args.stable_seconds)
        previous = None
        while True:
            try:
                result = exchange.scan()
            except ExchangeBusy:
                result = {"status": "busy", "reason": "another exchange operation holds the lock; polling will retry"}
            fingerprint = json.dumps(result, sort_keys=True, ensure_ascii=False)
            if fingerprint != previous:
                print(fingerprint, flush=True)
                previous = fingerprint
            if args.once or result.get("status") == "stopped":
                return 1 if result.get("status") in {"rejected", "busy"} else 0
            # Short sleeps make the stop marker responsive even with long polls.
            deadline = time.monotonic() + args.interval
            while time.monotonic() < deadline:
                if (exchange.state_dir / "STOP").exists():
                    print('{"status":"stopped"}', flush=True)
                    return 0
                time.sleep(min(0.25, max(0, deadline - time.monotonic())))
    except KeyboardInterrupt:
        return 0
    except (ExchangeError, OSError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
