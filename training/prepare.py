"""Prepare the benchmark corpus: validate hashes and ingest through the real pipeline."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from training.dataset import prepare_datasets  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate and ingest the benchmark corpus")
    parser.add_argument("--benchmark", required=True)
    parser.add_argument("--output", default="benchmarks/prepared_dataset.json")
    args = parser.parse_args(argv)

    report = prepare_datasets(args.benchmark, progress=lambda p, m: print(f"[{p:3d}%] {m}"))
    report["prepared_at_utc"] = datetime.now(timezone.utc).isoformat()
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    ok = report["all_hashes_ok"] and report["all_counts_ok"]
    print(f"Prepared dataset written to {out}")
    print(f"Hashes OK: {report['all_hashes_ok']} | Counts OK: {report['all_counts_ok']}")
    for entry in report["files"]:
        print(
            f"  {entry['file']}: parsed={entry.get('parsed_events', 'n/a')} "
            f"expected={entry['expected_events']} hash_ok={entry['sha256_ok']}"
        )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
