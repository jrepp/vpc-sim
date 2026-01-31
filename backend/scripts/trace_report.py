from __future__ import annotations

import sqlite3
from pathlib import Path


def main() -> None:
    dbs = sorted(Path("backend").glob(".test*.db"))
    if not dbs:
        print("No api trace databases found.")
        return

    durations: list[float] = []
    rows: list[tuple[float, str, str, int]] = []
    span_rows: list[tuple[float, str]] = []
    for db in dbs:
        conn = sqlite3.connect(db)
        try:
            durations.extend(r[0] for r in conn.execute("SELECT duration_ms FROM api_traces"))
            rows.extend(
                conn.execute(
                    "SELECT duration_ms, method, path, status_code FROM api_traces"
                )
            )
            span_rows.extend(
                conn.execute("SELECT duration_ms, name FROM api_spans")
            )
        finally:
            conn.close()

    if not durations:
        print("No api_traces rows found.")
        return

    durations.sort()
    idx = int(0.95 * (len(durations) - 1))
    p95 = durations[idx]
    print(f"p95={p95:.2f}ms, count={len(durations)}")
    print("\nTop 10 slowest calls:")
    for duration, method, path, status in sorted(rows, reverse=True)[:10]:
        print(f"{duration:8.2f}  {status}  {method} {path}")

    if not span_rows:
        return

    span_buckets: dict[str, list[float]] = {}
    for duration, name in span_rows:
        span_buckets.setdefault(name, []).append(duration)

    span_summary: list[tuple[float, int, str]] = []
    for name, durs in span_buckets.items():
        durs.sort()
        idx = int(0.95 * (len(durs) - 1))
        span_summary.append((durs[idx], len(durs), name))

    print("\nSpan p95 by name:")
    for p95, count, name in sorted(span_summary, reverse=True)[:10]:
        print(f"p95={p95:6.2f}ms  count={count:3d}  {name}")


if __name__ == "__main__":
    main()
