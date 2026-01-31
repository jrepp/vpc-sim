from __future__ import annotations

import sqlite3
from pathlib import Path


def main() -> None:
    dbs = sorted(Path("backend").glob(".test*.db"))
    if not dbs:
        print("No api trace databases found.")
        return

    durations: list[float] = []
    rows: list[tuple[float, str, str, int, str | None, str | None]] = []
    span_rows: list[tuple[float, str]] = []
    for db in dbs:
        conn = sqlite3.connect(db)
        try:
            durations.extend(r[0] for r in conn.execute("SELECT duration_ms FROM api_traces"))
            rows.extend(
                conn.execute(
                    "SELECT duration_ms, method, path, status_code, action, namespace FROM api_traces"
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
    for duration, method, path, status, _action, _namespace in sorted(rows, reverse=True)[:10]:
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

    action_counts: dict[str, int] = {}
    for name, durs in span_buckets.items():
        if not name.startswith("ec2.action."):
            continue
        action = name.split("ec2.action.", 1)[1]
        action_counts[action] = len(durs)

    if action_counts:
        print("\nEC2 action call counts:")
        for action, count in sorted(action_counts.items(), key=lambda item: item[1], reverse=True):
            print(f"{count:4d}  {action}")

    namespace_counts: dict[str, int] = {}
    for _duration, _method, _path, _status, action, namespace in rows:
        if not namespace:
            continue
        if action:
            key = f"{namespace}:{action}"
        else:
            key = namespace
        namespace_counts[key] = namespace_counts.get(key, 0) + 1

    if namespace_counts:
        print("\nNamespace action counts:")
        for key, count in sorted(namespace_counts.items(), key=lambda item: item[1], reverse=True):
            print(f"{count:4d}  {key}")


if __name__ == "__main__":
    main()
