"""
acrf_trace.cli — command-line interface for acrf-trace.

Commands:
    acrf-trace report   Print ACRF-08 compliance report
    acrf-trace clear    Clear all traces from the database
    acrf-trace count    Print number of traces recorded
"""

import sys
from datetime import timezone
from acrf_trace.store import SQLiteTraceStore


def cmd_report(db_path: str = "acrf_trace.db") -> None:
    """Print a human-readable ACRF-08 compliance report."""
    store = SQLiteTraceStore(db_path)
    traces = store.all()

    print()
    print("ACRF-08 Trace Report")
    print("=" * 50)
    print()

    if not traces:
        print("No traces found in database.")
        print(f"Database: {db_path}")
        print()
        print("To start recording traces, wrap your agent functions:")
        print("    from acrf_trace import wrap")
        print("    @wrap(agent_name='MyAgent')")
        print("    def my_agent(input):")
        print("        ...")
        return

    # Basic stats
    agent_counts: dict[str, int] = {}
    timestamps = []
    chains_with_parent = 0

    for t in traces:
        agent_counts[t.agent_name] = agent_counts.get(t.agent_name, 0) + 1
        timestamps.append(t.timestamp)
        if t.parent_trace_id:
            chains_with_parent += 1

    timestamps.sort()
    earliest = timestamps[0]
    latest = timestamps[-1]

    print(f"Database:     {db_path}")
    print(f"Total traces: {len(traces)}")
    print(f"Agents seen:  {len(agent_counts)}")
    print(f"Time range:   {earliest}")
    print(f"              → {latest}")
    print()

    # Per-agent summary
    print("Per-agent call counts:")
    for agent, count in sorted(agent_counts.items()):
        bar = "█" * count
        print(f"  {agent:<25} {count:>4} calls  {bar}")
    print()

    # ACRF-08 compliance checks
    print("ACRF-08 Compliance Checks:")
    print("-" * 50)

    # CF-2: Distributed tracing
    traces_with_id = sum(1 for t in traces if t.trace_id)
    cf2_pct = traces_with_id / len(traces) * 100
    cf2_status = "✓" if cf2_pct == 100 else "⚠"
    print(f"  CF-2 Trace IDs present:      {cf2_status} {cf2_pct:.0f}% of traces have trace IDs")

    # CF-2 parent tracing
    parent_pct = chains_with_parent / len(traces) * 100
    parent_status = "✓" if parent_pct > 50 else "✗"
    print(f"  CF-2 Causal chain links:     {parent_status} {parent_pct:.0f}% of traces reference a parent")

    # CF-3 integrity
    print(f"  CF-3 Log integrity hashes:   ✗ Not yet implemented (planned v0.2)")

    # CF-1 circuit breakers
    print(f"  CF-1 Circuit breakers:       ⚠ Cannot verify from traces alone")

    print()

    # Recommendations
    print("Recommendations:")
    if parent_pct == 0:
        print("  • Pass parent_trace_id when one agent calls another")
        print("    to enable full causal chain reconstruction (CF-2).")
    if cf2_pct < 100:
        print("  • Ensure all agent calls go through @wrap decorator.")
    print("  • Add integrity hashing in v0.2 to meet CF-3.")
    print()

    # Overall maturity
    cf2_met = cf2_pct == 100
    chain_met = parent_pct > 50
    if cf2_met and chain_met:
        level = 2
        label = "DEFINED"
    elif cf2_met:
        level = 1
        label = "INITIAL"
    else:
        level = 0
        label = "NONE"

    print(f"ACRF-08 Maturity Level: {level}/4 — {label}")
    print()


def cmd_clear(db_path: str = "acrf_trace.db") -> None:
    store = SQLiteTraceStore(db_path)
    count = store.count()
    store.clear()
    print(f"Cleared {count} traces from {db_path}.")


def cmd_count(db_path: str = "acrf_trace.db") -> None:
    store = SQLiteTraceStore(db_path)
    print(f"{store.count()} traces in {db_path}.")


def main() -> None:
    """Entry point for the acrf-trace CLI."""
    args = sys.argv[1:]

    if not args or args[0] == "help":
        print("Usage: acrf-trace <command>")
        print()
        print("Commands:")
        print("  report   Print ACRF-08 compliance report")
        print("  clear    Clear all traces from the database")
        print("  count    Print number of traces recorded")
        return

    command = args[0]
    db_path = args[1] if len(args) > 1 else "acrf_trace.db"

    if command == "report":
        cmd_report(db_path)
    elif command == "clear":
        cmd_clear(db_path)
    elif command == "count":
        cmd_count(db_path)
    else:
        print(f"Unknown command: {command}")
        print("Run 'acrf-trace help' for usage.")
        sys.exit(1)
