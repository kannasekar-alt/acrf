"""
acrf_trace.store — trace storage backends.

Provides two interchangeable storage options:
  - TraceStore: in-memory list (fast, ephemeral, good for tests)
  - SQLiteTraceStore: SQLite file (persistent, good for production)

Both expose the same interface: record(), all(), clear(), count().
Users select which store is active via get_store() / set_store().
"""

import json
import sqlite3
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# Context variable that tracks the current trace ID.
# When Agent A is running, this is set to A's trace_id.
# When Agent B is called by A, B reads this to find its parent.
_current_trace_id: ContextVar[str | None] = ContextVar(
    "_current_trace_id", default=None
)


def get_current_trace_id() -> str | None:
    """Return the trace ID of the currently executing agent, if any."""
    return _current_trace_id.get()


def set_current_trace_id(trace_id: str | None):
    """Set the current trace ID. Returns a token for resetting."""
    return _current_trace_id.set(trace_id)


@dataclass
class Trace:
    """One recorded call to a wrapped agent function."""
    trace_id: str
    agent_name: str
    input_data: Any
    output_data: Any
    timestamp: str
    parent_trace_id: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class TraceStore:
    """In-memory list of traces."""

    def __init__(self) -> None:
        self._traces: list[Trace] = []

    def record(
        self,
        agent_name: str,
        input_data: Any,
        output_data: Any,
        parent_trace_id: str | None = None,
    ) -> Trace:
        trace = Trace(
            trace_id=str(uuid.uuid4()),
            agent_name=agent_name,
            input_data=input_data,
            output_data=output_data,
            timestamp=datetime.now(timezone.utc).isoformat(),
            parent_trace_id=parent_trace_id,
        )
        self._traces.append(trace)
        return trace

    def all(self) -> list[Trace]:
        return list(self._traces)

    def clear(self) -> None:
        self._traces.clear()

    def count(self) -> int:
        return len(self._traces)


class SQLiteTraceStore:
    """Persistent SQLite-backed trace store."""

    SCHEMA = """
        CREATE TABLE IF NOT EXISTS traces (
            trace_id        TEXT PRIMARY KEY,
            agent_name      TEXT NOT NULL,
            input_data      TEXT NOT NULL,
            output_data     TEXT NOT NULL,
            timestamp       TEXT NOT NULL,
            parent_trace_id TEXT
        )
    """

    def __init__(self, db_path: str | Path = "acrf_trace.db") -> None:
        self.db_path = Path(db_path)
        self._init_schema()

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path, isolation_level=None)
        try:
            yield conn
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(self.SCHEMA)

    def record(
        self,
        agent_name: str,
        input_data: Any,
        output_data: Any,
        parent_trace_id: str | None = None,
    ) -> Trace:
        trace = Trace(
            trace_id=str(uuid.uuid4()),
            agent_name=agent_name,
            input_data=input_data,
            output_data=output_data,
            timestamp=datetime.now(timezone.utc).isoformat(),
            parent_trace_id=parent_trace_id,
        )
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO traces VALUES (?, ?, ?, ?, ?, ?)",
                (
                    trace.trace_id,
                    trace.agent_name,
                    json.dumps(trace.input_data, default=str),
                    json.dumps(trace.output_data, default=str),
                    trace.timestamp,
                    trace.parent_trace_id,
                ),
            )
        return trace

    def all(self) -> list[Trace]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT trace_id, agent_name, input_data, output_data, "
                "timestamp, parent_trace_id FROM traces ORDER BY timestamp"
            ).fetchall()
        return [
            Trace(
                trace_id=r[0],
                agent_name=r[1],
                input_data=json.loads(r[2]),
                output_data=json.loads(r[3]),
                timestamp=r[4],
                parent_trace_id=r[5],
            )
            for r in rows
        ]

    def clear(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM traces")

    def count(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) FROM traces").fetchone()
        return row[0]

    def get_chain(self, trace_id: str) -> list[Trace]:
        """
        Trace backward from a trace_id to find the full causal chain.
        Returns the chain from root to the given trace, oldest first.
        """
        all_traces = {t.trace_id: t for t in self.all()}
        chain = []
        current = all_traces.get(trace_id)
        while current:
            chain.append(current)
            if current.parent_trace_id:
                current = all_traces.get(current.parent_trace_id)
            else:
                break
        return list(reversed(chain))


# Module-level default store
_store: TraceStore | SQLiteTraceStore = SQLiteTraceStore("acrf_trace.db")


def get_store() -> TraceStore | SQLiteTraceStore:
    return _store


def set_store(store: TraceStore | SQLiteTraceStore) -> None:
    global _store
    _store = store
