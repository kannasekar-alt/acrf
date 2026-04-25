"""
acrf_trace — causal trace library for AI agent communication.

Implements ACRF-08 (Cascading Failure Blindness) defense pattern.

Quickstart:
    from acrf_trace import wrap, get_store

    @wrap(agent_name="PriceAgent")
    def price_agent(ticker):
        return f"price: $150 for {ticker}"

    price_agent("TSLA")
    print(get_store().count())  # 1
"""

from acrf_trace.decorator import wrap
from acrf_trace.store import get_store, set_store, TraceStore, SQLiteTraceStore, Trace

__version__ = "0.1.0"
__all__ = [
    "wrap",
    "get_store",
    "set_store",
    "TraceStore",
    "SQLiteTraceStore",
    "Trace",
]
