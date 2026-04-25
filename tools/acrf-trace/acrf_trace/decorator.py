"""
acrf_trace.decorator — the @wrap decorator.

Automatically captures input/output of wrapped agent functions
and links them into a causal chain using context variables.

When Agent A calls Agent B (both wrapped), B's trace automatically
records A's trace_id as its parent_trace_id. No extra code needed.
"""

from functools import wraps
from typing import Callable, Any

from acrf_trace.store import get_store, get_current_trace_id, set_current_trace_id


def wrap(agent_name: str) -> Callable:
    """
    Decorator factory. Records input/output and causal chain links.

    Usage:
        @wrap(agent_name="PriceAgent")
        def price_agent(input_msg):
            return f"price: $150 for {input_msg}"

        price_agent("TSLA")
        # Trace recorded with agent_name, input, output, timestamp.
        # If called from another wrapped agent, parent_trace_id is set.
    """
    if not isinstance(agent_name, str) or not agent_name.strip():
        raise ValueError("agent_name must be a non-empty string")

    def decorator(func: Callable) -> Callable:

        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            store = get_store()

            # Who called me? Read the current context trace ID.
            # If another wrapped agent is running, this will be their trace_id.
            # If nobody called me (I'm the root), this will be None.
            parent_trace_id = get_current_trace_id()

            input_data = {"args": args, "kwargs": kwargs}

            # Record the trace BEFORE calling the function
            # so we have the trace_id ready to set in context.
            import uuid
            from datetime import datetime, timezone
            from acrf_trace.store import Trace

            trace_id = str(uuid.uuid4())

            # Set MY trace_id as the current context.
            # Any wrapped agents I call will see this as their parent.
            token = set_current_trace_id(trace_id)

            try:
                output_data = func(*args, **kwargs)
            finally:
                # Restore the previous context (my caller's trace_id).
                # This is critical — without this, context leaks between calls.
                set_current_trace_id(parent_trace_id)

            # Now record the completed trace with full input/output.
            from datetime import datetime, timezone
            trace = Trace(
                trace_id=trace_id,
                agent_name=agent_name,
                input_data=input_data,
                output_data=output_data,
                timestamp=datetime.now(timezone.utc).isoformat(),
                parent_trace_id=parent_trace_id,
            )
            store._traces.append(trace) if hasattr(store, '_traces') else None

            # For SQLite store, use the record method but with our pre-built trace_id
            if not hasattr(store, '_traces'):
                import json, sqlite3
                from pathlib import Path
                with sqlite3.connect(store.db_path, isolation_level=None) as conn:
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

            return output_data

        return wrapper

    return decorator
