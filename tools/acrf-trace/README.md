# acrf-trace

A causal trace tool for AI agent communication.
Implements the ACRF-08 (Cascading Failure Blindness) defense pattern.

Part of the ACRF framework: https://github.com/kannasekar-alt/ACRF
Presented at RSA Conference 2026.

---

## The problem this solves

Imagine PriceAgent calls TradeAgent, which calls ExecutionAgent:

    PriceAgent -> TradeAgent -> ExecutionAgent

ExecutionAgent makes a bad trade. Your team asks: who caused this?

Without tracing -- nobody knows. The chain is invisible.
This is ACRF-08: Cascading Failure Blindness.

acrf-trace gives every agent call a unique ID, links each call
to whoever triggered it, and lets you reconstruct the full chain
from any single action -- all the way back to the root cause.

If TradeAgent received poisoned input, you find it instantly:

    ExecutionAgent <- TradeAgent (POISONED HERE) <- PriceAgent

---

## Install

    pip install acrf-trace

Or from source:

    git clone https://github.com/kannasekar-alt/ACRF.git
    cd tools/acrf-trace
    pip install -e .

---

## Quickstart -- 2 lines to add tracing

Before (your existing agent code):

    def price_agent(ticker):
        return f"price: $150 for {ticker}"

After (with tracing added):

    from acrf_trace import wrap

    @wrap(agent_name="PriceAgent")
    def price_agent(ticker):
        return f"price: $150 for {ticker}"

That is the only change. Every call is now recorded automatically.

---

## Causal chain tracing -- agents calling agents

When agents call other agents, the chain links automatically.
No extra code needed. No arguments to pass. It just works.

Example -- 3 agents in a chain:

    from acrf_trace import wrap

    @wrap(agent_name="PriceAgent")
    def price_agent(ticker):
        return trade_agent(ticker, action="BUY")

    @wrap(agent_name="TradeAgent")
    def trade_agent(ticker, action):
        return execution_agent(f"{action} {ticker}")

    @wrap(agent_name="ExecutionAgent")
    def execution_agent(order):
        return f"executed: {order}"

    price_agent("TSLA")

What gets recorded:

    PriceAgent      trace: f1966a1e   parent: ROOT
    TradeAgent      trace: cc525327   parent: f1966a1e
    ExecutionAgent  trace: 0b63544f   parent: cc525327

PriceAgent started the chain (ROOT).
TradeAgent was called BY PriceAgent.
ExecutionAgent was called BY TradeAgent.

---

## Trace backward from any agent

If ExecutionAgent produced bad output, find the root cause:

    from acrf_trace import get_store

    chain = get_store().get_chain("0b63544f")

    for hop in chain:
        print(hop.agent_name)
        print("  Input: ", hop.input_data)
        print("  Output:", hop.output_data)
        print()

Output:

    PriceAgent
      Input:  args=('TSLA',)
      Output: executed: BUY TSLA

    TradeAgent
      Input:  args=('TSLA',) kwargs={'action': 'BUY'}
      Output: trade decided, then executed: BUY TSLA

    ExecutionAgent
      Input:  args=('BUY TSLA',)
      Output: executed: BUY TSLA

Full chain. Every input. Every output. Every hop.

---

## CLI report -- ACRF-08 compliance check

After your agents have been running, generate a compliance report:

    acrf-trace report

Example output:

    ACRF-08 Trace Report
    ==================================================
    Database:     acrf_trace.db
    Total traces: 3
    Agents seen:  3

    Per-agent call counts:
      ExecutionAgent     1 calls
      PriceAgent         1 calls
      TradeAgent         1 calls

    ACRF-08 Compliance Checks:
      CF-2 Trace IDs present:      100% of traces have trace IDs
      CF-2 Causal chain links:     67% of traces reference a parent
      CF-3 Log integrity hashes:   Not yet implemented (planned v0.2)
      CF-1 Circuit breakers:       Cannot verify from traces alone

    ACRF-08 Maturity Level: 2/4 - DEFINED

Other CLI commands:

    acrf-trace count     how many traces are recorded
    acrf-trace clear     wipe the database and start fresh

---

## What the maturity levels mean

    Level 0 - NONE      No tracing at all
    Level 1 - INITIAL   Trace IDs exist but no causal links
    Level 2 - DEFINED   Full causal chain reconstructable
    Level 3 - MANAGED   Log integrity protected against tampering
    Level 4 - OPTIMIZED Tested time-to-reconstruct meets a defined target

Installing acrf-trace gets you to Level 2 with two lines of code
per agent function.

---

## Storage

Traces are saved to acrf_trace.db (SQLite) in your current directory.
The file survives process restarts. You can run agents today and
query the data tomorrow.

Use a custom database path:

    from acrf_trace import set_store
    from acrf_trace.store import SQLiteTraceStore

    set_store(SQLiteTraceStore("/var/log/agents/traces.db"))

Use in-memory storage for tests (no file created):

    from acrf_trace import set_store
    from acrf_trace.store import TraceStore

    set_store(TraceStore())

---

## ACRF-08 control objectives addressed

    CF-2  Every agent call has a trace ID.
          Every call records who triggered it (parent trace ID).
          Full causal chain reconstructable from any single action.

Planned for v0.2:

    CF-3  Integrity hashes on trace records.
          Detects if anyone tampered with the logs.

Out of scope for this library (your infrastructure):

    CF-1  Circuit breakers that halt agent chains on anomaly.
    CF-4  Tested time-to-reconstruct a cause chain.

---

## Works with any Python agent framework

acrf-trace is framework-agnostic. Works with:

    LangChain agents
    CrewAI agents
    AutoGen agents
    Custom Python functions
    Any callable that takes input and returns output

If it is a Python function, you can wrap it.

---

## Authors

Ravi Karthick Sankara Narayanan
Kanna Sekar

## License

Apache 2.0
