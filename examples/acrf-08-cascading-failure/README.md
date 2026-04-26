# ACRF-08: Cascading Failure Blindness

Tools and examples for detecting and defending against cascading failure blindness in AI agent systems.

**ACRF Risk:** 08
**AIVSS Severity:** High (7.4)
**OWASP Agentic:** ASI08 Cascading Failures
**OWASP MCP:** MCP08 Lack of Audit

---

## What this covers

Agent A calls B calls C calls D. When D does something wrong, there is
no practical way to reconstruct whose intent initiated the chain, which
hop introduced the error, or how to stop the cascade.

This folder contains two things:

1. Example YAML files describing real multi-agent systems (travel booking,
automated trading) that you can use as starting points for your own
ACRF-08 assessment.

2. The acrf-trace library (in tools/acrf-trace/) which gives every agent
call a trace ID, links each call to its parent, and lets you reconstruct
the full causal chain from any single action.

---

## Example systems in this folder

**travel-booking-agents.yaml**
A travel concierge agent coordinating with flight, hotel, and car rental
booking agents, plus an external deal-finder. Models a realistic
multi-agent system with cross-boundary channels and high-blast-radius
actions (actual bookings, payments).

**trading-research-agents.yaml**
A research analyst agent coordinating with market data, portfolio
modelling, and external news summary agents. A separate execution agent
can place actual trades. Models a system where cascading failures have
direct financial consequences.

Use these as starting points. Replace the fictional agents with your
own system description, fill in the evidence section, and run:

    acrf assess trading-research-agents.yaml

---

## How to use acrf-trace in your real environment

acrf-trace is the reference implementation of the ACRF-08 defense pattern.
It implements CF-2: distributed tracing spanning all agent hops.

Install it:

    pip install acrf-trace

Or from source:

    cd tools/acrf-trace
    pip install -e .

Add two lines to any agent function:

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

Every call is now recorded. The full chain is reconstructable.

---

## Tracing a cascade after an incident

If ExecutionAgent produced a bad trade, find the root cause:

    from acrf_trace import get_store

    chain = get_store().get_chain("execution-agent-trace-id")

    for hop in chain:
        print(hop.agent_name)
        print("  Input: ", hop.input_data)
        print("  Output:", hop.output_data)

Output:

    PriceAgent
      Input:  args=('TSLA',)
      Output: BUY 10 shares TSLA

    TradeAgent
      Input:  args=('TSLA',) kwargs={'action': 'BUY'}
      Output: trade confirmed

    ExecutionAgent
      Input:  args=('BUY TSLA',)
      Output: executed: BUY TSLA at wrong price

Full chain. Every input. Every output. Every hop.
If PriceAgent received a poisoned price feed - you find it here.

---

## Generate a compliance report

After your agents have been running:

    acrf-trace report

Shows per-agent call counts, causal chain coverage, and your current
ACRF-08 maturity level.

---

## ACRF-08 maturity levels

    Level 0 - NONE      No tracing. No circuit breakers.
    Level 1 - INITIAL   Trace IDs exist but no causal chain links.
    Level 2 - DEFINED   Full causal chain reconstructable from any action.
    Level 3 - MANAGED   Log integrity protected against tampering.
    Level 4 - OPTIMIZED Tested time-to-reconstruct meets a defined target.

Installing acrf-trace gets you to Level 2 with two lines of code
per agent function.

---

## Control objectives

    CF-1  Circuit breakers on inter-agent channels with automatic trip thresholds.
    CF-2  Distributed tracing spans all agent hops - full cascade reconstructable.
    CF-3  Trace and log integrity protected against modification.
    CF-4  Tested MTTR target for reconstructing an agent-action cause chain.

acrf-trace directly addresses CF-2.
CF-3 integrity hashing is planned for acrf-trace v0.2.
CF-1 and CF-4 require infrastructure changes in your own environment.

---

## Attribution

Part of the ACRF framework: https://github.com/kannasekar-alt/ACRF
Presented at RSA Conference 2026.

Authors: Ravi Karthick Sankara Narayanan and Kanna Sekar

Licensed under Apache 2.0.

## Built with

- acrf-trace 0.1.0 (pip install acrf-trace)
- Python 3.11
- SQLite - persistent trace storage built into Python, no server needed
- PyYAML 6.0 - system description example files
- Docker + Docker Compose - planned for v0.2 cascading failure demo

## Security patterns implemented

- Distributed tracing - every agent call gets a unique trace ID
- Causal chain linking - parent trace ID connects every hop
- Persistent audit store - SQLite database survives process restarts
- Backward trace reconstruction - get_chain() walks from any point to root
- ACRF-08 maturity scoring - CF-1 through CF-4 control objectives assessed

## How RBAC and ABAC apply here

**RBAC (Role-Based Access Control):**
Trace data reveals which agents called which actions.
With role awareness, you can detect violations in the causal chain:
a monitor-role agent calling an execute-role action appears
immediately in the trace. The chain shows not just WHAT happened
but WHO had authority to do it at each hop.

**ABAC (Attribute-Based Access Control):**
Chain depth and agent attributes should drive circuit breaker policy:
- chain_depth > 5: flag for human review
- chain_depth > 10: automatic circuit breaker fires
- unknown_agent in chain: halt and alert immediately
- parent_trace_id missing: reject - unlinked call cannot be trusted

acrf-trace captures every attribute needed to enforce these policies.
Version 0.2 will add integrity hashing (CF-3) and attribute-based
circuit breakers that use chain metadata to halt cascades automatically.

## What the cybersecurity community can take from this

When something goes wrong in a multi-agent system,
Mean Time To Root Cause (MTTR) is the metric that matters.

Without tracing: MTTR = hours or days (manual log correlation across systems)
With acrf-trace: MTTR = seconds (one get_chain() call reconstructs everything)

Traditional SIEMs (Splunk, Sentinel, Chronicle) see agent logs
but cannot reconstruct causal intent across agent boundaries.
acrf-trace fills that gap - purpose-built for AI agent communication chains.

If your SIEM gives you logs today, acrf-trace gives you causality.
The difference is the difference between finding the fire
and understanding who started it and why.
