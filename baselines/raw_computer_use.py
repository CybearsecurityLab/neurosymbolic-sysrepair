"""Baseline 1 – Raw Computer Use (open-loop tool-use agent).

The LLM receives the system prompt and a bash tool. It runs freely until it
signals REMEDIATION_COMPLETE or exhausts MAX_STEPS iterations.

LangGraph topology:
    START → agent_node → (tool_node → agent_node)* → END
"""

from __future__ import annotations

import json
import operator
import time
from typing import Annotated, TypedDict

from langgraph.graph import END, START, StateGraph

from .base_agent import BaseAgent
from .state import AgentResult, CommandRecord
from .tools import BASH_TOOL


# ---------------------------------------------------------------------------
# LangGraph state
# ---------------------------------------------------------------------------

class RawCUState(TypedDict):
    messages: Annotated[list[dict], operator.add]
    step_count: int
    done: bool
    forced_halt: bool


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class RawComputerUseAgent(BaseAgent):
    """Open-loop LLM agent with unrestricted bash tool access."""

    MAX_STEPS: int = 40

    def run(self, system_prompt: str) -> AgentResult:
        start_time = time.time()

        graph = self._build_graph()
        initial_state: RawCUState = {
            "messages": [{"role": "system", "content": system_prompt}],
            "step_count": 0,
            "done": False,
            "forced_halt": False,
        }
        final_state = graph.invoke(initial_state)

        return AgentResult(
            baseline="raw",
            model=self.model,
            scenario_id="",
            commands=self.commands,
            wall_time_seconds=time.time() - start_time,
            declared_done=final_state["done"],
            forced_halt=final_state["forced_halt"],
        )

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------

    def _build_graph(self):
        agent = self

        # ---- nodes -------------------------------------------------------

        def agent_node(state: RawCUState) -> dict:
            resp = agent.llm.chat(state["messages"], tools=[BASH_TOOL])
            msg = resp.choices[0].message
            ai_msg: dict = {"role": "assistant", "content": msg.content or ""}
            if msg.tool_calls:
                ai_msg["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in msg.tool_calls
                ]
            return {"messages": [ai_msg]}

        def tool_node(state: RawCUState) -> dict:
            last = state["messages"][-1]
            tool_calls = last.get("tool_calls", [])
            if not tool_calls:
                return {"done": True}

            tc = tool_calls[0]
            cmd = json.loads(tc["function"]["arguments"]).get("command", "echo noop")
            step = state["step_count"] + 1
            record = agent.bash(cmd, step)

            done = agent._is_done(record)
            tool_msg = {
                "role": "tool",
                "tool_call_id": tc["id"],
                "content": (
                    f"exit_code: {record.exit_code}\n"
                    f"stdout: {record.stdout}\n"
                    f"stderr: {record.stderr}"
                ),
            }
            return {
                "messages": [tool_msg],
                "step_count": step,
                "done": done,
                "forced_halt": step >= agent.MAX_STEPS,
            }

        # ---- routing -----------------------------------------------------

        def should_continue(state: RawCUState) -> str:
            if state["done"] or state["forced_halt"]:
                return END
            last = state["messages"][-1]
            if last.get("tool_calls"):
                return "tool_node"
            return END

        # ---- build -------------------------------------------------------

        sg = StateGraph(RawCUState)
        sg.add_node("agent_node", agent_node)
        sg.add_node("tool_node", tool_node)
        sg.add_edge(START, "agent_node")
        sg.add_conditional_edges(
            "agent_node",
            should_continue,
            {"tool_node": "tool_node", END: END},
        )
        sg.add_edge("tool_node", "agent_node")
        return sg.compile()
