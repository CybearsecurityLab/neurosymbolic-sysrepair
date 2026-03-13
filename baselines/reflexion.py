"""Baseline 4 – Reflexion.

The generator runs a full tool-use loop (up to MAX_STEPS_PER_CYCLE steps).  If
it fails, the reflector analyses the execution trace and produces a correction
strategy.  The generator is then re-invoked with that correction appended to
the system prompt.  Up to MAX_CYCLES cycles are attempted.

LangGraph topology:
    START → generator_node ──(done)──→ END
                   ↑             ↓(failed)
                   └── reflector_node
"""

from __future__ import annotations

import json
import operator
import time
from typing import Annotated, TypedDict

from langgraph.graph import END, START, StateGraph

from .base_agent import BaseAgent
from .state import AgentResult, CommandRecord, ReflectionRecord
from .tools import BASH_TOOL


# ---------------------------------------------------------------------------
# LangGraph state
# ---------------------------------------------------------------------------

class ReflexionState(TypedDict):
    messages: Annotated[list[dict], operator.add]
    current_cycle: int
    correction_strategy: str
    cycle_commands: list        # CommandRecord objects for current cycle
    all_commands: list          # cumulative CommandRecord objects
    reflections: list           # ReflectionRecord objects
    done: bool
    forced_halt: bool


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class ReflexionAgent(BaseAgent):
    """Generator + reflector loop with up to MAX_CYCLES reflection passes."""

    MAX_STEPS_PER_CYCLE: int = 40
    MAX_CYCLES: int = 5

    def run(self, system_prompt: str) -> AgentResult:
        start_time = time.time()
        graph = self._build_graph(system_prompt)
        initial_state: ReflexionState = {
            "messages": [{"role": "system", "content": system_prompt}],
            "current_cycle": 0,
            "correction_strategy": "",
            "cycle_commands": [],
            "all_commands": [],
            "reflections": [],
            "done": False,
            "forced_halt": False,
        }
        final_state = graph.invoke(initial_state)

        # self.commands is already populated by self.bash() calls in nodes
        return AgentResult(
            baseline="reflexion",
            model=self.model,
            scenario_id="",
            commands=self.commands,
            wall_time_seconds=time.time() - start_time,
            declared_done=final_state["done"],
            forced_halt=final_state["forced_halt"],
            reflection_cycles=final_state["current_cycle"],
            reflections=final_state["reflections"],
        )

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------

    def _build_graph(self, system_prompt: str):
        agent = self

        # ---- nodes -------------------------------------------------------

        def generator_node(state: ReflexionState) -> dict:
            correction = state["correction_strategy"]
            cycle_prompt = system_prompt
            if correction:
                cycle_prompt += f"\n\n## Correction from Previous Attempt\n{correction}"

            msgs = [{"role": "system", "content": cycle_prompt}]
            cycle_cmds: list[CommandRecord] = []

            for step in range(1, agent.MAX_STEPS_PER_CYCLE + 1):
                resp = agent.llm.chat(msgs, tools=[BASH_TOOL], temperature=0.2)
                msg = resp.choices[0].message

                ai_msg: dict = {"role": "assistant", "content": msg.content or ""}
                if msg.tool_calls:
                    tc = msg.tool_calls[0]
                    ai_msg["tool_calls"] = [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments,
                            },
                        }
                    ]
                    cmd = json.loads(tc.function.arguments).get("command", "echo noop")
                    record = agent.bash(cmd, step)
                    cycle_cmds.append(record)

                    tool_msg = {
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": (
                            f"exit_code: {record.exit_code}\n"
                            f"stdout: {record.stdout[:800]}\n"
                            f"stderr: {record.stderr[:400]}"
                        ),
                    }
                    msgs += [ai_msg, tool_msg]

                    if agent._is_done(record):
                        return {
                            "messages": msgs[1:],   # skip re-adding system msg
                            "cycle_commands": cycle_cmds,
                            "all_commands": state["all_commands"] + cycle_cmds,
                            "done": True,
                        }
                else:
                    # No tool call — check if model declared completion in text
                    content = msg.content or ""
                    if any(
                        w in content.upper()
                        for w in ["DONE", "COMPLETE", "REMEDIATED"]
                    ):
                        return {
                            "cycle_commands": cycle_cmds,
                            "all_commands": state["all_commands"] + cycle_cmds,
                            "done": True,
                        }
                    break

            return {
                "cycle_commands": cycle_cmds,
                "all_commands": state["all_commands"] + cycle_cmds,
                "done": False,
            }

        def reflector_node(state: ReflexionState) -> dict:
            cycle_cmds: list[CommandRecord] = state["cycle_commands"]
            trace_lines = []
            for i, c in enumerate(cycle_cmds):
                trace_lines.append(
                    f"[{i + 1}] $ {c.command}\n"
                    f"     exit={c.exit_code}"
                    f"  stdout={c.stdout[:200]}"
                    f"  stderr={c.stderr[:200]}"
                )
            trace_text = "\n".join(trace_lines)

            reflect_prompt = (
                "You are a strict technical auditor reviewing a failed remediation attempt.\n\n"
                f"Execution trace (cycle {state['current_cycle'] + 1}):\n{trace_text}\n\n"
                "The remediation FAILED. Analyze and output:\n"
                "Root Cause: <what specifically went wrong>\n"
                "Wrong Assumption: <what the agent incorrectly assumed about the system>\n"
                "Correction Strategy: <precise instructions for the next attempt, be specific>"
            )
            resp = agent.llm.chat(
                [
                    {
                        "role": "system",
                        "content": "You are a security audit assistant.",
                    },
                    {"role": "user", "content": reflect_prompt},
                ],
                temperature=0.1,
            )
            reflection_text = resp.choices[0].message.content or ""

            # Extract correction strategy section
            lines = reflection_text.split("\n")
            correction = "\n".join(
                ln
                for ln in lines
                if "Correction" in ln or ln.startswith("  ") or ln.startswith("- ")
            )
            if not correction:
                correction = reflection_text

            rec = ReflectionRecord(
                cycle=state["current_cycle"],
                generator_commands=state["cycle_commands"],
                reflection_text=reflection_text,
                correction_strategy=correction,
            )
            new_cycle = state["current_cycle"] + 1
            return {
                "current_cycle": new_cycle,
                "correction_strategy": correction,
                "reflections": state["reflections"] + [rec],
                "cycle_commands": [],
                "forced_halt": new_cycle >= agent.MAX_CYCLES,
            }

        # ---- routing -----------------------------------------------------

        def route_after_generator(state: ReflexionState) -> str:
            if state["done"] or state["forced_halt"]:
                return END
            if state["current_cycle"] >= agent.MAX_CYCLES:
                return END
            return "reflector_node"

        def route_after_reflector(state: ReflexionState) -> str:
            if state["forced_halt"]:
                return END
            return "generator_node"

        # ---- build -------------------------------------------------------

        sg = StateGraph(ReflexionState)
        sg.add_node("generator_node", generator_node)
        sg.add_node("reflector_node", reflector_node)
        sg.add_edge(START, "generator_node")
        sg.add_conditional_edges(
            "generator_node",
            route_after_generator,
            {"reflector_node": "reflector_node", END: END},
        )
        sg.add_conditional_edges(
            "reflector_node",
            route_after_reflector,
            {"generator_node": "generator_node", END: END},
        )
        return sg.compile()
