"""Baseline 2 – ReAct (Reasoning + Acting).

Forces an explicit Thought → Action → Observation cycle using three separate
LLM calls per step.

LangGraph topology:
    START → thought_node → action_node → thought_node → ... → END
"""

from __future__ import annotations

import operator
import time
from typing import Annotated, TypedDict

from langgraph.graph import END, START, StateGraph

from .base_agent import BaseAgent
from .state import AgentResult


# ---------------------------------------------------------------------------
# LangGraph state
# ---------------------------------------------------------------------------

class ReActState(TypedDict):
    messages: Annotated[list[dict], operator.add]
    last_observation: str
    step_count: int
    done: bool
    forced_halt: bool


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class ReActAgent(BaseAgent):
    """Explicit Thought → Action → Observation loop."""

    MAX_STEPS: int = 40

    def run(self, system_prompt: str) -> AgentResult:
        start_time = time.time()
        graph = self._build_graph(system_prompt)
        initial_state: ReActState = {
            "messages": [{"role": "system", "content": system_prompt}],
            "last_observation": "Beginning remediation. Analyze the system state above.",
            "step_count": 0,
            "done": False,
            "forced_halt": False,
        }
        final_state = graph.invoke(initial_state)
        return AgentResult(
            baseline="react",
            model=self.model,
            scenario_id="",
            commands=self.commands,
            wall_time_seconds=time.time() - start_time,
            declared_done=final_state["done"],
            forced_halt=final_state["forced_halt"],
            trace=self.trace,
        )

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------

    def _build_graph(self, system_prompt: str):
        agent = self

        # ---- nodes -------------------------------------------------------

        def thought_node(state: ReActState) -> dict:
            thought_prompt = (
                f"Observation: {state['last_observation']}\n"
                f"Step {state['step_count']}/{agent.MAX_STEPS}.\n\n"
                "Based on this observation and your remediation goal, what is your next "
                "reasoning step?\n"
                "Format exactly: Thought: <your technical reasoning>"
            )
            msgs = state["messages"] + [{"role": "user", "content": thought_prompt}]
            resp = agent.llm.chat(msgs, temperature=0.2)
            thought_text = resp.choices[0].message.content or ""
            agent.trace.append({
                "node": "thought",
                "step": state["step_count"],
                "prompt": thought_prompt,
                "response": thought_text,
            })
            return {
                "messages": [
                    {"role": "user", "content": thought_prompt},
                    {"role": "assistant", "content": thought_text},
                ]
            }

        def action_node(state: ReActState) -> dict:
            last_thought = state["messages"][-1]["content"]
            action_prompt = (
                f"{last_thought}\n\n"
                "Based on this reasoning, what single bash command should you execute?\n"
                "If remediation is complete, output: DONE\n"
                "Otherwise output the exact command only, no explanation, no markdown."
            )
            msgs = state["messages"] + [{"role": "user", "content": action_prompt}]
            resp = agent.llm.chat(msgs, temperature=0.1)
            cmd_text = (resp.choices[0].message.content or "").strip()

            if cmd_text.upper() == "DONE" or not cmd_text:
                agent.trace.append({
                    "node": "action",
                    "step": state["step_count"],
                    "prompt": action_prompt,
                    "response": cmd_text,
                    "action": "DONE",
                })
                return {
                    "messages": [
                        {"role": "user", "content": action_prompt},
                        {"role": "assistant", "content": cmd_text},
                    ],
                    "done": True,
                }

            # Strip markdown fences if the model wraps in backticks
            cmd_text = cmd_text.strip("`").strip()
            if cmd_text.startswith("bash\n"):
                cmd_text = cmd_text[5:]

            step = state["step_count"] + 1
            record = agent.bash(cmd_text, step)
            obs = (
                f"exit_code: {record.exit_code}\n"
                f"stdout: {record.stdout[:1000]}\n"
                f"stderr: {record.stderr[:500]}"
            )
            # Run verification scan and append pass/fail to observation
            verify_passed, verify_msg = agent.verify()
            obs += f"\n\n{verify_msg}"
            done = verify_passed or agent._is_done(record)

            agent.trace.append({
                "node": "action",
                "step": step,
                "prompt": action_prompt,
                "response": cmd_text,
                "command": cmd_text,
                "exit_code": record.exit_code,
                "stdout": record.stdout[:1000],
                "stderr": record.stderr[:500],
                "verify": verify_msg,
                "done": done,
            })

            return {
                "messages": [
                    {"role": "user", "content": action_prompt},
                    {"role": "assistant", "content": cmd_text},
                ],
                "last_observation": obs,
                "step_count": step,
                "done": done,
                "forced_halt": step >= agent.MAX_STEPS,
            }

        # ---- routing -----------------------------------------------------

        def should_continue(state: ReActState) -> str:
            if state["done"] or state["forced_halt"]:
                return END
            return "thought_node"

        # ---- build -------------------------------------------------------

        sg = StateGraph(ReActState)
        sg.add_node("thought_node", thought_node)
        sg.add_node("action_node", action_node)
        sg.add_edge(START, "thought_node")
        sg.add_edge("thought_node", "action_node")
        sg.add_conditional_edges(
            "action_node",
            should_continue,
            {"thought_node": "thought_node", END: END},
        )
        return sg.compile()
