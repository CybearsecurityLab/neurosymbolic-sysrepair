"""Baseline 3 – Plan-and-Solve.

The planner generates a complete JSON remediation plan upfront; the executor
works through each step, retrying on failure and re-invoking the planner if
stuck.

LangGraph topology:
    START → planner_node → executor_node → status_node
                ↑                               |
                └───────────────────────────────┘  (conditional re-plan or next step)
"""

from __future__ import annotations

import json
import operator
import time
from typing import Annotated, TypedDict

from pydantic import BaseModel as PydanticBase

from langgraph.graph import END, START, StateGraph

from .base_agent import BaseAgent
from .state import AgentResult, PlanStep


# ---------------------------------------------------------------------------
# Pydantic models for structured planner output
# ---------------------------------------------------------------------------

class PlanStepSchema(PydanticBase):
    id: int
    description: str
    command_hint: str


class PlanResponse(PydanticBase):
    steps: list[PlanStepSchema]


# ---------------------------------------------------------------------------
# LangGraph state
# ---------------------------------------------------------------------------

class PlanAndSolveState(TypedDict):
    messages: Annotated[list[dict], operator.add]
    plan: list[dict]               # list of PlanStep dicts
    current_step_idx: int
    step_results: list[dict]
    executor_step_count: int
    planner_retry_count: int
    stuck: bool
    done: bool
    forced_halt: bool


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class PlanAndSolveAgent(BaseAgent):
    """Two-phase plan-then-execute agent with re-planning on failure."""

    MAX_EXECUTOR_STEPS: int = 50
    MAX_PLAN_STEPS: int = 15
    MAX_PLANNER_RETRIES: int = 3
    MAX_STEP_RETRIES: int = 3

    def run(self, system_prompt: str) -> AgentResult:
        start_time = time.time()
        graph = self._build_graph(system_prompt)
        initial_state: PlanAndSolveState = {
            "messages": [{"role": "system", "content": system_prompt}],
            "plan": [],
            "current_step_idx": 0,
            "step_results": [],
            "executor_step_count": 0,
            "planner_retry_count": 0,
            "stuck": False,
            "done": False,
            "forced_halt": False,
        }
        final_state = graph.invoke(initial_state)

        plan_steps = (
            [PlanStep(**s) for s in final_state["plan"]]
            if final_state["plan"]
            else []
        )
        steps_wasted = sum(
            1 for r in final_state["step_results"] if not r.get("success", True)
        )

        return AgentResult(
            baseline="plan_and_solve",
            model=self.model,
            scenario_id="",
            commands=self.commands,
            wall_time_seconds=time.time() - start_time,
            declared_done=final_state["done"],
            forced_halt=final_state["forced_halt"],
            plan=plan_steps,
            plan_length=len(plan_steps),
            steps_wasted=steps_wasted,
            trace=self.trace,
        )

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------

    def _build_graph(self, system_prompt: str):
        agent = self

        # ---- nodes -------------------------------------------------------

        def planner_node(state: PlanAndSolveState) -> dict:
            failure_context = ""
            if state["planner_retry_count"] > 0:
                last_results = state["step_results"][-3:] if state["step_results"] else []
                failure_context = (
                    f"\n\nPrevious plan failed. Last results:\n"
                    f"{json.dumps(last_results, indent=2)}\n"
                    "Revise your plan to address these failures."
                )

            plan_prompt = (
                "Generate a complete remediation plan as JSON.\n"
                f"Maximum {agent.MAX_PLAN_STEPS} steps.\n\n"
                "Return ONLY a JSON object in this exact format:\n"
                '{"steps": [{"id": 1, "description": "...", "command_hint": '
                '"exact bash command"}, ...]}\n\n'
                "Steps must be in dependency order. Each command_hint must be a "
                "single executable bash command."
                + failure_context
            )
            msgs = state["messages"] + [{"role": "user", "content": plan_prompt}]

            try:
                resp = agent.llm.structured(msgs, PlanResponse)
                plan_dicts = [
                    {
                        "id": s.id,
                        "description": s.description,
                        "command_hint": s.command_hint,
                    }
                    for s in resp.steps[: agent.MAX_PLAN_STEPS]
                ]
            except Exception:
                plan_dicts = []

            agent.trace.append({
                "node": "planner",
                "retry": state["planner_retry_count"],
                "prompt": plan_prompt,
                "plan": plan_dicts,
            })

            return {
                "messages": [{"role": "user", "content": plan_prompt}],
                "plan": plan_dicts,
                "current_step_idx": 0,
            }

        def executor_node(state: PlanAndSolveState) -> dict:
            idx = state["current_step_idx"]
            plan = state["plan"]
            if idx >= len(plan):
                return {"done": True}

            step = plan[idx]
            cmd = step["command_hint"]
            retry_count = 0
            step_cmds = []
            success = False

            for _attempt in range(agent.MAX_STEP_RETRIES):
                global_step = state["executor_step_count"] + len(step_cmds) + 1
                record = agent.bash(cmd, global_step)
                step_cmds.append(record)

                # Run verification scan after each command
                verify_passed, _verify_msg = agent.verify()
                if verify_passed or record.exit_code == 0 or agent._is_done(record):
                    success = True
                    break

                retry_count += 1
                # Ask LLM to produce a corrected command
                fix_prompt = (
                    f"Command failed: {cmd}\n"
                    f"stderr: {record.stderr[:300]}\n"
                    f"stdout: {record.stdout[:300]}\n"
                    f"Step goal: {step['description']}\n"
                    "Provide a corrected single bash command to achieve this step "
                    "goal. Output the command only."
                )
                fix_resp = agent.llm.chat(
                    state["messages"] + [{"role": "user", "content": fix_prompt}],
                    temperature=0.1,
                )
                cmd = (fix_resp.choices[0].message.content or "").strip().strip("`")

            result = {
                "step_id": step["id"],
                "success": success,
                "retry_count": retry_count,
                "commands": len(step_cmds),
            }
            agent.trace.append({
                "node": "executor",
                "plan_step": step,
                "commands": [
                    {"command": c.command, "exit_code": c.exit_code,
                     "stdout": c.stdout[:500], "stderr": c.stderr[:300]}
                    for c in step_cmds
                ],
                "success": success,
                "retry_count": retry_count,
                "verify_passed": verify_passed,
            })
            new_count = state["executor_step_count"] + len(step_cmds)
            stuck = not success and retry_count >= agent.MAX_STEP_RETRIES - 1

            return {
                "step_results": state["step_results"] + [result],
                "current_step_idx": idx + 1,
                "executor_step_count": new_count,
                "stuck": stuck,
                "done": verify_passed,
                "forced_halt": new_count >= agent.MAX_EXECUTOR_STEPS,
            }

        def status_node(state: PlanAndSolveState) -> dict:
            if state["done"] or state["forced_halt"]:
                return {}
            if state["current_step_idx"] >= len(state["plan"]):
                return {"done": True}
            if state["stuck"] and state["planner_retry_count"] < agent.MAX_PLANNER_RETRIES:
                return {
                    "planner_retry_count": state["planner_retry_count"] + 1,
                    "stuck": False,
                }
            if state["stuck"]:
                return {"done": True, "forced_halt": True}
            return {}

        # ---- routing -----------------------------------------------------

        def route_status(state: PlanAndSolveState) -> str:
            if state["done"] or state["forced_halt"]:
                return END
            if state["stuck"] and state["planner_retry_count"] <= agent.MAX_PLANNER_RETRIES:
                return "planner_node"
            if state["current_step_idx"] >= len(state["plan"]):
                return END
            return "executor_node"

        # ---- build -------------------------------------------------------

        sg = StateGraph(PlanAndSolveState)
        sg.add_node("planner_node", planner_node)
        sg.add_node("executor_node", executor_node)
        sg.add_node("status_node", status_node)
        sg.add_edge(START, "planner_node")
        sg.add_edge("planner_node", "executor_node")
        sg.add_edge("executor_node", "status_node")
        sg.add_conditional_edges(
            "status_node",
            route_status,
            {
                "planner_node": "planner_node",
                "executor_node": "executor_node",
                END: END,
            },
        )
        return sg.compile()
