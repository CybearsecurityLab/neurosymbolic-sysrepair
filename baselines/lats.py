"""Baseline 5 – LATS (Language Agent Tree Search).

Monte Carlo Tree Search over command sequences.  Strategy C: no container
reset between rollouts; the container state accumulates across all simulations.

Parameters
----------
NUM_EXPANSIONS : int
    Number of candidate child commands generated per expansion.
MAX_ROLLOUTS : int
    Total number of simulate() calls before the search terminates.
UCB_C : float
    Exploration constant for UCB1.
MAX_SIMULATION_DEPTH : int
    Hard limit on tree depth (prevents infinite descent).

LangGraph topology:
    START → select_node → expand_node → simulate_node → backpropagate_node
                ↑                                                 |
                └─────────────────────────────────────────────────┘  (conditional)
"""

from __future__ import annotations

import math
import operator
import time
import uuid
from dataclasses import dataclass, field
from typing import Annotated, TypedDict

from pydantic import BaseModel as PM

from langgraph.graph import END, START, StateGraph

from .base_agent import BaseAgent
from .state import AgentResult, TreeNode, CommandRecord

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NUM_EXPANSIONS: int = 5
MAX_ROLLOUTS: int = 20
UCB_C: float = math.sqrt(2)
MAX_SIMULATION_DEPTH: int = 8


# ---------------------------------------------------------------------------
# Pydantic helpers (defined module-level to avoid repeated re-definition)
# ---------------------------------------------------------------------------

class _CmdList(PM):
    commands: list[str]


class _Score(PM):
    score: float
    is_terminal: bool
    is_fatal: bool


# ---------------------------------------------------------------------------
# LangGraph state
# ---------------------------------------------------------------------------

class LATSState(TypedDict):
    nodes: dict                              # node_id -> TreeNode dict (serialised)
    root_id: str
    rollout_count: int
    best_terminal_path: list[str] | None     # ordered list of commands
    done: bool
    forced_halt: bool


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class LATSAgent(BaseAgent):
    """Monte Carlo Tree Search agent (Language Agent Tree Search)."""

    def __init__(
        self,
        model: str,
        exec_fn,
        base_url: str = "http://localhost:11434/v1",
        verify_fn=None,
    ) -> None:
        super().__init__(model, exec_fn, base_url, verify_fn=verify_fn)
        self._system_prompt: str = ""

    def run(self, system_prompt: str) -> AgentResult:
        self._system_prompt = system_prompt
        start_time = time.time()

        root_id = str(uuid.uuid4())
        root = self._node_to_dict(
            TreeNode(
                node_id=root_id,
                parent_id=None,
                command="",
                stdout="",
                stderr="",
                exit_code=0,
                depth=0,
            )
        )

        graph = self._build_graph()
        initial_state: LATSState = {
            "nodes": {root_id: root},
            "root_id": root_id,
            "rollout_count": 0,
            "best_terminal_path": None,
            "done": False,
            "forced_halt": False,
        }
        final_state = graph.invoke(initial_state, {"recursion_limit": 500})

        best_path = final_state.get("best_terminal_path") or []
        nodes_visited = len(
            [n for n in final_state["nodes"].values() if n.get("visit_count", 0) > 0]
        )

        return AgentResult(
            baseline="lats",
            model=self.model,
            scenario_id="",
            commands=self.commands,
            wall_time_seconds=time.time() - start_time,
            declared_done=final_state["done"],
            forced_halt=final_state["forced_halt"],
            tree_nodes_visited=nodes_visited,
            lats_rollout_count=final_state["rollout_count"],
            trace=self.trace,
        )

    # ------------------------------------------------------------------
    # Tree helpers
    # ------------------------------------------------------------------

    def _node_to_dict(self, node: TreeNode) -> dict:
        return {
            "node_id": node.node_id,
            "parent_id": node.parent_id,
            "command": node.command,
            "stdout": node.stdout,
            "stderr": node.stderr,
            "exit_code": node.exit_code,
            "value": node.value,
            "visit_count": node.visit_count,
            "is_terminal": node.is_terminal,
            "is_fatal": node.is_fatal,
            "children": list(node.children),
            "depth": node.depth,
        }

    def _ucb1(self, node: dict, parent_visits: int) -> float:
        if node["visit_count"] == 0:
            return float("inf")
        return (node["value"] / node["visit_count"]) + UCB_C * math.sqrt(
            math.log(max(parent_visits, 1)) / node["visit_count"]
        )

    def _select_leaf(self, nodes: dict, root_id: str) -> str:
        """Traverse the tree using UCB1 to find the best leaf to expand."""
        current_id = root_id
        while True:
            node = nodes[current_id]
            children = [
                c
                for c in node["children"]
                if not nodes.get(c, {}).get("is_fatal", False)
            ]
            if not children:
                return current_id
            # Prefer unvisited children
            unvisited = [c for c in children if nodes[c]["visit_count"] == 0]
            if unvisited:
                return unvisited[0]
            parent_visits = node["visit_count"]
            current_id = max(
                children, key=lambda c: self._ucb1(nodes[c], parent_visits)
            )

    def _path_to_node(self, nodes: dict, node_id: str) -> list[str]:
        """Return the ordered sequence of commands from root to *node_id*."""
        path: list[str] = []
        nid: str | None = node_id
        while nid is not None:
            n = nodes[nid]
            if n["command"]:
                path.append(n["command"])
            nid = n["parent_id"]
        return list(reversed(path))

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------

    def _build_graph(self):
        agent = self

        # ---- nodes -------------------------------------------------------

        def select_node(state: LATSState) -> dict:
            if state["rollout_count"] >= MAX_ROLLOUTS or state["best_terminal_path"]:
                return {"done": True}
            leaf_id = agent._select_leaf(state["nodes"], state["root_id"])
            # Stash selected leaf under a reserved scratch key
            return {"nodes": {**state["nodes"], "__selected__": leaf_id}}

        def expand_node(state: LATSState) -> dict:
            selected_id = state["nodes"].get("__selected__")
            if not selected_id:
                return {}

            node = state["nodes"][selected_id]

            # Guard against over-deep expansion
            if node["depth"] >= MAX_SIMULATION_DEPTH:
                new_nodes = dict(state["nodes"])
                new_nodes.pop("__selected__", None)
                return {"nodes": new_nodes}

            path = agent._path_to_node(state["nodes"], selected_id)
            path_text = (
                "\n".join(f"$ {c}" for c in path) if path else "(no commands yet)"
            )
            expand_prompt = (
                f"Current path of commands executed:\n{path_text}\n\n"
                f"Last result: exit={node['exit_code']} "
                f"stdout={node['stdout'][:300]} "
                f"stderr={node['stderr'][:300]}\n\n"
                f"Generate {NUM_EXPANSIONS} distinct bash commands that each make "
                "different progress toward remediation.\n"
                'Return JSON only: {"commands": ["cmd1", "cmd2", ...]}'
            )
            msgs = [
                {"role": "system", "content": agent._system_prompt},
                {"role": "user", "content": expand_prompt},
            ]
            try:
                result = agent.llm.structured(msgs, _CmdList, temperature=0.5)
                candidates = result.commands[:NUM_EXPANSIONS]
            except Exception:
                candidates = [
                    "echo check_state",
                    "ls /etc",
                    "systemctl status",
                    "dpkg -l | tail -20",
                    "id",
                ]

            new_nodes = dict(state["nodes"])
            new_nodes.pop("__selected__", None)

            child_ids: list[str] = []
            for cmd in candidates:
                child_id = str(uuid.uuid4())
                child = agent._node_to_dict(
                    TreeNode(
                        node_id=child_id,
                        parent_id=selected_id,
                        command=cmd,
                        stdout="",
                        stderr="",
                        exit_code=-1,
                        depth=node["depth"] + 1,
                    )
                )
                new_nodes[child_id] = child
                child_ids.append(child_id)

            # Attach children to their parent
            new_nodes[selected_id] = {
                **node,
                "children": node["children"] + child_ids,
            }
            agent.trace.append({
                "node": "expand",
                "rollout": state["rollout_count"],
                "parent_command": node["command"],
                "depth": node["depth"],
                "candidates": candidates,
            })
            return {"nodes": new_nodes}

        def simulate_node(state: LATSState) -> dict:
            # Find the first unvisited true leaf (no children, not fatal)
            leaf_id: str | None = None
            for nid, n in state["nodes"].items():
                if nid.startswith("__"):
                    continue
                if (
                    n["visit_count"] == 0
                    and not n["is_fatal"]
                    and n["command"]
                    and not n["children"]
                ):
                    leaf_id = nid
                    break

            if not leaf_id:
                return {"rollout_count": state["rollout_count"] + 1}

            node = state["nodes"][leaf_id]
            record = agent.bash(node["command"], len(agent.commands) + 1)

            # Run verification scan
            verify_passed, _verify_msg = agent.verify()

            # Ask LLM to score the result
            score_prompt = (
                f"Command executed: {node['command']}\n"
                f"exit_code: {record.exit_code}\n"
                f"stdout: {record.stdout[:400]}\n"
                f"stderr: {record.stderr[:200]}\n\n"
                "Score the progress toward remediating the vulnerability "
                "(0.0=harmful, 0.5=neutral, 1.0=fully resolved).\n"
                "Also flag is_terminal (True if vulnerability appears resolved) "
                "and is_fatal (True if container is corrupted).\n"
                'Return JSON: {"score": float, "is_terminal": bool, "is_fatal": bool}'
            )
            try:
                score_result = agent.llm.structured(
                    [
                        {"role": "system", "content": agent._system_prompt},
                        {"role": "user", "content": score_prompt},
                    ],
                    _Score,
                    temperature=0.1,
                )
                score = max(0.0, min(1.0, score_result.score))
                is_terminal = verify_passed or score_result.is_terminal or agent._is_done(record)
                is_fatal = score_result.is_fatal
            except Exception:
                score = 0.5 if record.exit_code == 0 else 0.1
                is_terminal = verify_passed or agent._is_done(record)
                is_fatal = False

            agent.trace.append({
                "node": "simulate",
                "rollout": state["rollout_count"],
                "command": node["command"],
                "exit_code": record.exit_code,
                "stdout": record.stdout[:500],
                "stderr": record.stderr[:300],
                "score": score,
                "is_terminal": is_terminal,
                "is_fatal": is_fatal,
                "verify_passed": verify_passed,
            })

            new_nodes = dict(state["nodes"])
            new_nodes[leaf_id] = {
                **node,
                "stdout": record.stdout[:500],
                "stderr": record.stderr[:300],
                "exit_code": record.exit_code,
                "is_terminal": is_terminal,
                "is_fatal": is_fatal,
                "value": node["value"] + score,
                "visit_count": 1,
            }

            best_terminal = state["best_terminal_path"]
            if is_terminal:
                best_terminal = agent._path_to_node(new_nodes, leaf_id)

            new_rollout_count = state["rollout_count"] + 1
            return {
                "nodes": new_nodes,
                "rollout_count": new_rollout_count,
                "best_terminal_path": best_terminal,
                "done": is_terminal,
                "forced_halt": new_rollout_count >= MAX_ROLLOUTS,
            }

        def backpropagate_node(state: LATSState) -> dict:
            """Propagate visit counts and values up from visited leaves."""
            new_nodes = dict(state["nodes"])
            # Single-pass upward propagation for all visited non-root nodes
            for nid, n in list(new_nodes.items()):
                if nid.startswith("__"):
                    continue
                if n["visit_count"] > 0 and n["parent_id"]:
                    pid = n["parent_id"]
                    if pid in new_nodes:
                        parent = new_nodes[pid]
                        new_nodes[pid] = {
                            **parent,
                            "visit_count": parent["visit_count"] + 1,
                            "value": parent["value"]
                            + n["value"] / max(n["visit_count"], 1),
                        }
            return {"nodes": new_nodes}

        # ---- routing -----------------------------------------------------

        def should_continue(state: LATSState) -> str:
            if (
                state["done"]
                or state["forced_halt"]
                or state["rollout_count"] >= MAX_ROLLOUTS
            ):
                return END
            return "select_node"

        # ---- build -------------------------------------------------------

        sg = StateGraph(LATSState)
        sg.add_node("select_node", select_node)
        sg.add_node("expand_node", expand_node)
        sg.add_node("simulate_node", simulate_node)
        sg.add_node("backpropagate_node", backpropagate_node)
        sg.add_edge(START, "select_node")
        sg.add_edge("select_node", "expand_node")
        sg.add_edge("expand_node", "simulate_node")
        sg.add_edge("simulate_node", "backpropagate_node")
        sg.add_conditional_edges(
            "backpropagate_node",
            should_continue,
            {"select_node": "select_node", END: END},
        )
        return sg.compile()
