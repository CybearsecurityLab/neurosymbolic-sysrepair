"""OpenAI tool-call schema definitions shared by all baselines."""

from __future__ import annotations

BASH_TOOL: dict = {
    "type": "function",
    "function": {
        "name": "bash",
        "description": (
            "Execute a bash command in the target container and return "
            "stdout/stderr/exit_code."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The bash command to run.",
                }
            },
            "required": ["command"],
        },
    },
}
