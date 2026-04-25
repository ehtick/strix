"""SDK function-tool wrapper for the legacy ``terminal_execute`` tool.

The terminal lives in the sandbox container — each persistent tmux
session is keyed by ``terminal_id`` on the in-container manager. The
host-side wrapper is a thin pass-through.
"""

from __future__ import annotations

import json
from typing import Any

from agents import RunContextWrapper

from strix.tools._decorator import strix_tool
from strix.tools._sandbox_dispatch import post_to_sandbox


def _dump(result: dict[str, Any]) -> str:
    return json.dumps(result, ensure_ascii=False, default=str)


@strix_tool(timeout=180)
async def terminal_execute(
    ctx: RunContextWrapper,
    command: str,
    is_input: bool = False,
    timeout: float | None = None,
    terminal_id: str | None = None,
    no_enter: bool = False,
) -> str:
    """Run a shell command in the sandboxed Kali tmux session.

    The session is **persistent** — environment variables, current
    directory, and running processes carry across calls keyed by
    ``terminal_id`` (default: ``"default"``). Use distinct ids to run
    multiple concurrent sessions.

    When to use this vs ``python_action``:

    - Shell work: CLI tools (nmap, sqlmap, ffuf, nuclei), package
      managers, file/system commands, services, process control. Use
      ``terminal_execute``.
    - Python code, data processing, HTTP automation, iterative scripting:
      use ``python_action`` instead — it's more structured and easier to
      debug. Don't run embedded Python via ``python -c`` or heredocs
      here.

    Avoid long pipelines and complex bash one-liners; prefer multiple
    simple calls for clarity and debugging. For multi-step shell work,
    separate tool calls beat ``&& ; |``-chained commands.

    Long-running commands:

    - Commands are **never** killed automatically — they keep running
      after the timeout fires.
    - ``timeout`` (max 60s, capped) only controls how long to wait for
      output before returning. On timeout the call returns
      ``status="running"``; on completion ``status="completed"``.
    - For daemons / very long jobs, append ``&`` to background.
    - Use an **empty command** to poll for new output from a running
      process (the call waits ``timeout`` seconds collecting output).
    - Use ``C-c`` / ``C-d`` / ``C-z`` to interrupt — special keys work
      automatically without setting ``is_input``.

    Interactive processes:

    - ``is_input=True`` sends the command as input to a running foreground
      process (REPL prompts, ``apt install`` y/n, etc.).
    - ``no_enter=True`` sends keystrokes without a trailing newline —
      useful for vim navigation (``gg``, ``5j``, ``i``), passwords, or
      multi-step keybindings.

    Special key support (tmux key names): ``C-c``, ``C-d``, ``Up``,
    ``Down``, ``F1``-``F12``, ``Enter``, ``Escape``, ``Tab``, ``Space``,
    ``BSpace``, ``M-f`` (alt), ``S-Tab`` (shift), and combinations like
    ``C-S-key``. Note: ``BSpace`` not ``Backspace``, ``Escape`` not
    ``Esc``.

    Working directory is tracked across calls and returned in the
    response. Large outputs are auto-truncated.

    Args:
        command: Shell command, special key (``C-c``), or empty string
            to poll a running process.
        is_input: Treat ``command`` as input to a running foreground
            process. Special keys auto-detect; you only need this for
            regular text input.
        timeout: Seconds to wait before returning partial output. Capped
            at 60s. Defaults to 30s.
        terminal_id: Persistent session selector. Use distinct ids for
            concurrent sessions.
        no_enter: When True, sends keystrokes without a trailing return.
    """
    return _dump(
        await post_to_sandbox(
            ctx,
            "terminal_execute",
            {
                "command": command,
                "is_input": is_input,
                "timeout": timeout,
                "terminal_id": terminal_id,
                "no_enter": no_enter,
            },
        ),
    )
