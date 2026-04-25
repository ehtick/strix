"""SDK function-tool wrappers for the legacy ``file_edit`` tools.

These three tools (``str_replace_editor``, ``list_files``, ``search_files``)
operate on files inside the sandbox container's ``/workspace`` filesystem.
The legacy harness marks them ``sandbox_execution=True`` (default) so the
executor POSTs them to the in-container tool server.

The host-side SDK wrappers therefore delegate to ``post_to_sandbox`` —
the legacy implementations live in the container image and we don't
import them on the host (they pull in ``openhands_aci``, which is a
sandbox-only dependency).
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
async def str_replace_editor(
    ctx: RunContextWrapper,
    command: str,
    path: str,
    file_text: str | None = None,
    view_range: list[int] | None = None,
    old_str: str | None = None,
    new_str: str | None = None,
    insert_line: int | None = None,
) -> str:
    """View, create, or edit a file in the sandbox filesystem.

    Commands:

    - ``view`` — show file contents. Optionally restrict to a line range
      via ``view_range`` (1-indexed; ``[start, -1]`` for "from start to
      end of file").
    - ``create`` — write a new file with ``file_text``. Use this for
      exploit scripts, PoCs, helper modules, etc.
    - ``str_replace`` — find ``old_str`` in the file and replace with
      ``new_str``. ``old_str`` must be unique in the file; include
      enough surrounding context to make it so.
    - ``insert`` — insert ``new_str`` after line ``insert_line``.
    - ``undo_edit`` — revert the most recent edit to ``path``.

    Multi-line ``new_str`` / ``old_str`` / ``file_text`` use real
    newlines, not literal ``\\n``.

    Args:
        command: ``view`` / ``create`` / ``str_replace`` / ``insert`` /
            ``undo_edit``.
        path: File path. Relative paths anchor at ``/workspace``.
        file_text: Required for ``create``.
        view_range: Optional ``[start, end]`` (1-indexed) for ``view``.
        old_str: Required for ``str_replace`` — must be unique in file.
        new_str: Required for ``str_replace`` and ``insert``.
        insert_line: Required for ``insert``; new content goes AFTER
            this line.
    """
    return _dump(
        await post_to_sandbox(
            ctx,
            "str_replace_editor",
            {
                "command": command,
                "path": path,
                "file_text": file_text,
                "view_range": view_range,
                "old_str": old_str,
                "new_str": new_str,
                "insert_line": insert_line,
            },
        ),
    )


@strix_tool(timeout=120)
async def list_files(
    ctx: RunContextWrapper,
    path: str,
    recursive: bool = False,
) -> str:
    """List files and directories under a sandbox path.

    Output is sorted alphabetically and capped at 500 entries to avoid
    flooding the model with huge directory trees.

    Args:
        path: Directory path; relative paths anchor at ``/workspace``.
        recursive: When True, walks subdirectories.
    """
    return _dump(
        await post_to_sandbox(
            ctx,
            "list_files",
            {"path": path, "recursive": recursive},
        ),
    )


@strix_tool(timeout=120)
async def search_files(
    ctx: RunContextWrapper,
    path: str,
    regex: str,
    file_pattern: str = "*",
) -> str:
    """Recursively regex-search files in the sandbox using ripgrep.

    Fast — uses ``rg`` under the hood. Walks subdirectories. Use this
    for code-pattern hunts (``def\\s+authenticate``, ``API_KEY``,
    secrets, etc.) when you don't already know the file.

    Args:
        path: Root path to search. Relative paths anchor at ``/workspace``.
        regex: Pattern to match (PCRE-style; passed straight to ``rg``).
        file_pattern: Glob filter (e.g. ``"*.py"``, ``"*.{js,ts}"``).
            Defaults to all files.
    """
    return _dump(
        await post_to_sandbox(
            ctx,
            "search_files",
            {"path": path, "regex": regex, "file_pattern": file_pattern},
        ),
    )
