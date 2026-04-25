"""Per-agent todo tools.

In-memory only — todos live for the lifetime of one scan, scoped per
agent via ``ctx.context['agent_id']``. Bulk forms are preserved so the
prompt-template documentation still works (``todos`` / ``updates`` /
``todo_ids`` accept JSON strings or comma-separated strings).
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from agents import RunContextWrapper

from strix.tools._decorator import strix_tool


VALID_PRIORITIES = ["low", "normal", "high", "critical"]
VALID_STATUSES = ["pending", "in_progress", "done"]


# Per-agent silo: ``_todos_storage[agent_id][todo_id] = todo_dict``.
# Keyed by ``ctx.context['agent_id']`` so two agents in the same scan
# don't see each other's lists.
_todos_storage: dict[str, dict[str, dict[str, Any]]] = {}


def _dump(result: dict[str, Any]) -> str:
    return json.dumps(result, ensure_ascii=False, default=str)


def _agent_id_from(ctx: RunContextWrapper) -> str:
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    return str(inner.get("agent_id") or "default")


def _get_agent_todos(agent_id: str) -> dict[str, dict[str, Any]]:
    return _todos_storage.setdefault(agent_id, {})


def _normalize_priority(priority: str | None, default: str = "normal") -> str:
    candidate = (priority or default or "normal").lower()
    if candidate not in VALID_PRIORITIES:
        raise ValueError(f"Invalid priority. Must be one of: {', '.join(VALID_PRIORITIES)}")
    return candidate


def _sorted_todos(agent_id: str) -> list[dict[str, Any]]:
    agent_todos = _get_agent_todos(agent_id)
    todos_list: list[dict[str, Any]] = []
    for todo_id, todo in agent_todos.items():
        entry = todo.copy()
        entry["todo_id"] = todo_id
        todos_list.append(entry)

    priority_order = {"critical": 0, "high": 1, "normal": 2, "low": 3}
    status_order = {"done": 0, "in_progress": 1, "pending": 2}
    todos_list.sort(
        key=lambda x: (
            status_order.get(x.get("status", "pending"), 99),
            priority_order.get(x.get("priority", "normal"), 99),
            x.get("created_at", ""),
        ),
    )
    return todos_list


def _normalize_todo_ids(raw_ids: Any) -> list[str]:
    if raw_ids is None:
        return []
    if isinstance(raw_ids, str):
        stripped = raw_ids.strip()
        if not stripped:
            return []
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            data = stripped.split(",") if "," in stripped else [stripped]
        if isinstance(data, list):
            return [str(item).strip() for item in data if str(item).strip()]
        return [str(data).strip()]
    if isinstance(raw_ids, list):
        return [str(item).strip() for item in raw_ids if str(item).strip()]
    return [str(raw_ids).strip()]


def _normalize_bulk_updates(raw_updates: Any) -> list[dict[str, Any]]:
    if raw_updates is None:
        return []
    data: Any = raw_updates
    if isinstance(raw_updates, str):
        stripped = raw_updates.strip()
        if not stripped:
            return []
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as e:
            raise ValueError("Updates must be valid JSON") from e

    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise TypeError("Updates must be a list of update objects")

    normalized: list[dict[str, Any]] = []
    for item in data:
        if not isinstance(item, dict):
            raise TypeError("Each update must be an object with todo_id")
        todo_id = item.get("todo_id") or item.get("id")
        if not todo_id:
            raise ValueError("Each update must include 'todo_id'")
        normalized.append(
            {
                "todo_id": str(todo_id).strip(),
                "title": item.get("title"),
                "description": item.get("description"),
                "priority": item.get("priority"),
                "status": item.get("status"),
            },
        )
    return normalized


def _normalize_bulk_todos(raw_todos: Any) -> list[dict[str, Any]]:
    if raw_todos is None:
        return []
    data: Any = raw_todos
    if isinstance(raw_todos, str):
        stripped = raw_todos.strip()
        if not stripped:
            return []
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            entries = [line.strip(" -*\t") for line in stripped.splitlines() if line.strip(" -*\t")]
            return [{"title": entry} for entry in entries]

    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise TypeError("Todos must be provided as a list, dict, or JSON string")

    normalized: list[dict[str, Any]] = []
    for item in data:
        if isinstance(item, str):
            title = item.strip()
            if title:
                normalized.append({"title": title})
            continue
        if not isinstance(item, dict):
            raise TypeError("Each todo entry must be a string or object with a title")
        title = item.get("title", "")
        if not isinstance(title, str) or not title.strip():
            raise ValueError("Each todo entry must include a non-empty 'title'")
        normalized.append(
            {
                "title": title.strip(),
                "description": (item.get("description") or "").strip() or None,
                "priority": item.get("priority"),
            },
        )
    return normalized


def _apply_single_update(
    agent_todos: dict[str, dict[str, Any]],
    todo_id: str,
    title: str | None = None,
    description: str | None = None,
    priority: str | None = None,
    status: str | None = None,
) -> dict[str, Any] | None:
    if todo_id not in agent_todos:
        return {"todo_id": todo_id, "error": f"Todo with ID '{todo_id}' not found"}
    todo = agent_todos[todo_id]
    if title is not None:
        if not title.strip():
            return {"todo_id": todo_id, "error": "Title cannot be empty"}
        todo["title"] = title.strip()
    if description is not None:
        todo["description"] = description.strip() if description else None
    if priority is not None:
        try:
            todo["priority"] = _normalize_priority(priority, str(todo.get("priority", "normal")))
        except ValueError as exc:
            return {"todo_id": todo_id, "error": str(exc)}
    if status is not None:
        status_candidate = status.lower()
        if status_candidate not in VALID_STATUSES:
            return {
                "todo_id": todo_id,
                "error": f"Invalid status. Must be one of: {', '.join(VALID_STATUSES)}",
            }
        todo["status"] = status_candidate
        todo["completed_at"] = datetime.now(UTC).isoformat() if status_candidate == "done" else None
    todo["updated_at"] = datetime.now(UTC).isoformat()
    return None


# --- public tools ---------------------------------------------------------


@strix_tool(timeout=30)
async def create_todo(
    ctx: RunContextWrapper,
    title: str | None = None,
    description: str | None = None,
    priority: str = "normal",
    todos: str | None = None,
) -> str:
    """Create one or many todos for the current agent."""
    agent_id = _agent_id_from(ctx)
    try:
        default_priority = _normalize_priority(priority)
        tasks: list[dict[str, Any]] = []
        if todos is not None:
            tasks.extend(_normalize_bulk_todos(todos))
        if title and title.strip():
            tasks.append(
                {
                    "title": title.strip(),
                    "description": description.strip() if description else None,
                    "priority": default_priority,
                },
            )
        if not tasks:
            return _dump(
                {
                    "success": False,
                    "error": "Provide a title or 'todos' list to create.",
                    "todo_id": None,
                },
            )

        agent_todos = _get_agent_todos(agent_id)
        created: list[dict[str, Any]] = []
        for task in tasks:
            task_priority = _normalize_priority(task.get("priority"), default_priority)
            todo_id = str(uuid.uuid4())[:6]
            timestamp = datetime.now(UTC).isoformat()
            agent_todos[todo_id] = {
                "title": task["title"],
                "description": task.get("description"),
                "priority": task_priority,
                "status": "pending",
                "created_at": timestamp,
                "updated_at": timestamp,
                "completed_at": None,
            }
            created.append({"todo_id": todo_id, "title": task["title"], "priority": task_priority})
    except (ValueError, TypeError) as e:
        return _dump({"success": False, "error": f"Failed to create todo: {e}", "todo_id": None})

    return _dump(
        {
            "success": True,
            "created": created,
            "count": len(created),
            "todos": _sorted_todos(agent_id),
            "total_count": len(_get_agent_todos(agent_id)),
        },
    )


@strix_tool(timeout=30)
async def list_todos(
    ctx: RunContextWrapper,
    status: str | None = None,
    priority: str | None = None,
) -> str:
    """List the current agent's todos, sorted by status then priority."""
    agent_id = _agent_id_from(ctx)
    try:
        agent_todos = _get_agent_todos(agent_id)
        status_filter = status.lower() if isinstance(status, str) else None
        priority_filter = priority.lower() if isinstance(priority, str) else None

        todos_list: list[dict[str, Any]] = []
        for todo_id, todo in agent_todos.items():
            if status_filter and todo.get("status") != status_filter:
                continue
            if priority_filter and todo.get("priority") != priority_filter:
                continue
            entry = todo.copy()
            entry["todo_id"] = todo_id
            todos_list.append(entry)

        priority_order = {"critical": 0, "high": 1, "normal": 2, "low": 3}
        status_order = {"done": 0, "in_progress": 1, "pending": 2}
        todos_list.sort(
            key=lambda x: (
                status_order.get(x.get("status", "pending"), 99),
                priority_order.get(x.get("priority", "normal"), 99),
                x.get("created_at", ""),
            ),
        )

        summary: dict[str, int] = {"pending": 0, "in_progress": 0, "done": 0}
        for todo in todos_list:
            sv = todo.get("status", "pending")
            summary[sv] = summary.get(sv, 0) + 1
    except (ValueError, TypeError) as e:
        return _dump(
            {
                "success": False,
                "error": f"Failed to list todos: {e}",
                "todos": [],
                "total_count": 0,
                "summary": {"pending": 0, "in_progress": 0, "done": 0},
            },
        )

    return _dump(
        {
            "success": True,
            "todos": todos_list,
            "total_count": len(todos_list),
            "summary": summary,
        },
    )


@strix_tool(timeout=30)
async def update_todo(
    ctx: RunContextWrapper,
    todo_id: str | None = None,
    title: str | None = None,
    description: str | None = None,
    priority: str | None = None,
    status: str | None = None,
    updates: str | None = None,
) -> str:
    """Update one or many todos."""
    agent_id = _agent_id_from(ctx)
    try:
        agent_todos = _get_agent_todos(agent_id)
        updates_to_apply: list[dict[str, Any]] = []
        if updates is not None:
            updates_to_apply.extend(_normalize_bulk_updates(updates))
        if todo_id is not None:
            updates_to_apply.append(
                {
                    "todo_id": todo_id,
                    "title": title,
                    "description": description,
                    "priority": priority,
                    "status": status,
                },
            )
        if not updates_to_apply:
            return _dump(
                {"success": False, "error": "Provide todo_id or 'updates' list to update."},
            )

        updated: list[str] = []
        errors: list[dict[str, Any]] = []
        for upd in updates_to_apply:
            err = _apply_single_update(
                agent_todos,
                upd["todo_id"],
                upd.get("title"),
                upd.get("description"),
                upd.get("priority"),
                upd.get("status"),
            )
            if err:
                errors.append(err)
            else:
                updated.append(upd["todo_id"])
    except (ValueError, TypeError) as e:
        return _dump({"success": False, "error": str(e)})

    response: dict[str, Any] = {
        "success": len(errors) == 0,
        "updated": updated,
        "updated_count": len(updated),
        "todos": _sorted_todos(agent_id),
        "total_count": len(agent_todos),
    }
    if errors:
        response["errors"] = errors
    return _dump(response)


def _mark(
    *,
    agent_id: str,
    todo_id: str | None,
    todo_ids: str | None,
    new_status: str,
) -> str:
    try:
        agent_todos = _get_agent_todos(agent_id)
        ids: list[str] = []
        if todo_ids is not None:
            ids.extend(_normalize_todo_ids(todo_ids))
        if todo_id is not None:
            ids.append(todo_id)
        if not ids:
            msg = f"Provide todo_id or todo_ids to mark as {new_status}."
            return _dump({"success": False, "error": msg})

        marked: list[str] = []
        errors: list[dict[str, Any]] = []
        timestamp = datetime.now(UTC).isoformat()
        for tid in ids:
            if tid not in agent_todos:
                errors.append({"todo_id": tid, "error": f"Todo with ID '{tid}' not found"})
                continue
            todo = agent_todos[tid]
            todo["status"] = new_status
            todo["completed_at"] = timestamp if new_status == "done" else None
            todo["updated_at"] = timestamp
            marked.append(tid)
    except (ValueError, TypeError) as e:
        return _dump({"success": False, "error": str(e)})

    key = "marked_done" if new_status == "done" else "marked_pending"
    response: dict[str, Any] = {
        "success": len(errors) == 0,
        key: marked,
        "marked_count": len(marked),
        "todos": _sorted_todos(agent_id),
        "total_count": len(agent_todos),
    }
    if errors:
        response["errors"] = errors
    return _dump(response)


@strix_tool(timeout=30)
async def mark_todo_done(
    ctx: RunContextWrapper,
    todo_id: str | None = None,
    todo_ids: str | None = None,
) -> str:
    """Mark one (``todo_id``) or many (``todo_ids``) todos as done."""
    return _mark(
        agent_id=_agent_id_from(ctx),
        todo_id=todo_id,
        todo_ids=todo_ids,
        new_status="done",
    )


@strix_tool(timeout=30)
async def mark_todo_pending(
    ctx: RunContextWrapper,
    todo_id: str | None = None,
    todo_ids: str | None = None,
) -> str:
    """Mark one (``todo_id``) or many (``todo_ids``) todos as pending."""
    return _mark(
        agent_id=_agent_id_from(ctx),
        todo_id=todo_id,
        todo_ids=todo_ids,
        new_status="pending",
    )


@strix_tool(timeout=30)
async def delete_todo(
    ctx: RunContextWrapper,
    todo_id: str | None = None,
    todo_ids: str | None = None,
) -> str:
    """Delete one (``todo_id``) or many (``todo_ids``) todos."""
    agent_id = _agent_id_from(ctx)
    try:
        agent_todos = _get_agent_todos(agent_id)
        ids: list[str] = []
        if todo_ids is not None:
            ids.extend(_normalize_todo_ids(todo_ids))
        if todo_id is not None:
            ids.append(todo_id)
        if not ids:
            return _dump({"success": False, "error": "Provide todo_id or todo_ids to delete."})

        deleted: list[str] = []
        errors: list[dict[str, Any]] = []
        for tid in ids:
            if tid not in agent_todos:
                errors.append({"todo_id": tid, "error": f"Todo with ID '{tid}' not found"})
                continue
            del agent_todos[tid]
            deleted.append(tid)
    except (ValueError, TypeError) as e:
        return _dump({"success": False, "error": str(e)})

    response: dict[str, Any] = {
        "success": len(errors) == 0,
        "deleted": deleted,
        "deleted_count": len(deleted),
        "todos": _sorted_todos(agent_id),
        "total_count": len(agent_todos),
    }
    if errors:
        response["errors"] = errors
    return _dump(response)
