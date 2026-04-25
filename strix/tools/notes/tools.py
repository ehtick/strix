"""Per-run notes (shared across agents).

Persisted to ``run_dir/notes/notes.jsonl`` (replayable event log) and,
for the ``wiki`` category, also rendered as Markdown to
``run_dir/wiki/<slug>.md``. Concurrent appends are serialised by a
threading.RLock so two agents writing simultaneously can't corrupt
the JSONL.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from pathlib import Path

from agents import RunContextWrapper

from strix.tools._decorator import strix_tool


logger = logging.getLogger(__name__)


_notes_storage: dict[str, dict[str, Any]] = {}
_VALID_NOTE_CATEGORIES = ["general", "findings", "methodology", "questions", "plan", "wiki"]
_notes_lock = threading.RLock()
_loaded_notes_run_dir: str | None = None
_DEFAULT_CONTENT_PREVIEW_CHARS = 280


def _dump(result: dict[str, Any]) -> str:
    return json.dumps(result, ensure_ascii=False, default=str)


def _get_run_dir() -> Path | None:
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if not tracer:
            return None
        return tracer.get_run_dir()
    except (ImportError, OSError, RuntimeError):
        return None


def _get_notes_jsonl_path() -> Path | None:
    run_dir = _get_run_dir()
    if not run_dir:
        return None
    notes_dir = run_dir / "notes"
    notes_dir.mkdir(parents=True, exist_ok=True)
    return notes_dir / "notes.jsonl"


def _append_note_event(op: str, note_id: str, note: dict[str, Any] | None = None) -> None:
    """Append one note operation to the run's ``notes/notes.jsonl``.

    C6: hold ``_notes_lock`` across the file open + write so two
    concurrent agents can't interleave bytes mid-line.
    """
    notes_path = _get_notes_jsonl_path()
    if not notes_path:
        return
    event: dict[str, Any] = {
        "timestamp": datetime.now(UTC).isoformat(),
        "op": op,
        "note_id": note_id,
    }
    if note is not None:
        event["note"] = note
    with _notes_lock, notes_path.open("a", encoding="utf-8") as f:
        f.write(f"{json.dumps(event, ensure_ascii=True)}\n")


def _load_notes_from_jsonl(notes_path: Path) -> dict[str, dict[str, Any]]:
    hydrated: dict[str, dict[str, Any]] = {}
    if not notes_path.exists():
        return hydrated
    with notes_path.open(encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            op = str(event.get("op", "")).strip().lower()
            note_id = str(event.get("note_id", "")).strip()
            if not note_id or op not in {"create", "update", "delete"}:
                continue
            if op == "delete":
                hydrated.pop(note_id, None)
                continue
            note = event.get("note")
            if not isinstance(note, dict):
                continue
            existing = hydrated.get(note_id, {})
            existing.update(note)
            hydrated[note_id] = existing
    return hydrated


def _ensure_notes_loaded() -> None:
    global _loaded_notes_run_dir  # noqa: PLW0603
    run_dir = _get_run_dir()
    run_dir_key = str(run_dir.resolve()) if run_dir else "__no_run_dir__"
    if _loaded_notes_run_dir == run_dir_key:
        return
    _notes_storage.clear()
    notes_path = _get_notes_jsonl_path()
    if notes_path:
        _notes_storage.update(_load_notes_from_jsonl(notes_path))
        try:
            for note_id, note in _notes_storage.items():
                if note.get("category") == "wiki":
                    _persist_wiki_note(note_id, note)
        except OSError:
            pass
    _loaded_notes_run_dir = run_dir_key


def _sanitize_wiki_title(title: str) -> str:
    cleaned = "".join(ch.lower() if ch.isalnum() else "-" for ch in title.strip())
    slug = "-".join(part for part in cleaned.split("-") if part)
    return slug or "wiki-note"


def _get_wiki_directory() -> Path | None:
    try:
        run_dir = _get_run_dir()
        if not run_dir:
            return None
        wiki_dir = run_dir / "wiki"
        wiki_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return None
    else:
        return wiki_dir


def _get_wiki_note_path(note_id: str, note: dict[str, Any]) -> Path | None:
    wiki_dir = _get_wiki_directory()
    if not wiki_dir:
        return None
    wiki_filename = note.get("wiki_filename")
    if not isinstance(wiki_filename, str) or not wiki_filename.strip():
        title = note.get("title", "wiki-note")
        wiki_filename = f"{note_id}-{_sanitize_wiki_title(str(title))}.md"
        note["wiki_filename"] = wiki_filename
    return wiki_dir / wiki_filename


def _persist_wiki_note(note_id: str, note: dict[str, Any]) -> None:
    wiki_path = _get_wiki_note_path(note_id, note)
    if not wiki_path:
        return
    tags = note.get("tags", [])
    tags_line = ", ".join(str(tag) for tag in tags) if isinstance(tags, list) and tags else "none"
    content = (
        f"# {note.get('title', 'Wiki Note')}\n\n"
        f"**Note ID:** {note_id}\n"
        f"**Created:** {note.get('created_at', '')}\n"
        f"**Updated:** {note.get('updated_at', '')}\n"
        f"**Tags:** {tags_line}\n\n"
        "## Content\n\n"
        f"{note.get('content', '')}\n"
    )
    wiki_path.write_text(content, encoding="utf-8")


def _remove_wiki_note(note_id: str, note: dict[str, Any]) -> None:
    wiki_path = _get_wiki_note_path(note_id, note)
    if not wiki_path:
        return
    if wiki_path.exists():
        wiki_path.unlink()


def _filter_notes(
    category: str | None = None,
    tags: list[str] | None = None,
    search_query: str | None = None,
) -> list[dict[str, Any]]:
    _ensure_notes_loaded()
    filtered: list[dict[str, Any]] = []
    for note_id, note in _notes_storage.items():
        if category and note.get("category") != category:
            continue
        if tags:
            note_tags = note.get("tags", [])
            if not any(tag in note_tags for tag in tags):
                continue
        if search_query:
            search_lower = search_query.lower()
            title_match = search_lower in note.get("title", "").lower()
            content_match = search_lower in note.get("content", "").lower()
            if not (title_match or content_match):
                continue
        entry = note.copy()
        entry["note_id"] = note_id
        filtered.append(entry)
    filtered.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return filtered


def _to_note_listing_entry(
    note: dict[str, Any],
    *,
    include_content: bool = False,
) -> dict[str, Any]:
    entry = {
        "note_id": note.get("note_id"),
        "title": note.get("title", ""),
        "category": note.get("category", "general"),
        "tags": note.get("tags", []),
        "created_at": note.get("created_at", ""),
        "updated_at": note.get("updated_at", ""),
    }
    wiki_filename = note.get("wiki_filename")
    if isinstance(wiki_filename, str) and wiki_filename:
        entry["wiki_filename"] = wiki_filename
    content = str(note.get("content", ""))
    if include_content:
        entry["content"] = content
    elif content:
        if len(content) > _DEFAULT_CONTENT_PREVIEW_CHARS:
            entry["content_preview"] = f"{content[:_DEFAULT_CONTENT_PREVIEW_CHARS].rstrip()}..."
        else:
            entry["content_preview"] = content
    return entry


def _create_note_impl(  # noqa: PLR0911
    title: str,
    content: str,
    category: str = "general",
    tags: list[str] | None = None,
) -> dict[str, Any]:
    """Create one note. Public — used by ``append_note_content`` and tests."""
    with _notes_lock:
        try:
            _ensure_notes_loaded()
            if not title or not title.strip():
                return {"success": False, "error": "Title cannot be empty", "note_id": None}
            if not content or not content.strip():
                return {"success": False, "error": "Content cannot be empty", "note_id": None}
            if category not in _VALID_NOTE_CATEGORIES:
                return {
                    "success": False,
                    "error": (
                        f"Invalid category. Must be one of: {', '.join(_VALID_NOTE_CATEGORIES)}"
                    ),
                    "note_id": None,
                }

            note_id = ""
            for _ in range(20):
                candidate = str(uuid.uuid4())[:5]
                if candidate not in _notes_storage:
                    note_id = candidate
                    break
            if not note_id:
                return {"success": False, "error": "Failed to allocate note ID", "note_id": None}

            timestamp = datetime.now(UTC).isoformat()
            note = {
                "title": title.strip(),
                "content": content.strip(),
                "category": category,
                "tags": tags or [],
                "created_at": timestamp,
                "updated_at": timestamp,
            }
            _notes_storage[note_id] = note
            _append_note_event("create", note_id, note)
            if category == "wiki":
                _persist_wiki_note(note_id, note)
        except (ValueError, TypeError) as e:
            return {"success": False, "error": f"Failed to create note: {e}", "note_id": None}
        except OSError as e:
            return {"success": False, "error": f"Failed to persist wiki note: {e}", "note_id": None}
        else:
            return {
                "success": True,
                "note_id": note_id,
                "message": f"Note '{title}' created successfully",
            }


def _list_notes_impl(
    category: str | None = None,
    tags: list[str] | None = None,
    search: str | None = None,
    include_content: bool = False,
) -> dict[str, Any]:
    with _notes_lock:
        try:
            filtered = _filter_notes(category=category, tags=tags, search_query=search)
            notes = [_to_note_listing_entry(n, include_content=include_content) for n in filtered]
        except (ValueError, TypeError) as e:
            return {
                "success": False,
                "error": f"Failed to list notes: {e}",
                "notes": [],
                "total_count": 0,
            }
    return {"success": True, "notes": notes, "total_count": len(notes)}


def _get_note_impl(note_id: str) -> dict[str, Any]:
    with _notes_lock:
        try:
            _ensure_notes_loaded()
            if not note_id or not note_id.strip():
                return {"success": False, "error": "Note ID cannot be empty", "note": None}
            note = _notes_storage.get(note_id)
            if note is None:
                return {
                    "success": False,
                    "error": f"Note with ID '{note_id}' not found",
                    "note": None,
                }
            note_with_id = note.copy()
            note_with_id["note_id"] = note_id
        except (ValueError, TypeError) as e:
            return {"success": False, "error": f"Failed to get note: {e}", "note": None}
        else:
            return {"success": True, "note": note_with_id}


def _update_note_impl(
    note_id: str,
    title: str | None = None,
    content: str | None = None,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    with _notes_lock:
        try:
            _ensure_notes_loaded()
            if note_id not in _notes_storage:
                return {"success": False, "error": f"Note with ID '{note_id}' not found"}
            note = _notes_storage[note_id]
            if title is not None:
                if not title.strip():
                    return {"success": False, "error": "Title cannot be empty"}
                note["title"] = title.strip()
            if content is not None:
                if not content.strip():
                    return {"success": False, "error": "Content cannot be empty"}
                note["content"] = content.strip()
            if tags is not None:
                note["tags"] = tags
            note["updated_at"] = datetime.now(UTC).isoformat()
            _append_note_event("update", note_id, note)
            if note.get("category") == "wiki":
                _persist_wiki_note(note_id, note)
        except (ValueError, TypeError) as e:
            return {"success": False, "error": f"Failed to update note: {e}"}
        except OSError as e:
            return {"success": False, "error": f"Failed to persist wiki note: {e}"}
        else:
            return {
                "success": True,
                "message": f"Note '{note['title']}' updated successfully",
            }


def _delete_note_impl(note_id: str) -> dict[str, Any]:
    with _notes_lock:
        try:
            _ensure_notes_loaded()
            if note_id not in _notes_storage:
                return {"success": False, "error": f"Note with ID '{note_id}' not found"}
            note = _notes_storage[note_id]
            note_title = note["title"]
            if note.get("category") == "wiki":
                _remove_wiki_note(note_id, note)
            del _notes_storage[note_id]
            _append_note_event("delete", note_id)
        except (ValueError, TypeError) as e:
            return {"success": False, "error": f"Failed to delete note: {e}"}
        except OSError as e:
            return {"success": False, "error": f"Failed to delete wiki note: {e}"}
        else:
            return {
                "success": True,
                "message": f"Note '{note_title}' deleted successfully",
            }


def append_note_content(note_id: str, delta: str) -> dict[str, Any]:
    """Append text to an existing note's content. Used by the agents-graph
    wiki-update hook on agent_finish."""
    with _notes_lock:
        try:
            _ensure_notes_loaded()
            if note_id not in _notes_storage:
                return {"success": False, "error": f"Note with ID '{note_id}' not found"}
            note = _notes_storage[note_id]
            existing = str(note.get("content") or "")
            updated = f"{existing.rstrip()}{delta}"
            return _update_note_impl(note_id=note_id, content=updated)
        except (ValueError, TypeError) as e:
            return {"success": False, "error": f"Failed to append note content: {e}"}


# --- public tools ---------------------------------------------------------


@strix_tool(timeout=30)
async def create_note(
    ctx: RunContextWrapper,
    title: str,
    content: str,
    category: str = "general",
    tags: list[str] | None = None,
) -> str:
    """Document an observation, finding, methodology step, or research note.

    Notes are your **shared run memory** — they're visible to every
    agent in the same scan and persist to ``run_dir/notes/notes.jsonl``
    (replayable event log). Wiki-category notes are additionally
    rendered as Markdown under ``run_dir/wiki/<slug>.md``.

    For actionable tasks, use ``todo`` instead — notes are for capturing
    information, todos are for tracking work.

    Categories:

    - ``general`` — default, anything that doesn't fit elsewhere.
    - ``findings`` — confirmed vulnerabilities or weaknesses (write
      these up promptly; you'll cite them when filing reports).
    - ``methodology`` — what you tried, what worked, what didn't —
      useful for the final scan report.
    - ``questions`` — open questions / things to come back to.
    - ``plan`` — multi-step plans you want to track.
    - ``wiki`` — repository or target source maps shared across agents
      in the same run. Use this for codebase architecture notes the
      whole agent tree should see.

    Tags are free-form (e.g. ``["sqli", "auth", "critical"]``) — useful
    for later ``list_notes(tags=...)`` filtering.

    Args:
        title: Short headline.
        content: Full note body. Markdown is preserved.
        category: One of the categories above. Default ``"general"``.
        tags: Optional free-form tags.
    """
    del ctx
    return _dump(
        await asyncio.to_thread(_create_note_impl, title, content, category, tags),
    )


@strix_tool(timeout=30)
async def list_notes(
    ctx: RunContextWrapper,
    category: str | None = None,
    tags: list[str] | None = None,
    search: str | None = None,
    include_content: bool = False,
) -> str:
    """List existing notes — metadata-first by default.

    Filters compose: passing ``category="findings"`` and
    ``tags=["sqli"]`` returns notes that are *both* in the findings
    category AND have at least one of those tags.

    By default each entry includes a ``content_preview`` (first 280
    chars). Set ``include_content=True`` to get full bodies — useful
    when you need to scan many notes; expensive in tokens for large
    notes.

    Args:
        category: Filter by category.
        tags: Filter to notes that have any of these tags.
        search: Substring match against title and content.
        include_content: When False (default) entries have a preview;
            when True the full ``content`` is included.
    """
    del ctx
    return _dump(
        await asyncio.to_thread(
            _list_notes_impl,
            category=category,
            tags=tags,
            search=search,
            include_content=include_content,
        ),
    )


@strix_tool(timeout=30)
async def get_note(ctx: RunContextWrapper, note_id: str) -> str:
    """Fetch one note by its 5-char ID. Returns the full content.

    Args:
        note_id: Note id from ``create_note`` or a ``list_notes`` entry.
    """
    del ctx
    return _dump(await asyncio.to_thread(_get_note_impl, note_id))


@strix_tool(timeout=30)
async def update_note(
    ctx: RunContextWrapper,
    note_id: str,
    title: str | None = None,
    content: str | None = None,
    tags: list[str] | None = None,
) -> str:
    """Update a note's title, content, or tags.

    Pass ``None`` for any field you want left unchanged. Replacing
    ``content`` is a full overwrite — to append, fetch first with
    ``get_note``, concat, and pass the result.

    Args:
        note_id: Target note's 5-char ID.
        title: New title, or ``None`` to keep.
        content: New content, or ``None`` to keep.
        tags: New tags list, or ``None`` to keep.
    """
    del ctx
    return _dump(
        await asyncio.to_thread(
            _update_note_impl,
            note_id=note_id,
            title=title,
            content=content,
            tags=tags,
        ),
    )


@strix_tool(timeout=30)
async def delete_note(ctx: RunContextWrapper, note_id: str) -> str:
    """Delete a note. For wiki notes, also removes the rendered Markdown file.

    Args:
        note_id: Note id to delete.
    """
    del ctx
    return _dump(await asyncio.to_thread(_delete_note_impl, note_id))
