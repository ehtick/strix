"""Pure caido-sdk-client call sequences shared by ``tools.py`` and ``python_action``.

Functions here:

- Take an explicit ``Client`` argument — no module-level state, no
  context lookups. The caller decides what client to use.
- Return raw caido-sdk-client objects (or dicts of primitives where the
  composition itself is the value-add, like :func:`replay_send_raw`).
- Live without ``@function_tool`` decorators, ``RunContextWrapper``, or
  any host-side framework dependency. They run identically inside the
  Strix host process (called from ``tools.py``) and inside the sandbox
  container (called from the ``python_action`` driver), against the
  same Caido instance — host gets there via the host-mapped port,
  container gets there via ``localhost:48080``.

Single source of truth for the Caido SDK call shapes; ``tools.py`` adds
LLM-specific JSON serialization and error wrapping on top.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from caido_sdk_client.types import (
    ConnectionInfoInput,
    CreateReplaySessionFromRaw,
    CreateReplaySessionOptions,
    CreateScopeOptions,
    ReplaySendOptions,
    RequestGetOptions,
    UpdateScopeOptions,
)


if TYPE_CHECKING:
    from caido_sdk_client import Client


RequestPart = Literal["request", "response"]
SortBy = Literal[
    "timestamp",
    "host",
    "method",
    "path",
    "status_code",
    "response_time",
    "response_size",
    "source",
]
SortOrder = Literal["asc", "desc"]


_REQ_FIELD_MAP: dict[SortBy, tuple[str, str]] = {
    "timestamp": ("req", "created_at"),
    "host": ("req", "host"),
    "method": ("req", "method"),
    "path": ("req", "path"),
    "source": ("req", "source"),
    "status_code": ("resp", "code"),
    "response_time": ("resp", "roundtrip"),
    "response_size": ("resp", "length"),
}


# ----------------------------------------------------------------------
# Requests — list / get
# ----------------------------------------------------------------------
async def list_requests(
    client: Client,
    *,
    httpql_filter: str | None = None,
    first: int = 50,
    after: str | None = None,
    sort_by: SortBy = "timestamp",
    sort_order: SortOrder = "desc",
    scope_id: str | None = None,
) -> Any:
    builder = client.request.list().first(first)
    if httpql_filter:
        builder = builder.filter(httpql_filter)
    if after:
        builder = builder.after(after)
    if scope_id:
        builder = builder.scope(scope_id)
    target, field = _REQ_FIELD_MAP[sort_by]
    builder = (builder.descending if sort_order == "desc" else builder.ascending)(target, field)
    return await builder.execute()


async def get_request(
    client: Client,
    request_id: str,
    *,
    part: RequestPart = "request",
) -> Any:
    opts = RequestGetOptions(
        request_raw=(part == "request"),
        response_raw=(part == "response"),
    )
    return await client.request.get(request_id, opts)


# ----------------------------------------------------------------------
# Raw HTTP request build / parse / mutate
# ----------------------------------------------------------------------
def build_raw_request(
    *,
    method: str,
    url: str,
    headers: dict[str, str],
    body: str,
) -> tuple[ConnectionInfoInput, bytes]:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid URL: {url}")
    is_tls = parsed.scheme.lower() == "https"
    host = parsed.hostname or ""
    port = parsed.port or (443 if is_tls else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    final_headers = {**headers}
    final_headers.setdefault("Host", parsed.netloc)
    final_headers.setdefault("User-Agent", "strix")
    if body and "Content-Length" not in {k.title() for k in final_headers}:
        final_headers["Content-Length"] = str(len(body.encode("utf-8")))

    lines = [f"{method.upper()} {path} HTTP/1.1"]
    lines.extend(f"{k}: {v}" for k, v in final_headers.items())
    raw = ("\r\n".join(lines) + "\r\n\r\n" + body).encode("utf-8")

    return ConnectionInfoInput(host=host, port=port, is_tls=is_tls), raw


def parse_raw_request(raw_content: str) -> dict[str, Any]:
    lines = raw_content.split("\n")
    request_line = lines[0].strip().split(" ")
    if len(request_line) < 2:
        raise ValueError("Invalid request line format")
    method, url_path = request_line[0], request_line[1]

    parsed_headers: dict[str, str] = {}
    body_start = 0
    for i, line in enumerate(lines[1:], 1):
        if line.strip() == "":
            body_start = i + 1
            break
        if ":" in line:
            key, value = line.split(":", 1)
            parsed_headers[key.strip()] = value.strip()

    body = "\n".join(lines[body_start:]).strip() if body_start < len(lines) else ""
    return {"method": method, "url_path": url_path, "headers": parsed_headers, "body": body}


def full_url_from_components(
    original: Any,
    components: dict[str, Any],
    modifications: dict[str, Any],
) -> str:
    if "url" in modifications:
        return str(modifications["url"])
    headers = components["headers"]
    host_header = headers.get("Host") or original.host
    scheme = "https" if original.is_tls else "http"
    return f"{scheme}://{host_header}{components['url_path']}"


def apply_modifications(
    components: dict[str, Any],
    modifications: dict[str, Any],
    full_url: str,
) -> dict[str, Any]:
    headers = dict(components["headers"])
    body = components["body"]
    final_url = full_url

    if "params" in modifications:
        parsed = urlparse(final_url)
        existing = {k: v[0] if v else "" for k, v in parse_qs(parsed.query).items()}
        existing.update(modifications["params"])
        final_url = urlunparse(parsed._replace(query=urlencode(existing)))

    if "headers" in modifications:
        headers.update(modifications["headers"])

    if "body" in modifications:
        body = modifications["body"]

    if "cookies" in modifications:
        cookies: dict[str, str] = {}
        if headers.get("Cookie"):
            for cookie in headers["Cookie"].split(";"):
                if "=" in cookie:
                    k, v = cookie.split("=", 1)
                    cookies[k.strip()] = v.strip()
        cookies.update(modifications["cookies"])
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

    return {
        "method": components["method"],
        "url": final_url,
        "headers": headers,
        "body": body,
    }


# ----------------------------------------------------------------------
# Replay — send raw bytes, get a result
# ----------------------------------------------------------------------
async def replay_send_raw(
    client: Client,
    *,
    raw: bytes,
    connection: ConnectionInfoInput,
) -> dict[str, Any]:
    started = time.time()
    session = await client.replay.sessions.create(
        CreateReplaySessionOptions(
            request_source=CreateReplaySessionFromRaw(raw=raw, connection=connection),
        ),
    )
    result = await client.replay.send(
        session.id,
        ReplaySendOptions(raw=raw, connection=connection),
    )
    elapsed_ms = int((time.time() - started) * 1000)
    response_raw = result.entry.response_raw if hasattr(result.entry, "response_raw") else None
    return {
        "session_id": str(session.id),
        "status": result.status,
        "error": result.error,
        "elapsed_ms": elapsed_ms,
        "response_raw": response_raw,
    }


# ----------------------------------------------------------------------
# Scope CRUD
# ----------------------------------------------------------------------
async def scope_list(client: Client) -> Any:
    return await client.scope.list()


async def scope_get(client: Client, scope_id: str) -> Any:
    return await client.scope.get(scope_id)


async def scope_create(
    client: Client,
    *,
    name: str,
    allowlist: list[str] | None = None,
    denylist: list[str] | None = None,
) -> Any:
    return await client.scope.create(
        CreateScopeOptions(
            name=name,
            allowlist=list(allowlist or []),
            denylist=list(denylist or []),
        ),
    )


async def scope_update(
    client: Client,
    scope_id: str,
    *,
    name: str,
    allowlist: list[str] | None = None,
    denylist: list[str] | None = None,
) -> Any:
    return await client.scope.update(
        scope_id,
        UpdateScopeOptions(
            name=name,
            allowlist=list(allowlist or []),
            denylist=list(denylist or []),
        ),
    )


async def scope_delete(client: Client, scope_id: str) -> None:
    await client.scope.delete(scope_id)
