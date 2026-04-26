---
name: python
description: python_action — execute Python in the sandbox with Caido proxy helpers (list_requests, view_request, send_request, repeat_request, scope_rules) pre-bound as awaitables. Stateless per call; persistence via files.
---


# python_action — when and how

Use ``python_action`` for any Python-side work: payload encoding/decoding,
parsing/transforming captured HTTP traffic, crypto operations, custom
exploit scripts, log/JSON analysis. Use ``exec_command`` for shell tools
(nmap, sqlmap, ffuf, agent-browser, package managers, daemons).

**Do not** wrap Python in bash heredocs, ``python3 -c`` one-liners, or
``echo | python3`` chains via ``exec_command`` — ``python_action`` exists
so structured output replaces fragile stdout parsing.

## What's pre-bound (no imports needed)

All proxy helpers are **async** — call them with ``await``:

- ``list_requests(httpql_filter=, first=50, after=, sort_by=, sort_order=,
  scope_id=)`` → cursor-paginated SDK ``Connection``. Iterate
  ``connection.edges``; each edge has ``.cursor`` and ``.node.request`` /
  ``.node.response``.
- ``view_request(request_id, part="request")`` → SDK request object.
  ``.request.raw`` and ``.response.raw`` are bytes.
- ``send_request(method, url, headers=None, body="")`` → dict with
  ``status``, ``error``, ``elapsed_ms``, ``response_raw`` (bytes or None),
  ``session_id``.
- ``repeat_request(request_id, modifications={...})`` → same shape.
  ``modifications`` keys: ``url`` / ``params`` / ``headers`` / ``body`` /
  ``cookies``.
- ``scope_rules(action, allowlist=, denylist=, scope_id=, scope_name=)``
  — same actions as the host-side tool (``list``/``get``/``create``/
  ``update``/``delete``).

Top-level ``await`` works — the body is wrapped in an async function for
you. ``print()`` to emit visible output; the last expression is **not**
auto-shown.

## Stateless model + how to keep state

Each ``python_action`` call is a **fresh process**: variables, imports,
and definitions do not survive. To carry state across steps:

- **Combine into one call** when the workflow is short — write the full
  multi-step routine as one ``code`` block.
- **Persist to disk** for longer-lived state. ``/workspace/scratch/`` is
  pentester-writable and survives across calls within a scan.
- **Build a script** with ``apply_patch`` to ``/workspace/scratch/<name>.py``
  and run it via ``exec_command python3 ...`` when you need a file the
  agent can iterate on.

## Examples

### Hunt SQLi candidates by inspecting captured traffic

```python
# All POSTs that look interesting
posts = await list_requests(
    httpql_filter='req.method.eq:"POST" AND req.path.cont:"/api/"',
    first=50,
)
candidates = []
for edge in posts.edges:
    body = await view_request(edge.node.request.id, part="request")
    raw = body.request.raw.decode("utf-8", errors="replace")
    if "id=" in raw or "user=" in raw:
        candidates.append(edge.node.request.id)

print(f"{len(candidates)} candidates")
print(candidates[:10])
```

### Replay with a SQLi probe and a tampered cookie

```python
result = await repeat_request(
    "req_abc123",
    modifications={
        "params": {"id": "1' OR '1'='1"},
        "cookies": {"session": "ATTACKER_TOKEN"},
    },
)
print(result["status"], result["elapsed_ms"], "ms")
if result["response_raw"]:
    print(result["response_raw"].decode("utf-8", errors="replace")[:500])
```

### Decode/encode payloads

```python
import base64, urllib.parse, hashlib

token = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWxpY2UifQ.sig"
header_b64, payload_b64, _ = token.split(".")
print(base64.urlsafe_b64decode(payload_b64 + "=="))
```

### Iterate an exploit by writing to scratch

When iterating, prefer writing the script to disk so you can edit-and-rerun
without re-sending the whole code each call:

```text
# 1. Use apply_patch to create /workspace/scratch/exploit.py
# 2. exec_command: python3 /workspace/scratch/exploit.py
# 3. Edit + re-run; repeat until working
```

For one-shot crypto/encoding work or a single proxy-data analysis,
``python_action`` is the cleaner choice.
