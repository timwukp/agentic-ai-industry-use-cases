"""Chat history API — durable per-user transcripts in S3 with a metadata index.

Layout (bucket CHAT_HISTORY_BUCKET):
  chat/<userSub>/<sessionId>.json      full transcript (messages + metadata)
  index/<userSub>.json                 per-user index: one entry per session
                                       {sessionId, industryId, title, summary,
                                        startedAt, updatedAt, messageCount}

Identity comes from the API Gateway JWT authorizer claims (sub), NEVER from
the request body — a client cannot read or write another user's history by
construction. The Cognito sub is the partition key of everything.

Summaries: generated with Haiku on save when the session has grown by 4+
messages since the last summary (cheap, and the index stays useful without
a nightly job). Summary failure degrades to a truncated first-user-message
title — never blocks the save.

Routes (all behind the Cognito authorizer):
  POST /api/chat/save        body: {sessionId, industryId, messages:[{role,content}]}
  GET  /api/chat/sessions    -> the caller's index entries, newest first
  GET  /api/chat/session?id= -> one full transcript (ownership enforced)
"""

import json
import os
from datetime import datetime, timezone

import boto3

_s3 = boto3.client("s3")
_bedrock = None

SUMMARY_MODEL = os.environ.get(
    "SUMMARY_MODEL", "us.anthropic.claude-haiku-4-5-20251001-v1:0"
)
MAX_MESSAGES = 500  # per session — a runaway client cannot balloon storage
MAX_CONTENT = 20_000  # chars per message
SUMMARY_EVERY = 4  # regenerate summary after this many new messages


def _bedrock_client():
    global _bedrock
    if _bedrock is None:
        _bedrock = boto3.client("bedrock-runtime")
    return _bedrock


def _bucket() -> str:
    return os.environ["CHAT_HISTORY_BUCKET"]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _response(status: int, body: dict) -> dict:
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def _caller_sub(event) -> str | None:
    """Cognito sub from the JWT authorizer — the only trusted identity."""
    try:
        return event["requestContext"]["authorizer"]["jwt"]["claims"]["sub"]
    except (KeyError, TypeError):
        return None


def _get_json(key: str):
    try:
        obj = _s3.get_object(Bucket=_bucket(), Key=key)
        return json.loads(obj["Body"].read())
    except _s3.exceptions.NoSuchKey:
        return None


def _put_json(key: str, payload) -> None:
    _s3.put_object(
        Bucket=_bucket(),
        Key=key,
        Body=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        ContentType="application/json",
    )


def _summarize(messages: list[dict]) -> str | None:
    """One-line session summary via Haiku; None on any failure."""
    lines = []
    for m in messages[:40]:
        role = "U" if m.get("role") == "user" else "A"
        lines.append(f"{role}: {str(m.get('content', ''))[:300]}")
    prompt = (
        "Summarize this finance-assistant chat session in ONE line (max 15 "
        "words), naming the main topic and any key entities. Reply with the "
        "summary only, in the language the user wrote in.\n\n" + "\n".join(lines)
    )
    try:
        resp = _bedrock_client().converse(
            modelId=SUMMARY_MODEL,
            messages=[{"role": "user", "content": [{"text": prompt}]}],
            inferenceConfig={"maxTokens": 100, "temperature": 0.0},
        )
        return resp["output"]["message"]["content"][0]["text"].strip()[:200]
    except Exception:  # noqa: BLE001 — summary must never block a save
        return None


def _fallback_title(messages: list[dict]) -> str:
    for m in messages:
        if m.get("role") == "user" and m.get("content"):
            return str(m["content"])[:80]
    return "(empty session)"


def save_session(sub: str, body: dict) -> dict:
    session_id = str(body.get("sessionId", "")).strip()
    industry_id = str(body.get("industryId", "")).strip()[:40]
    messages = body.get("messages")
    if not session_id or not isinstance(messages, list) or not messages:
        return _response(400, {"error": "sessionId and messages[] required"})
    if not session_id.replace("-", "").replace("_", "").isalnum():
        return _response(400, {"error": "invalid sessionId"})
    clean = [
        {
            "role": "user" if m.get("role") == "user" else "assistant",
            "content": str(m.get("content", ""))[:MAX_CONTENT],
        }
        for m in messages[:MAX_MESSAGES]
        if isinstance(m, dict) and m.get("content")
    ]
    if not clean:
        return _response(400, {"error": "no valid messages"})

    key = f"chat/{sub}/{session_id}.json"
    existing = _get_json(key) or {}
    started_at = existing.get("startedAt") or _now()

    prev_count = existing.get("summaryAtCount", 0)
    summary = existing.get("summary")
    if summary is None or len(clean) - prev_count >= SUMMARY_EVERY:
        fresh = _summarize(clean)
        if fresh:
            summary = fresh
            prev_count = len(clean)

    transcript = {
        "sessionId": session_id,
        "industryId": industry_id,
        "userSub": sub,
        "startedAt": started_at,
        "updatedAt": _now(),
        "messageCount": len(clean),
        "summary": summary,
        "summaryAtCount": prev_count,
        "messages": clean,
    }
    _put_json(key, transcript)

    index_key = f"index/{sub}.json"
    index = _get_json(index_key) or {"sessions": []}
    entry = {
        "sessionId": session_id,
        "industryId": industry_id,
        "title": _fallback_title(clean),
        "summary": summary,
        "startedAt": started_at,
        "updatedAt": transcript["updatedAt"],
        "messageCount": len(clean),
    }
    sessions = [s for s in index["sessions"] if s.get("sessionId") != session_id]
    sessions.append(entry)
    sessions.sort(key=lambda s: s.get("updatedAt", ""), reverse=True)
    _put_json(index_key, {"sessions": sessions[:500]})

    return _response(200, {"saved": True, "summary": summary})


def list_sessions(sub: str) -> dict:
    index = _get_json(f"index/{sub}.json") or {"sessions": []}
    return _response(200, index)


def get_session(sub: str, session_id: str) -> dict:
    if not session_id:
        return _response(400, {"error": "id required"})
    # key embeds the CALLER's sub — someone else's session id 404s here
    transcript = _get_json(f"chat/{sub}/{session_id}.json")
    if transcript is None:
        return _response(404, {"error": "session not found"})
    return _response(200, transcript)


def lambda_handler(event, context):
    sub = _caller_sub(event)
    if not sub:
        return _response(401, {"error": "no identity"})
    route = event.get("routeKey", "")
    params = event.get("queryStringParameters") or {}

    if route == "POST /api/chat/save":
        try:
            body = json.loads(event.get("body") or "{}")
        except json.JSONDecodeError:
            return _response(400, {"error": "invalid JSON body"})
        return save_session(sub, body)
    if route == "GET /api/chat/sessions":
        return list_sessions(sub)
    if route == "GET /api/chat/session":
        return get_session(sub, str(params.get("id", "")).strip())
    return _response(404, {"error": f"Unknown route: {route}"})
