"""chat_history Lambda: identity isolation, save/index/get, summary fallback.

Bedrock is stubbed; S3 via moto. The security property under test: identity
comes ONLY from JWT claims, so caller A can never read or write caller B's
transcripts regardless of what the request says.
"""

import importlib
import json
import os
import sys
from pathlib import Path

import boto3
import pytest

REPO = Path(__file__).resolve().parents[2]

BUCKET = "chat-history-test"


@pytest.fixture()
def handler(monkeypatch):
    from moto import mock_aws

    with mock_aws():
        os.environ["CHAT_HISTORY_BUCKET"] = BUCKET
        boto3.client("s3", region_name="us-east-1").create_bucket(Bucket=BUCKET)
        sys.path.insert(0, str(REPO / "tools" / "shared" / "chat_history"))
        try:
            import handler as h

            h = importlib.reload(h)
            h._s3 = boto3.client("s3", region_name="us-east-1")
            # summaries stubbed: deterministic, no bedrock
            monkeypatch.setattr(h, "_summarize", lambda msgs: "stub summary")
            yield h
        finally:
            sys.path.pop(0)


def _event(route, sub, body=None, params=None):
    return {
        "routeKey": route,
        "body": json.dumps(body) if body is not None else None,
        "queryStringParameters": params,
        "requestContext": {"authorizer": {"jwt": {"claims": {"sub": sub}}}},
    }


def _msgs(n=2):
    out = []
    for i in range(n):
        out.append({"role": "user", "content": f"question {i} about oil"})
        out.append({"role": "assistant", "content": f"answer {i}"})
    return out


def test_save_list_get_roundtrip(handler):
    r = handler.lambda_handler(
        _event(
            "POST /api/chat/save",
            "user-a",
            {"sessionId": "sess-1-a", "industryId": "finance", "messages": _msgs()},
        ),
        None,
    )
    assert r["statusCode"] == 200
    assert json.loads(r["body"])["summary"] == "stub summary"

    r = handler.lambda_handler(_event("GET /api/chat/sessions", "user-a"), None)
    sessions = json.loads(r["body"])["sessions"]
    assert len(sessions) == 1
    assert sessions[0]["sessionId"] == "sess-1-a"
    assert sessions[0]["industryId"] == "finance"
    assert sessions[0]["messageCount"] == 4

    r = handler.lambda_handler(
        _event("GET /api/chat/session", "user-a", params={"id": "sess-1-a"}), None
    )
    transcript = json.loads(r["body"])
    assert transcript["messages"][0]["content"] == "question 0 about oil"


def test_identity_isolation_cross_user(handler):
    handler.lambda_handler(
        _event(
            "POST /api/chat/save",
            "user-a",
            {"sessionId": "sess-priv", "industryId": "finance", "messages": _msgs()},
        ),
        None,
    )
    # user B cannot list A's sessions...
    r = handler.lambda_handler(_event("GET /api/chat/sessions", "user-b"), None)
    assert json.loads(r["body"])["sessions"] == []
    # ...nor fetch A's transcript even knowing the session id
    r = handler.lambda_handler(
        _event("GET /api/chat/session", "user-b", params={"id": "sess-priv"}), None
    )
    assert r["statusCode"] == 404


def test_no_identity_rejected(handler):
    r = handler.lambda_handler({"routeKey": "GET /api/chat/sessions"}, None)
    assert r["statusCode"] == 401


def test_resave_updates_not_duplicates(handler):
    for n in (1, 3):
        handler.lambda_handler(
            _event(
                "POST /api/chat/save",
                "user-a",
                {
                    "sessionId": "sess-grow",
                    "industryId": "finance",
                    "messages": _msgs(n),
                },
            ),
            None,
        )
    r = handler.lambda_handler(_event("GET /api/chat/sessions", "user-a"), None)
    sessions = json.loads(r["body"])["sessions"]
    assert len(sessions) == 1
    assert sessions[0]["messageCount"] == 6


def test_summary_failure_degrades_to_title(handler, monkeypatch):
    monkeypatch.setattr(handler, "_summarize", lambda msgs: None)
    handler.lambda_handler(
        _event(
            "POST /api/chat/save",
            "user-a",
            {"sessionId": "sess-nosum", "industryId": "finance", "messages": _msgs()},
        ),
        None,
    )
    r = handler.lambda_handler(_event("GET /api/chat/sessions", "user-a"), None)
    entry = json.loads(r["body"])["sessions"][0]
    assert entry["summary"] is None
    assert entry["title"].startswith("question 0")


def test_invalid_session_id_rejected(handler):
    r = handler.lambda_handler(
        _event(
            "POST /api/chat/save",
            "user-a",
            {"sessionId": "../escape", "industryId": "x", "messages": _msgs()},
        ),
        None,
    )
    assert r["statusCode"] == 400


def test_message_caps_enforced(handler):
    huge = [{"role": "user", "content": "x" * 50_000}] * 600
    r = handler.lambda_handler(
        _event(
            "POST /api/chat/save",
            "user-a",
            {"sessionId": "sess-cap", "industryId": "finance", "messages": huge},
        ),
        None,
    )
    assert r["statusCode"] == 200
    r = handler.lambda_handler(
        _event("GET /api/chat/session", "user-a", params={"id": "sess-cap"}), None
    )
    t = json.loads(r["body"])
    assert t["messageCount"] <= handler.MAX_MESSAGES
    assert all(len(m["content"]) <= handler.MAX_CONTENT for m in t["messages"])
