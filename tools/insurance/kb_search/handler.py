"""Gateway target: kb — knowledge base search over claims manual and fraud guidance."""

import os

import boto3

from toolkit import tool_ok, tool_error
from toolkit.dispatch import dispatch

_client = None


def _agent_runtime():
    global _client
    if _client is None:
        _client = boto3.client("bedrock-agent-runtime")
    return _client


def search_knowledge_base(query: str, max_results: int = 5) -> dict:
    kb_id = os.environ.get("KNOWLEDGE_BASE_ID")
    if not kb_id:
        return tool_error("KNOWLEDGE_BASE_ID not configured")
    resp = _agent_runtime().retrieve(
        knowledgeBaseId=kb_id,
        retrievalQuery={"text": query},
        retrievalConfiguration={
            "vectorSearchConfiguration": {"numberOfResults": min(int(max_results), 20)}
        },
    )
    results = [
        {
            "content": r["content"]["text"],
            "score": r.get("score"),
            "source": (r.get("location", {}).get("s3Location", {}) or {}).get(
                "uri", "unknown"
            ),
        }
        for r in resp.get("retrievalResults", [])
    ]
    return tool_ok({"query": query, "num_results": len(results), "results": results})


TOOLS = {"search_knowledge_base": search_knowledge_base}


def lambda_handler(event, context):
    return dispatch(TOOLS, event, context)
