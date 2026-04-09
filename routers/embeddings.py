"""
Embeddings endpoint router.

Handles /v1/embeddings endpoint.
"""

import asyncio
import json
import random
import time
from typing import Optional

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel

from services import get_responder, get_logger

router = APIRouter()


class EmbeddingRequest(BaseModel):
    """Embedding request body."""
    model: str = "text-embedding-3-small"
    input: str | list[str]
    encoding_format: Optional[str] = "float"
    dimensions: Optional[int] = None
    user: Optional[str] = None


async def add_response_delay():
    """Add random delay to avoid timing fingerprinting."""
    delay = random.uniform(0.08, 0.3)
    await asyncio.sleep(delay)


def get_api_headers() -> dict:
    """Get headers that mimic real OpenAI API."""
    return {
        "openai-model": "text-embedding-3-small",
        "openai-organization": "org-honeypot",
        "openai-processing-ms": str(random.randint(50, 200)),
        "openai-version": "2020-10-01",
        "x-ratelimit-limit-requests": "10000",
        "x-ratelimit-limit-tokens": "10000000",
        "x-ratelimit-remaining-requests": str(random.randint(9000, 9999)),
        "x-ratelimit-remaining-tokens": str(random.randint(9900000, 9999999)),
        "x-request-id": f"req_{random.randbytes(16).hex()}",
    }


@router.post("/v1/embeddings")
async def create_embedding(request: Request):
    """
    Create embeddings for input text.

    Always returns 200 with fake embeddings.
    """
    start_time = time.time()

    # Parse body
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {"raw_invalid": body_raw}

    await add_response_delay()

    # Generate response
    responder = get_responder()
    response_data = responder.embedding(
        model=body_parsed.get("model", "text-embedding-3-small"),
        input_text=body_parsed.get("input", ""),
    )

    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000

    # Log the request
    logger = get_logger()
    await logger.log_request(
        request=request,
        body_raw=body_raw,
        body_parsed=body_parsed,
        response_body=response_body,
        response_status=200,
        response_time_ms=response_time_ms,
    )

    return Response(
        content=response_body,
        media_type="application/json",
        headers=get_api_headers(),
    )
