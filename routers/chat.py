"""
Chat completions endpoint router.

Handles /v1/chat/completions and /v1/completions endpoints.
"""

import asyncio
import json
import random
import time
from typing import Optional

from fastapi import APIRouter, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from services import get_responder, get_logger

router = APIRouter()


class ChatMessage(BaseModel):
    """Chat message format."""
    role: str
    content: str
    name: Optional[str] = None


class ChatCompletionRequest(BaseModel):
    """Chat completion request body."""
    model: str = "gpt-4o"
    messages: list[ChatMessage]
    temperature: Optional[float] = 1.0
    top_p: Optional[float] = 1.0
    n: Optional[int] = 1
    stream: Optional[bool] = False
    stop: Optional[str | list[str]] = None
    max_tokens: Optional[int] = None
    presence_penalty: Optional[float] = 0.0
    frequency_penalty: Optional[float] = 0.0
    logit_bias: Optional[dict] = None
    user: Optional[str] = None


class CompletionRequest(BaseModel):
    """Legacy completion request body."""
    model: str = "gpt-3.5-turbo-instruct"
    prompt: str | list[str] = ""
    suffix: Optional[str] = None
    max_tokens: Optional[int] = 16
    temperature: Optional[float] = 1.0
    top_p: Optional[float] = 1.0
    n: Optional[int] = 1
    stream: Optional[bool] = False
    logprobs: Optional[int] = None
    echo: Optional[bool] = False
    stop: Optional[str | list[str]] = None
    presence_penalty: Optional[float] = 0.0
    frequency_penalty: Optional[float] = 0.0
    best_of: Optional[int] = 1
    user: Optional[str] = None


async def add_response_delay():
    """Add random delay to avoid timing fingerprinting."""
    delay = random.uniform(0.08, 0.3)  # 80-300ms
    await asyncio.sleep(delay)


@router.post("/v1/chat/completions")
async def chat_completions(request: Request):
    """
    Handle chat completion requests.

    Always returns 200 with plausible completion.
    """
    start_time = time.time()

    # Parse body
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {"raw_invalid": body_raw}

    # Add realistic delay
    await add_response_delay()

    # Generate response
    responder = get_responder()
    response_data = responder.chat_completion(
        model=body_parsed.get("model", "gpt-4o"),
        messages=body_parsed.get("messages", []),
        stream=body_parsed.get("stream", False),
        max_tokens=body_parsed.get("max_tokens"),
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

    # Check if streaming requested
    if body_parsed.get("stream"):
        return StreamingResponse(
            stream_response(response_data),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    return Response(
        content=response_body,
        media_type="application/json",
        headers=get_api_headers(),
    )


@router.post("/v1/completions")
async def completions(request: Request):
    """
    Handle legacy completion requests.

    Always returns 200 with plausible completion.
    """
    start_time = time.time()

    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {"raw_invalid": body_raw}

    await add_response_delay()

    responder = get_responder()
    response_data = responder.completion(
        model=body_parsed.get("model", "gpt-3.5-turbo-instruct"),
        prompt=body_parsed.get("prompt", ""),
        max_tokens=body_parsed.get("max_tokens"),
    )

    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000

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


async def stream_response(response_data: dict):
    """Generate SSE stream for streaming responses."""
    content = response_data["choices"][0]["message"]["content"]

    # Split content into chunks
    words = content.split()
    chunks = []
    current_chunk = []

    for word in words:
        current_chunk.append(word)
        if len(current_chunk) >= random.randint(2, 5):
            chunks.append(" ".join(current_chunk) + " ")
            current_chunk = []

    if current_chunk:
        chunks.append(" ".join(current_chunk))

    # Stream chunks
    for i, chunk in enumerate(chunks):
        chunk_data = {
            "id": response_data["id"],
            "object": "chat.completion.chunk",
            "created": response_data["created"],
            "model": response_data["model"],
            "choices": [
                {
                    "index": 0,
                    "delta": {"content": chunk},
                    "finish_reason": None,
                }
            ],
        }

        yield f"data: {json.dumps(chunk_data)}\n\n"
        await asyncio.sleep(random.uniform(0.01, 0.05))

    # Send final chunk
    final_chunk = {
        "id": response_data["id"],
        "object": "chat.completion.chunk",
        "created": response_data["created"],
        "model": response_data["model"],
        "choices": [
            {
                "index": 0,
                "delta": {},
                "finish_reason": "stop",
            }
        ],
    }

    yield f"data: {json.dumps(final_chunk)}\n\n"
    yield "data: [DONE]\n\n"


def get_api_headers() -> dict:
    """Get headers that mimic real OpenAI API."""
    return {
        "openai-model": "gpt-4o",
        "openai-organization": "org-honeypot",
        "openai-processing-ms": str(random.randint(100, 500)),
        "openai-version": "2020-10-01",
        "x-ratelimit-limit-requests": "10000",
        "x-ratelimit-limit-tokens": "2000000",
        "x-ratelimit-remaining-requests": str(random.randint(9000, 9999)),
        "x-ratelimit-remaining-tokens": str(random.randint(1900000, 1999999)),
        "x-ratelimit-reset-requests": "1ms",
        "x-ratelimit-reset-tokens": "1ms",
        "x-request-id": f"req_{random.randbytes(16).hex()}",
    }
