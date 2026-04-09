"""
Billing and usage endpoints router.

Handles high-value lure endpoints:
- /v1/usage
- /v1/dashboard/billing/usage
- /v1/organization/api-keys
- /v1/images/generations
"""

import asyncio
import json
import random
import time
import uuid
from typing import Optional

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel

from services import get_responder, get_logger

router = APIRouter()


class ImageGenerationRequest(BaseModel):
    """Image generation request body."""
    model: str = "dall-e-3"
    prompt: str
    n: Optional[int] = 1
    quality: Optional[str] = "standard"
    response_format: Optional[str] = "url"
    size: Optional[str] = "1024x1024"
    style: Optional[str] = "vivid"
    user: Optional[str] = None


async def add_response_delay():
    """Add random delay to avoid timing fingerprinting."""
    delay = random.uniform(0.08, 0.3)
    await asyncio.sleep(delay)


def get_api_headers() -> dict:
    """Get headers that mimic real OpenAI API."""
    return {
        "openai-organization": "org-honeypot",
        "openai-version": "2020-10-01",
        "x-request-id": f"req_{random.randbytes(16).hex()}",
    }


@router.get("/v1/usage")
async def get_usage(request: Request):
    """
    Get usage statistics.

    Returns fake but realistic usage data.
    """
    start_time = time.time()

    await add_response_delay()

    responder = get_responder()
    response_data = responder.usage()

    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000

    logger = get_logger()
    await logger.log_request(
        request=request,
        body_raw=None,
        body_parsed=None,
        response_body=response_body,
        response_status=200,
        response_time_ms=response_time_ms,
    )

    return Response(
        content=response_body,
        media_type="application/json",
        headers=get_api_headers(),
    )


@router.get("/v1/dashboard/billing/usage")
async def get_billing_usage(request: Request):
    """
    Get billing usage data.

    Returns fake billing information.
    """
    start_time = time.time()

    await add_response_delay()

    responder = get_responder()
    response_data = responder.billing_usage()

    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000

    logger = get_logger()
    await logger.log_request(
        request=request,
        body_raw=None,
        body_parsed=None,
        response_body=response_body,
        response_status=200,
        response_time_ms=response_time_ms,
    )

    return Response(
        content=response_body,
        media_type="application/json",
        headers=get_api_headers(),
    )


@router.get("/v1/organization/api-keys")
async def list_api_keys(request: Request):
    """
    List organization API keys.

    HIGH VALUE LURE: Returns fake API keys that look real.
    Any usage of these keys indicates credential theft.
    """
    start_time = time.time()

    await add_response_delay()

    responder = get_responder()
    response_data = responder.api_keys()

    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000

    logger = get_logger()
    await logger.log_request(
        request=request,
        body_raw=None,
        body_parsed=None,
        response_body=response_body,
        response_status=200,
        response_time_ms=response_time_ms,
    )

    return Response(
        content=response_body,
        media_type="application/json",
        headers=get_api_headers(),
    )


@router.get("/v1/assistants")
async def list_assistants(request: Request):
    """
    List assistants.

    HIGH VALUE LURE: Attackers enumerate assistants to find system prompts.
    """
    start_time = time.time()
    await add_response_delay()
    responder = get_responder()
    response_data = responder.assistants_list()
    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000
    logger = get_logger()
    await logger.log_request(
        request=request, body_raw=None, body_parsed=None,
        response_body=response_body, response_status=200, response_time_ms=response_time_ms,
    )
    return Response(content=response_body, media_type="application/json", headers=get_api_headers())


@router.post("/v1/assistants")
async def create_assistant(request: Request):
    """Create assistant — logs the system prompt payload."""
    start_time = time.time()
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {"raw_invalid": body_raw}
    await add_response_delay()
    response_data = {
        "id": f"asst_{uuid.uuid4().hex[:24]}",
        "object": "assistant",
        "created_at": int(time.time()),
        "name": body_parsed.get("name", "Assistant"),
        "description": body_parsed.get("description"),
        "model": body_parsed.get("model", "gpt-4o"),
        "instructions": body_parsed.get("instructions", ""),
        "tools": body_parsed.get("tools", []),
        "metadata": body_parsed.get("metadata", {}),
    }
    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000
    logger = get_logger()
    await logger.log_request(
        request=request, body_raw=body_raw, body_parsed=body_parsed,
        response_body=response_body, response_status=200, response_time_ms=response_time_ms,
    )
    return Response(content=response_body, media_type="application/json", headers=get_api_headers())


@router.get("/v1/files")
async def list_files(request: Request):
    """
    List uploaded files.

    HIGH VALUE LURE: Attackers look for training data and sensitive documents.
    """
    start_time = time.time()
    await add_response_delay()
    responder = get_responder()
    response_data = responder.files_list()
    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000
    logger = get_logger()
    await logger.log_request(
        request=request, body_raw=None, body_parsed=None,
        response_body=response_body, response_status=200, response_time_ms=response_time_ms,
    )
    return Response(content=response_body, media_type="application/json", headers=get_api_headers())


@router.get("/v1/fine-tuning/jobs")
async def list_fine_tuning_jobs(request: Request):
    """
    List fine-tuning jobs.

    RECON LURE: Reveals model names and training file IDs to enumerate.
    """
    start_time = time.time()
    await add_response_delay()
    responder = get_responder()
    response_data = responder.fine_tuning_jobs()
    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000
    logger = get_logger()
    await logger.log_request(
        request=request, body_raw=None, body_parsed=None,
        response_body=response_body, response_status=200, response_time_ms=response_time_ms,
    )
    return Response(content=response_body, media_type="application/json", headers=get_api_headers())


@router.get("/v1/threads")
async def list_threads(request: Request):
    """List assistant threads."""
    start_time = time.time()
    await add_response_delay()
    responder = get_responder()
    response_data = responder.threads_list()
    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000
    logger = get_logger()
    await logger.log_request(
        request=request, body_raw=None, body_parsed=None,
        response_body=response_body, response_status=200, response_time_ms=response_time_ms,
    )
    return Response(content=response_body, media_type="application/json", headers=get_api_headers())


@router.post("/v1/threads")
async def create_thread(request: Request):
    """Create a thread — logs initial messages payload."""
    start_time = time.time()
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {"raw_invalid": body_raw}
    await add_response_delay()
    response_data = {
        "id": f"thread_{uuid.uuid4().hex[:24]}",
        "object": "thread",
        "created_at": int(time.time()),
        "metadata": body_parsed.get("metadata", {}),
    }
    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000
    logger = get_logger()
    await logger.log_request(
        request=request, body_raw=body_raw, body_parsed=body_parsed,
        response_body=response_body, response_status=200, response_time_ms=response_time_ms,
    )
    return Response(content=response_body, media_type="application/json", headers=get_api_headers())


@router.post("/v1/moderations")
async def create_moderation(request: Request):
    """
    Moderation endpoint.

    LURE: Attackers test moderation to find bypass vectors.
    Always returns clean (not flagged) to keep them engaged.
    """
    start_time = time.time()
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {"raw_invalid": body_raw}
    await add_response_delay()
    responder = get_responder()
    response_data = responder.moderation_result(input_text=body_parsed.get("input", ""))
    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000
    logger = get_logger()
    await logger.log_request(
        request=request, body_raw=body_raw, body_parsed=body_parsed,
        response_body=response_body, response_status=200, response_time_ms=response_time_ms,
    )
    return Response(content=response_body, media_type="application/json", headers=get_api_headers())


@router.get("/v1/organization/users")
async def list_org_users(request: Request):
    """
    List organization users.

    HIGH VALUE LURE: Attackers enumerate users to understand org structure.
    """
    start_time = time.time()
    await add_response_delay()
    responder = get_responder()
    response_data = responder.org_users()
    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000
    logger = get_logger()
    await logger.log_request(
        request=request, body_raw=None, body_parsed=None,
        response_body=response_body, response_status=200, response_time_ms=response_time_ms,
    )
    return Response(content=response_body, media_type="application/json", headers=get_api_headers())


@router.get("/v1/organization/projects")
async def list_org_projects(request: Request):
    """List organization projects — recon lure."""
    start_time = time.time()
    await add_response_delay()
    responder = get_responder()
    response_data = responder.org_projects()
    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000
    logger = get_logger()
    await logger.log_request(
        request=request, body_raw=None, body_parsed=None,
        response_body=response_body, response_status=200, response_time_ms=response_time_ms,
    )
    return Response(content=response_body, media_type="application/json", headers=get_api_headers())


@router.post("/v1/images/generations")
async def create_image(request: Request):
    """
    Generate images from prompt.

    Returns fake image URLs.
    """
    start_time = time.time()

    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {"raw_invalid": body_raw}

    # Longer delay for image generation (more realistic)
    await asyncio.sleep(random.uniform(0.5, 2.0))

    responder = get_responder()
    response_data = responder.image_generation(
        prompt=body_parsed.get("prompt", ""),
        model=body_parsed.get("model", "dall-e-3"),
        n=body_parsed.get("n", 1),
        size=body_parsed.get("size", "1024x1024"),
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
