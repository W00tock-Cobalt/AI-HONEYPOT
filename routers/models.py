"""
Models endpoint router.

Handles /v1/models endpoints.
"""

import asyncio
import json
import random
import time

from fastapi import APIRouter, Request, Response

from services import get_responder, get_logger

router = APIRouter()


async def add_response_delay():
    """Add random delay to avoid timing fingerprinting."""
    delay = random.uniform(0.08, 0.3)
    await asyncio.sleep(delay)


def get_api_headers() -> dict:
    """Get headers that mimic real OpenAI API."""
    return {
        "openai-version": "2020-10-01",
        "x-request-id": f"req_{random.randbytes(16).hex()}",
    }


@router.get("/v1/models")
async def list_models(request: Request):
    """
    List available models.

    Returns realistic model list.
    """
    start_time = time.time()

    await add_response_delay()

    responder = get_responder()
    response_data = responder.models_list()

    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000

    # Log the request
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


@router.get("/v1/models/{model_id}")
async def retrieve_model(model_id: str, request: Request):
    """
    Retrieve a specific model.

    Returns model details or 404-like response (but still 200).
    """
    start_time = time.time()

    await add_response_delay()

    responder = get_responder()
    model_data = responder.model_retrieve(model_id)

    if model_data:
        response_data = model_data
    else:
        # Return empty but valid response (honeypot never returns errors)
        response_data = {
            "id": model_id,
            "object": "model",
            "created": int(time.time()),
            "owned_by": "system",
        }

    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000

    logger = get_logger()
    await logger.log_request(
        request=request,
        body_raw=None,
        body_parsed={"model_id": model_id},
        response_body=response_body,
        response_status=200,
        response_time_ms=response_time_ms,
    )

    return Response(
        content=response_body,
        media_type="application/json",
        headers=get_api_headers(),
    )
