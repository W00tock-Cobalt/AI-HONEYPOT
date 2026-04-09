"""
OpenAI API Honeypot - Main Application

A production-grade honeypot that mimics the OpenAI API to capture and analyze
attacks on AI infrastructure.

For security research purposes only.
"""

import json
import os
import sys
import time
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from rich.console import Console
from rich.panel import Panel

# Load environment before other imports
load_dotenv()

from models.db import Database
from services import init_logger, get_geoip_service, get_logger
from routers import (
    chat_router,
    models_router,
    embeddings_router,
    billing_router,
    admin_router,
    set_database,
)

console = Console()

# Configuration
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./honeypot.db")
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))
GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", "./GeoLite2-City.mmdb")

# Database instance
db: Database = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    global db

    # Startup
    console.print(Panel.fit(
        "[bold red]🍯 OpenAI API Honeypot[/bold red]\n"
        "[dim]Security Research Tool[/dim]",
        border_style="red",
    ))

    # Initialize database
    console.print("[yellow]Initializing database...[/yellow]")
    db = Database(DATABASE_URL)
    await db.init_db()
    console.print("[green]Database ready[/green]")

    # Initialize services
    console.print("[yellow]Initializing services...[/yellow]")
    init_logger(db)
    geoip = get_geoip_service(GEOIP_DB_PATH)
    console.print("[green]Services ready[/green]")

    # Set database for admin routes
    set_database(db)

    from routers.admin import ADMIN_PATH
    console.print(f"\n[bold green]Listening on {HOST}:{PORT}[/bold green]")
    console.print(f"[dim]Admin UI : http://127.0.0.1:{PORT}{ADMIN_PATH}[/dim]")
    if ADMIN_PATH == "/admin":
        console.print("[yellow]⚠  Set ADMIN_PATH in .env to a secret path before deploying publicly[/yellow]")
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")

    yield

    # Shutdown
    console.print("\n[yellow]Shutting down...[/yellow]")
    await db.close()
    geoip.close()
    console.print("[green]Goodbye![/green]")


# Create FastAPI app
app = FastAPI(
    title="OpenAI API",  # Fake title to look real
    description="OpenAI API",
    version="1.0.0",
    docs_url=None,  # Disable docs - real API doesn't expose them at root
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Setup templates with custom filter
templates = Jinja2Templates(directory="templates")


def country_flag(country_code: str) -> str:
    """Convert country code to flag emoji."""
    if not country_code or len(country_code) != 2:
        return "🌐"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in country_code.upper())


templates.env.filters["country_flag"] = country_flag

# Include routers
app.include_router(chat_router)
app.include_router(models_router)
app.include_router(embeddings_router)
app.include_router(billing_router)
# Admin router self-manages its prefix via ADMIN_PATH env var (set in .env)
app.include_router(admin_router)


@app.middleware("http")
async def add_custom_headers(request: Request, call_next):
    """Add headers to mimic real OpenAI API gateway."""
    response = await call_next(request)

    # Remove FastAPI default headers
    if "x-fastapi-version" in response.headers:
        del response.headers["x-fastapi-version"]

    # Add realistic headers
    response.headers["server"] = "cloudflare"
    response.headers["cf-ray"] = f"{os.urandom(8).hex()}-IAD"
    response.headers["cf-cache-status"] = "DYNAMIC"
    response.headers["alt-svc"] = 'h3=":443"; ma=86400'
    response.headers["x-content-type-options"] = "nosniff"
    response.headers["strict-transport-security"] = "max-age=31536000; includeSubDomains"

    return response


@app.get("/")
async def root(request: Request):
    """Root endpoint - fake OpenAI dashboard (honeypot lure)."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/dashboard")
async def dashboard(request: Request):
    """Dashboard alias."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api")
async def api_root():
    """API status endpoint - mimics OpenAI API root."""
    return {
        "status": "ok",
        "message": "OpenAI API is operational",
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.get("/playground")
async def playground(request: Request):
    """Playground - chat interface."""
    return templates.TemplateResponse("chat.html", {"request": request})


@app.get("/chat")
async def chat(request: Request):
    """Chat interface alias."""
    return templates.TemplateResponse("chat.html", {"request": request})


# Catch-all for unknown paths (log but return generic response)
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def catch_all(request: Request, path: str):
    """Catch all other requests and log them."""
    start_time = time.time()

    # Parse body if present
    body_raw = None
    body_parsed = None
    try:
        body_raw = (await request.body()).decode("utf-8", errors="replace")
        if body_raw:
            body_parsed = json.loads(body_raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass

    # Match real OpenAI 404 format exactly
    response_data = {
        "error": {
            "message": "Not Found",
            "type": "invalid_request_error",
            "param": None,
            "code": None,
        }
    }

    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000

    # Log the request
    logger = get_logger()
    await logger.log_request(
        request=request,
        body_raw=body_raw,
        body_parsed=body_parsed,
        response_body=response_body,
        response_status=404,
        response_time_ms=response_time_ms,
    )

    return Response(
        content=response_body,
        media_type="application/json",
        status_code=404,
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=HOST,
        port=PORT,
        log_level="info",
        access_log=False,  # We do our own logging
    )
