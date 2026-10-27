import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import text
import os

from .database import init_db, SessionLocal, cleanup_expired_scan_data
from .config import validate_startup_config
from .rate_limit import check_rate_limit
from .routers import auth as auth_router
from .routers import repositories, scans, github_oauth
from .routers import mfa as mfa_router
from .routers import support as support_router
from .routers import team as team_router


log = logging.getLogger("aisafety")

from .observability import init_observability  # noqa: E402

init_observability()   # no-op unless SENTRY_DSN is set; must run before the FastAPI app is created
RETENTION_SWEEP_SECONDS = int(os.environ.get("RETENTION_SWEEP_SECONDS", str(6 * 3600)))


async def _retention_loop():
    """Enforce SCAN_RETENTION_DAYS on a schedule, not only when someone scans."""
    while True:
        await asyncio.sleep(RETENTION_SWEEP_SECONDS)
        try:
            from .email_tokens import purge_old
            await asyncio.to_thread(purge_old)
            removed = await asyncio.to_thread(cleanup_expired_scan_data)
            if removed:
                log.info("retention sweep removed %s expired scans", removed)
        except Exception:  # pragma: no cover - keep the loop alive
            log.exception("retention sweep failed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    validate_startup_config()
    init_db()
    from . import jobs
    with SessionLocal() as db:
        recovered = jobs.recover_orphans(db)
    if recovered:
        log.warning("closed %s scan(s) interrupted by the previous shutdown", recovered)
    jobs.queue.start()
    task = asyncio.create_task(_retention_loop())
    try:
        yield
    finally:
        task.cancel()
        jobs.queue.shutdown()


_prod = os.environ.get("ENVIRONMENT", "development").lower() == "production"
# Interactive API docs and the schema are an unnecessary reconnaissance aid in production.
app = FastAPI(
    title="AI Safety Checkup",
    version="0.1.0",
    lifespan=lifespan,
    docs_url=None if _prod else "/docs",
    redoc_url=None if _prod else "/redoc",
    openapi_url=None if _prod else "/openapi.json",
)

allowed_origins = [o.strip() for o in os.environ.get("CORS_ALLOWED_ORIGINS", "").split(",") if o.strip()]
if not allowed_origins:
    # Development convenience only. Production startup validation rejects a
    # missing/wildcard CORS policy.
    allowed_origins = ["*"]

class _TooLarge(Exception):
    pass


class BodyLimitMiddleware:
    """Reject request bodies over MAX_REQUEST_BYTES (default 1 MiB) before the app parses them.

    Checks Content-Length up front and also counts streamed (chunked) bodies, so a client cannot
    exhaust memory with an oversized JSON payload.
    """

    def __init__(self, app, max_bytes: int):
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        length = dict(scope["headers"]).get(b"content-length")
        started = False

        async def reject():
            body = b'{"detail":"Request body too large"}'
            await send({"type": "http.response.start", "status": 413,
                        "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
            await send({"type": "http.response.body", "body": body})

        if length and length.isdigit() and int(length) > self.max_bytes:
            return await reject()
        total = 0

        async def limited_receive():
            nonlocal total
            message = await receive()
            if message["type"] == "http.request":
                total += len(message.get("body", b""))
                if total > self.max_bytes:
                    raise _TooLarge()
            return message

        async def tracking_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _TooLarge:
            if not started:
                await reject()


app.add_middleware(BodyLimitMiddleware, max_bytes=int(os.environ.get("MAX_REQUEST_BYTES", str(1024 * 1024))))


@app.middleware("http")
async def request_rate_limit(request: Request, call_next):
    limited = check_rate_limit(request)
    if limited is not None:
        return limited
    return await call_next(request)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Cross-Origin-Resource-Policy", "same-site")
    if _prod:
        # This process only serves JSON/PDF; it never needs to run active content.
        response.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
    if request.headers.get("authorization"):
        response.headers["Cache-Control"] = "no-store"
    if os.environ.get("ENVIRONMENT", "development").lower() == "production":
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


@app.middleware("http")
async def catch_unhandled_errors(request: Request, call_next):
    """Turn an unexpected exception into a JSON 500 *inside* the CORS layer, so the browser can read it."""
    try:
        return await call_next(request)
    except Exception:
        log.exception("Unhandled error on %s %s", request.method, request.url.path)
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": "Internal server error"}, status_code=500)


# CORS must be the OUTERMOST layer (added last): otherwise errors produced by the layers above it
# (rate limit 429, body-size 413, unexpected 500) reach the browser without CORS headers, the
# browser hides them, and the page can only say "could not reach the API".
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.api_route("/health", methods=["GET", "HEAD"])
def health():
    """Liveness: the process is up."""
    return {"status": "ok"}


@app.get("/ready")
def ready():
    """Readiness: the database answers. Point load-balancer checks here."""
    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
    except Exception:
        return JSONResponse({"status": "unavailable"}, status_code=503)
    return {"status": "ready"}


app.include_router(auth_router.router)
app.include_router(mfa_router.router)
app.include_router(support_router.router)
app.include_router(team_router.router)
app.include_router(repositories.router)
app.include_router(scans.router)
app.include_router(github_oauth.router)
