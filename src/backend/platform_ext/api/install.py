"""Attach the Role 7 platform extension to a FastAPI app.

Safely registers multi-tenant authentication, agent management, persistent alerts,
Ed25519-signed release management, and WebSocket alert streams WITHOUT mutating
or deleting existing Role 6 routes (/api/v1/alerts/simulate, /ws/alerts, /api/v1/predict).
"""
from __future__ import annotations
import logging
import time
import uuid
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from ..config import get_settings
from ..db.session import init_engine, get_engine
from . import agents, alerts, auth, releases, ws

log = logging.getLogger("neural_breach.api")


def _err(status: int, code: str, rid: str | None, detail=None) -> JSONResponse:
    """Format structured error responses containing both 'error' and 'detail'
    for full compatibility with Role 6 client expectations and Role 7 security standards.
    """
    body = {
        "error": {
            "code": code,
            "request_id": rid or ""
        },
        "detail": detail if detail is not None else code
    }
    if detail is not None:
        body["error"]["detail"] = detail
    return JSONResponse(body, status_code=status, headers={"X-Request-ID": rid or ""})


def install_platform(app: FastAPI) -> FastAPI:
    """Install platform extension routes, hardening middleware, and DB engines
    onto the provided FastAPI application instance in a non-destructive manner.
    """
    s = get_settings()
    init_engine(s.database_url)

    if getattr(app.state, "platform_installed", False):
        return app
    app.state.platform_installed = True

    # Reset Starlette middleware_stack if already compiled by earlier test client runs
    if getattr(app, "middleware_stack", None) is not None:
        app.middleware_stack = None

    # 1. CORS Configuration (Explicit origins only; non-wildcard)
    if s.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=s.cors_origins,
            allow_credentials=False,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
            allow_headers=["Authorization", "Content-Type", "Idempotency-Key", "X-Request-ID"]
        )

    # 2. Hardening Middleware (Request IDs, size limits, security headers)
    # Does NOT hijack or enforce user JWT authentication on legacy unauthenticated endpoints!
    @app.middleware("http")
    async def platform_hardening(request: Request, call_next):
        rid = request.headers.get("x-request-id") or uuid.uuid4().hex
        request.state.request_id = rid
        t0 = time.perf_counter()

        # Enforce body size limits if Content-Length header is present
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > s.max_request_bytes:
            return _err(413, "payload_too_large", rid)

        try:
            resp = await call_next(request)
        except Exception:
            log.exception("unhandled error rid=%s path=%s", rid, request.url.path)
            return _err(500, "internal_error", rid)

        # Standard defense-in-depth HTTP security headers
        resp.headers.update({
            "X-Request-ID": rid,
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-store",
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains"
        })
        log.info(
            '{"rid":"%s","method":"%s","path":"%s","status":%d,"ms":%.1f}',
            rid, request.method, request.url.path, resp.status_code, (time.perf_counter() - t0) * 1000
        )
        return resp

    # 3. Structured Exception Handlers
    @app.exception_handler(HTTPException)
    async def http_exc(request: Request, exc: HTTPException):
        rid = getattr(request.state, "request_id", None) or request.headers.get("x-request-id")
        d = exc.detail
        if isinstance(d, dict):
            code = d.get("code") or d.get("error") or str(exc.status_code)
            detail = d.get("detail", d.get("message", d))
        else:
            code = str(d)
            detail = d
        r = _err(exc.status_code, code, rid, detail)
        if exc.headers:
            r.headers.update(exc.headers)
        return r

    @app.exception_handler(RequestValidationError)
    async def val_exc(request: Request, exc: RequestValidationError):
        rid = getattr(request.state, "request_id", None) or request.headers.get("x-request-id")
        errors = [{"loc": e["loc"], "msg": e["msg"]} for e in exc.errors()]
        return _err(422, "validation_error", rid, errors)

    # 4. Mount extension routers without modifying or deleting existing routes
    for r in (auth.router, agents.router, alerts.router, alerts.router_v2, releases.router, ws.router):
        app.include_router(r)

    # 5. Database Readiness Probe
    @app.get("/api/v1/ready", include_in_schema=False)
    def ready():
        from sqlalchemy import text
        try:
            with get_engine().connect() as c:
                c.execute(text("select 1"))
            return {"status": "ready"}
        except Exception:
            return JSONResponse({"status": "db_unavailable"}, status_code=503)

    return app
