"""Shared error handling: Denied is a 403 with a reason, a plugin failure a 502."""

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from ..plugin_api import Denied, PluginError

log = logging.getLogger("doorman.api")


def install(app: FastAPI, hide=None) -> None:
    """`hide`: applied to error texts before they go out (the agent API passes the pseudonymizer: a plugin
    error can quote the title of a hidden event)."""
    hide = hide or (lambda text: text)

    @app.exception_handler(Denied)
    async def denied(_: Request, exc: Denied):
        body = {"status": "denied", "code": exc.code, "reason": hide(exc.reason)}
        if exc.code in ("busy", "locked"):  # guard.GuardBusy, auth.PasswordLocked: ask again in retry_after seconds
            retry = int(getattr(exc, "retry_after", 30))
            return JSONResponse({**body, "retry_after": retry}, status_code=429, headers={"Retry-After": str(retry)})
        status = 401 if exc.code == "unauthenticated" else 403
        return JSONResponse(body, status_code=status)

    @app.exception_handler(PluginError)
    async def plugin_error(_: Request, exc: PluginError):
        return JSONResponse({"status": "error", "error": hide(str(exc))}, status_code=502)

    @app.exception_handler(KeyError)
    @app.exception_handler(TypeError)
    @app.exception_handler(ValueError)
    async def bad_input(request: Request, exc: Exception):
        log.exception("bad input on %s", request.url.path)
        reason = f"invalid request: {exc} is missing" if isinstance(exc, KeyError) else f"invalid request: {exc}"
        return JSONResponse({"status": "denied", "code": "invalid", "reason": reason}, status_code=400)
