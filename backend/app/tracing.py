"""Tracing utilities and SQLite-backed tracer."""
from __future__ import annotations

import contextvars
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import wraps
from typing import Generator, Optional, Protocol

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from .db import SessionLocal
from .models import ApiSpan, ApiTrace


@dataclass(frozen=True)
class TraceContext:
    """Lightweight carrier for trace/span identifiers."""
    trace_id: str
    span_id: Optional[str] = None


class Tracer(Protocol):
    """Minimal tracer interface to allow swapping to OTEL later."""

    def start_trace(self, request: Request) -> TraceContext:
        """Start a trace for an incoming request."""
        raise NotImplementedError

    def finish_trace(self, trace: TraceContext, response: Response, duration_ms: float) -> None:
        """Finalize a trace with response metadata."""
        raise NotImplementedError

    def record_span(
        self,
        trace_id: str,
        name: str,
        duration_ms: float,
        parent_span_id: Optional[str],
    ) -> None:
        """Record a span under a trace."""
        raise NotImplementedError


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SqliteTracer:
    """Persist traces/spans in SQLite via SQLAlchemy."""

    def start_trace(self, request: Request) -> TraceContext:
        """Insert the trace row with request metadata."""
        trace_id = uuid.uuid4().hex
        with SessionLocal() as session:
            session.add(
                ApiTrace(
                    id=trace_id,
                    method=request.method,
                    path=str(request.url.path),
                    status_code=0,
                    duration_ms=0.0,
                    started_at=_utc_now(),
                )
            )
            session.commit()
        return TraceContext(trace_id=trace_id, span_id=None)

    def finish_trace(self, trace: TraceContext, response: Response, duration_ms: float) -> None:
        """Update the trace row with response metadata."""
        with SessionLocal() as session:
            record = session.get(ApiTrace, trace.trace_id)
            if record:
                record.status_code = response.status_code
                record.duration_ms = duration_ms
            session.commit()

    def record_span(
        self,
        trace_id: str,
        name: str,
        duration_ms: float,
        parent_span_id: Optional[str],
    ) -> None:
        """Insert a span row for a named operation."""
        span_id = uuid.uuid4().hex
        with SessionLocal() as session:
            session.add(
                ApiSpan(
                    id=span_id,
                    trace_id=trace_id,
                    parent_span_id=parent_span_id,
                    name=name,
                    duration_ms=duration_ms,
                    started_at=_utc_now(),
                )
            )
            session.commit()


_current_trace_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "trace_id", default=None
)
_current_span_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "span_id", default=None
)
_current_tracer: contextvars.ContextVar[Optional[Tracer]] = contextvars.ContextVar(
    "tracer", default=None
)


def get_tracer(request: Request) -> Optional[Tracer]:
    """FastAPI dependency to access the active tracer."""
    return getattr(request.app.state, "tracer", None)


@contextmanager
def trace_span(name: str) -> Generator[None, None, None]:
    """Record a named span under the current request trace."""
    tracer = _current_tracer.get()
    trace_id = _current_trace_id.get()
    if not tracer or not trace_id:
        yield
        return
    parent_span_id = _current_span_id.get()
    span_token = _current_span_id.set(uuid.uuid4().hex)
    start = time.perf_counter()
    try:
        yield
    finally:
        duration_ms = (time.perf_counter() - start) * 1000.0
        tracer.record_span(trace_id, name, duration_ms, parent_span_id)
        _current_span_id.reset(span_token)


def traced(name: str):
    """Decorator to wrap a function in a trace span."""

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            with trace_span(name):
                return func(*args, **kwargs)

        return wrapper

    return decorator


class TraceMiddleware(BaseHTTPMiddleware):
    """Record a trace for each request, plus a response header."""

    def __init__(self, app, tracer: Tracer) -> None:
        super().__init__(app)
        self._tracer = tracer

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        start = time.perf_counter()
        trace = self._tracer.start_trace(request)
        trace_token = _current_trace_id.set(trace.trace_id)
        span_token = _current_span_id.set(trace.span_id)
        tracer_token = _current_tracer.set(self._tracer)
        try:
            response = await call_next(request)
        finally:
            duration_ms = (time.perf_counter() - start) * 1000.0
            _current_tracer.reset(tracer_token)
            _current_span_id.reset(span_token)
            _current_trace_id.reset(trace_token)
        self._tracer.finish_trace(trace, response, duration_ms)
        response.headers.setdefault("X-Trace-Id", trace.trace_id)
        return response
