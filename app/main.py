from contextlib import asynccontextmanager
from typing import List, Optional

import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.db import init_db
from app.schemas import ReportSummaryResponse, TaskCreate, TaskResponse
from app.services import (
    create_task,
    evaluate_report_filter,
    get_report_summary,
    get_task_by_id,
    list_tasks,
    search_tasks,
)


def get_database_path() -> str:
    """Dependency provider for database path to support test isolation."""
    return settings.DATABASE_PATH


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan handler: initialize and seed database on startup."""
    init_db(settings.DATABASE_PATH)
    yield


app = FastAPI(
    title="SecureFix Vulnerable Demo Lab",
    description="Deliberately vulnerable API for SecureFix AI local testing only. NOT FOR PRODUCTION.",
    version=settings.APP_VERSION,
    lifespan=lifespan,
)

# SFV-004: Permissive CORS configuration with wildcard origins
# Permissive origins, methods, and headers are enabled. Credentials are deliberately not combined with wildcards.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# SFV-006: Missing defensive security headers
# Standard defensive response headers (such as X-Content-Type-Options: nosniff
# and Content-Security-Policy) are intentionally omitted from demo responses.
@app.middleware("http")
async def security_headers_middleware(request, call_next):
    """Middleware demonstrating omission of defensive security headers."""
    response = await call_next(request)
    # Note: Defensive headers (X-Content-Type-Options, CSP, HSTS) are deliberately not added here
    return response


class ControlledDemoException(Exception):
    """Controlled synthetic exception for demo error responses."""
    pass


# SFV-005: Verbose error response returning synthetic diagnostic text and exception class
@app.exception_handler(ControlledDemoException)
async def controlled_demo_exception_handler(request, exc: ControlledDemoException):
    """Return diagnostic detail and internal exception type without exposing real secrets."""
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal demo processing failure",
            "diagnostic": "Synthetic internal diagnostic: operation failed in task processor",
            "exception_type": exc.__class__.__name__,
        },
    )


@app.get("/health")
def health_check():
    """Health check endpoint.

    # SFV-008: Version disclosure - exposes demo application version metadata.
    """
    return {
        "status": "healthy",
        "app": "securefix-vuln-lab",
        "version": settings.APP_VERSION,  # SFV-008: Demo version metadata exposed
        "environment": settings.APP_ENV,
    }


@app.get("/debug/controlled-error")
def trigger_controlled_error():
    """Controlled test endpoint triggering verbose error response.

    # SFV-005: Verbose error response trigger.
    """
    raise ControlledDemoException("Simulated controlled failure for diagnostic test")


@app.get("/tasks", response_model=List[TaskResponse])
def get_tasks(
    owner_id: Optional[str] = None,
    db_path: str = Depends(get_database_path),
):
    """List tasks, optionally filtered by synthetic owner ID."""
    return list_tasks(owner_id=owner_id, db_path=db_path)


@app.get("/tasks/search", response_model=List[TaskResponse])
def search_tasks_route(
    q: str = Query(..., min_length=1, max_length=100, description="Search keyword"),
    db_path: str = Depends(get_database_path),
):
    """Search tasks by title keyword.

    # SFV-002: SQL query concatenation in search route.
    """
    return search_tasks(search_term=q, db_path=db_path)


@app.get("/tasks/{task_id}", response_model=TaskResponse)
def get_task(
    task_id: int,
    x_user_id: Optional[str] = Header(default=None, alias="X-User-Id"),
    db_path: str = Depends(get_database_path),
):
    """Fetch task by ID.

    # SFV-001: Broken object-level authorization (IDOR).
    # Task lookup does not verify that the synthetic caller (X-User-Id) owns the requested task.
    # Any caller can retrieve any task ID regardless of owner_id.
    """
    task = get_task_by_id(task_id=task_id, db_path=db_path)
    if not task:
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found")
    return task


@app.post("/tasks", response_model=TaskResponse, status_code=201)
def create_new_task(
    payload: TaskCreate,
    db_path: str = Depends(get_database_path),
):
    """Create a new task with synthetic ownership."""
    try:
        return create_task(
            title=payload.title,
            description=payload.description,
            status=payload.status,
            owner_id=payload.owner_id,
            db_path=db_path,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/reports/summary", response_model=ReportSummaryResponse)
def get_summary_report(
    filter_expr: Optional[str] = None,
    db_path: str = Depends(get_database_path),
):
    """Return summary statistics of synthetic tasks with optional dynamic filter evaluation.

    # SFV-003: Dynamic evaluation in report filter helper.
    """
    summary = get_report_summary(db_path=db_path)
    if filter_expr:
        matched = evaluate_report_filter(summary=summary, filter_expr=filter_expr)
        summary["filter_applied"] = filter_expr
        summary["filter_matched"] = matched
    return summary


def run():
    """Start application server ensuring local loopback binding."""
    if not settings.validate_loopback():
        raise RuntimeError(
            f"Security Boundary Violation: Host '{settings.HOST}' is not a local loopback address! "
            "This vulnerable demo must ONLY bind to 127.0.0.1 or localhost."
        )
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=False)


if __name__ == "__main__":
    run()
