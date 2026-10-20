"""Pydantic schemas for request and response validation.

Part of securefix-vuln-lab.
"""

from typing import Dict, Literal, Optional
from pydantic import BaseModel, Field

TaskStatus = Literal["pending", "in_progress", "completed", "cancelled"]


class TaskCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=200, description="Task title")
    description: str = Field(default="", max_length=1000, description="Task description")
    status: TaskStatus = Field(default="pending", description="Task status")
    owner_id: str = Field(default="owner_1", min_length=1, max_length=50, description="Synthetic owner ID")


class TaskResponse(BaseModel):
    id: int
    title: str
    description: str
    status: str
    owner_id: str
    created_at: str


class ReportSummaryResponse(BaseModel):
    total_tasks: int
    by_status: Dict[str, int]
    by_owner: Dict[str, int]
    filter_applied: Optional[str] = None
    filter_matched: Optional[bool] = None
