from pydantic import BaseModel
from typing import Any


class EndpointSummary(BaseModel):
    method: str
    path: str
    operation_id: str | None = None
    summary: str | None = None
    tags: list[str] = []
    authenticated: bool = False
    parameter_count: int = 0


class DiscoveryResponse(BaseModel):
    api_title: str
    openapi_version: str
    path_count: int
    operation_count: int
    endpoints: list[EndpointSummary]
