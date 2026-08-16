from pathlib import Path

from fastapi import APIRouter, HTTPException

from backend.app.api.schemas import (
    DiscoveryResponse,
    EndpointSummary,
)
from backend.app.discovery.parser import load_and_discover


router = APIRouter(prefix="/api", tags=["API Discovery"])


DEFAULT_SPEC_PATH = (
    Path(__file__).resolve().parents[3]
    / "examples"
    / "crapi"
    / "crapi-openapi-spec.json"
)


@router.get(
    "/discovery",
    response_model=DiscoveryResponse,
)
def discover_api():
    """
    Load the configured OpenAPI specification and return
    a normalized API endpoint inventory.
    """

    try:
        specification, endpoints = load_and_discover(
            DEFAULT_SPEC_PATH
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to load OpenAPI specification: {exc}",
        )

    endpoint_summaries = []

    for endpoint in endpoints:
        endpoint_summaries.append(
            EndpointSummary(
                method=endpoint["method"],
                path=endpoint["path"],
                operation_id=endpoint.get("operation_id"),
                summary=endpoint.get("summary"),
                tags=endpoint.get("tags", []),
                authenticated=bool(endpoint.get("security")),
                parameter_count=len(endpoint.get("parameters", [])),
            )
        )

    return DiscoveryResponse(
        api_title=specification.get("info", {}).get(
            "title",
            "Unknown",
        ),
        openapi_version=specification.get(
            "openapi",
            specification.get("swagger", "Unknown"),
        ),
        path_count=len(specification.get("paths", {})),
        operation_count=len(endpoints),
        endpoints=endpoint_summaries,
    )
