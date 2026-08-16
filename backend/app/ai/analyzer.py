import json
from typing import Any

from backend.app.ai.client import get_gemini_client, get_model_name
from backend.app.ai.schemas import SecurityAnalysis


SYSTEM_INSTRUCTION = """
You are an API security assessment assistant.

Analyze API endpoints using only the supplied OpenAPI
metadata and identify security-relevant characteristics.

Focus particularly on:

- authentication
- authorization
- broken object level authorization (BOLA)
- broken function level authorization
- excessive data exposure
- rate limiting / unrestricted resource consumption
- injection risks
- sensitive information exposure
- security-sensitive identifiers
- trust boundaries

Do not claim that a vulnerability is confirmed merely because
an endpoint appears risky.

Distinguish between:

1. potential risk
2. recommended security test
3. confirmed vulnerability

The analysis is used to generate security tests later.

Return structured JSON matching the requested schema.
"""


def build_analysis_prompt(endpoint: dict[str, Any]) -> str:
    """
    Build the prompt sent to the LLM for one endpoint.
    """

    endpoint_data = {
        "method": endpoint.get("method"),
        "path": endpoint.get("path"),
        "operation_id": endpoint.get("operation_id"),
        "summary": endpoint.get("summary"),
        "description": endpoint.get("description"),
        "tags": endpoint.get("tags", []),
        "security": endpoint.get("security", []),
        "parameters": endpoint.get("parameters", []),
        "request_body": endpoint.get("request_body"),
        "responses": endpoint.get("responses", {}),
    }

    return (
        SYSTEM_INSTRUCTION
        + "\n\nEndpoint metadata:\n"
        + json.dumps(
            endpoint_data,
            indent=2,
            ensure_ascii=False,
        )
        + "\n\nReturn a JSON object with these fields:\n"
        + json.dumps(
            {
                "security_sensitive": True,
                "authentication_required": True,
                "authorization_sensitive": True,
                "object_identifier": "example",
                "potential_vulnerabilities": [],
                "recommended_tests": [],
                "reasoning": "analysis",
                "confidence": 0.0,
            },
            indent=2,
        )
    )


def analyze_endpoint(
    endpoint: dict[str, Any],
) -> SecurityAnalysis:
    """
    Analyze one API endpoint using Gemini.
    """

    client = get_gemini_client()
    model = get_model_name()

    prompt = build_analysis_prompt(endpoint)

    response = client.models.generate_content(
        model=model,
        contents=prompt,
        config={
            "response_mime_type": "application/json",
            "response_schema": SecurityAnalysis,
        },
    )

    if not response.parsed:
        raise RuntimeError(
            "Gemini returned no structured analysis."
        )

    return response.parsed
