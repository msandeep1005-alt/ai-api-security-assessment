import json
from typing import Any

from backend.app.ai.client import get_gemini_client, get_model_name
from backend.app.ai.schemas import SecurityAnalysis
from backend.app.ai.test_schemas import SecurityTestPlan


TEST_GENERATION_INSTRUCTION = """
You are an API security test-generation assistant.

Generate practical, safe, authorized security tests for the
supplied API endpoint and its AI security analysis.

The tests will later be executed by an automated API security
assessment engine against an explicitly authorized target.

Focus on:

- Broken Object Level Authorization (BOLA)
- Authentication weaknesses
- Authorization weaknesses
- Excessive data exposure
- Rate limiting / unrestricted resource consumption
- Input validation where relevant

Do not claim that a vulnerability is confirmed.

Generate tests that can produce objective evidence.

Each test must contain:
- unique test ID
- category
- HTTP method
- path
- objective
- severity
- authentication requirements
- whether multiple users are required
- concrete test steps
- expected behavior
- validation criteria

Return only structured JSON matching the requested schema.
"""


def build_test_generation_prompt(
    endpoint: dict[str, Any],
    analysis: SecurityAnalysis,
) -> str:
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

    analysis_data = analysis.model_dump()

    return (
        TEST_GENERATION_INSTRUCTION
        + "\n\nEndpoint:\n"
        + json.dumps(endpoint_data, indent=2, ensure_ascii=False)
        + "\n\nAI security analysis:\n"
        + json.dumps(analysis_data, indent=2, ensure_ascii=False)
        + "\n\nReturn a JSON object matching SecurityTestPlan."
    )


def generate_test_plan(
    endpoint: dict[str, Any],
    analysis: SecurityAnalysis,
) -> SecurityTestPlan:
    client = get_gemini_client()
    model = get_model_name()

    prompt = build_test_generation_prompt(
        endpoint,
        analysis,
    )

    response = client.models.generate_content(
        model=model,
        contents=prompt,
        config={
            "response_mime_type": "application/json",
            "response_schema": SecurityTestPlan,
        },
    )

    if not response.parsed:
        raise RuntimeError(
            "Gemini returned no structured security test plan."
        )

    return response.parsed
