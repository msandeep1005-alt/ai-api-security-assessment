from dataclasses import asdict, dataclass
from typing import Any

from backend.app.scanner.executor import ExecutionResult
from backend.app.validation.rate_limit_validator import (
    RateLimitValidationResult,
)


@dataclass
class RateLimitFinding:
    finding_id: str
    test_id: str
    category: str
    title: str
    severity: str
    endpoint: str
    method: str
    description: str
    impact: str
    remediation: str
    confirmed: bool
    evidence: dict[str, Any]


def create_rate_limit_finding(
    *,
    finding_id: str,
    test_id: str,
    endpoint: str,
    results: list[ExecutionResult],
    validation: RateLimitValidationResult,
) -> RateLimitFinding:

    return RateLimitFinding(
        finding_id=finding_id,
        test_id=test_id,
        category="RATE_LIMITING",
        title=validation.title,
        severity=validation.severity,
        endpoint=endpoint,
        method="GET",
        description=(
            "The authenticated endpoint accepted repeated "
            "requests without returning HTTP 429 throttling "
            "responses during the assessment."
        ),
        impact=(
            "Insufficient request throttling may allow an "
            "attacker to consume excessive application resources "
            "or repeatedly invoke an API operation without an "
            "effective server-side request limit."
        ),
        remediation=(
            "Implement server-side rate limiting appropriate "
            "to the endpoint and threat model. Apply limits "
            "using authenticated identity and, where appropriate, "
            "IP address and endpoint-specific controls. Return "
            "HTTP 429 when the configured threshold is exceeded."
        ),
        confirmed=validation.confirmed,
        evidence={
            "total_requests": len(results),
            "successful_requests": sum(
                1
                for result in results
                if result.status_code is not None
                and 200 <= result.status_code < 300
            ),
            "throttled_requests": sum(
                1
                for result in results
                if result.status_code == 429
            ),
            "requests": [
                {
                    "method": result.method,
                    "url": result.url,
                    "status_code": result.status_code,
                    "response_time_ms": result.response_time_ms,
                }
                for result in results
            ],
            "validation": {
                "confirmed": validation.confirmed,
                "severity": validation.severity,
                "title": validation.title,
                "explanation": validation.explanation,
            },
        },
    )


def rate_limit_finding_to_dict(
    finding: RateLimitFinding,
) -> dict[str, Any]:
    return asdict(finding)
