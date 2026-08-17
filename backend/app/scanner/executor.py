from dataclasses import dataclass, field
from typing import Any

import httpx


SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
}


def sanitize_headers(
    headers: dict[str, str],
) -> dict[str, str]:
    """
    Remove secrets from headers before they are stored as evidence.

    The original headers are still used for the HTTP request.
    """

    sanitized = {}

    for name, value in headers.items():
        if name.lower() in SENSITIVE_HEADERS:
            sanitized[name] = "[REDACTED]"
        else:
            sanitized[name] = value

    return sanitized


@dataclass
class ExecutionResult:
    test_id: str
    method: str
    url: str
    status_code: int | None
    response_time_ms: float
    response_body: str
    request_headers: dict[str, str] = field(default_factory=dict)
    error: str | None = None


class SecurityTestExecutor:
    """
    Executes authorized API security tests against a configured target.

    This executor records the HTTP evidence required by the validator
    while ensuring sensitive request headers are not persisted.
    """

    def __init__(
        self,
        target_url: str,
        timeout: float = 15.0,
        verify_ssl: bool = True,
    ):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    def execute(
        self,
        test_id: str,
        method: str,
        path: str,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
    ) -> ExecutionResult:

        url = f"{self.target_url}/{path.lstrip('/')}"
        request_headers = headers or {}

        # Keep real credentials for the actual request.
        # Only the sanitized copy is stored in ExecutionResult.
        evidence_headers = sanitize_headers(
            request_headers
        )

        try:
            with httpx.Client(
                timeout=self.timeout,
                verify=self.verify_ssl,
                follow_redirects=False,
            ) as client:

                response = client.request(
                    method=method.upper(),
                    url=url,
                    headers=request_headers,
                    params=params,
                    json=json_body,
                )

                return ExecutionResult(
                    test_id=test_id,
                    method=method.upper(),
                    url=url,
                    status_code=response.status_code,
                    response_time_ms=(
                        response.elapsed.total_seconds() * 1000
                    ),
                    response_body=response.text,
                    request_headers=evidence_headers,
                )

        except Exception as exc:
            return ExecutionResult(
                test_id=test_id,
                method=method.upper(),
                url=url,
                status_code=None,
                response_time_ms=0.0,
                response_body="",
                request_headers=evidence_headers,
                error=str(exc),
            )
