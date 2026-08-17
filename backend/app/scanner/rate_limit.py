from dataclasses import dataclass

from backend.app.scanner.executor import (
    ExecutionResult,
    SecurityTestExecutor,
)


@dataclass
class RateLimitExecution:
    results: list[ExecutionResult]
    total_requests: int
    throttled_requests: int
    successful_requests: int


def execute_rate_limit_test(
    executor: SecurityTestExecutor,
    test_id: str,
    path: str,
    headers: dict[str, str] | None = None,
    request_count: int = 20,
) -> RateLimitExecution:
    """
    Execute repeated requests against an authorized endpoint
    to determine whether the API applies rate limiting.
    """

    results = []

    for index in range(request_count):
        result = executor.execute(
            test_id=f"{test_id}-{index + 1:03d}",
            method="GET",
            path=path,
            headers=headers or {},
        )

        results.append(result)

    throttled = sum(
        1
        for result in results
        if result.status_code in {429}
    )

    successful = sum(
        1
        for result in results
        if result.status_code is not None
        and 200 <= result.status_code < 300
    )

    return RateLimitExecution(
        results=results,
        total_requests=len(results),
        throttled_requests=throttled,
        successful_requests=successful,
    )
