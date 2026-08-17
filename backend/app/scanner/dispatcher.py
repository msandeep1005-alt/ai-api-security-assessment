from dataclasses import dataclass
from typing import Any

from backend.app.ai.test_schemas import SecurityTest

from backend.app.scanner.authentication import (
    execute_authentication_test,
)
from backend.app.scanner.bola import (
    execute_bola_test,
)
from backend.app.scanner.executor import SecurityTestExecutor
from backend.app.scanner.information_disclosure import (
    execute_information_disclosure_test,
)
from backend.app.scanner.rate_limit import (
    execute_rate_limit_test,
)


@dataclass
class DispatchResult:
    test: SecurityTest
    category: str
    execution: Any


def normalize_category(category: str) -> str:
    value = category.strip().lower()

    if (
        "broken object" in value
        or "bola" in value
        or "idor" in value
    ):
        return "BOLA"

    if (
        "rate limit" in value
        or "unrestricted resource" in value
    ):
        return "RATE_LIMITING"

    if "authentication" in value:
        return "AUTHENTICATION"

    if (
        "information disclosure" in value
        or "excessive data" in value
    ):
        return "INFORMATION_DISCLOSURE"

    return "UNSUPPORTED"


def dispatch_security_test(
    *,
    executor: SecurityTestExecutor,
    test: SecurityTest,
    path: str | None = None,
    victim_headers: dict[str, str] | None = None,
    attacker_headers: dict[str, str] | None = None,
    authenticated_headers: dict[str, str] | None = None,
    rate_limit_request_count: int = 20,
) -> DispatchResult:
    """
    Dispatch an AI-generated security test to the appropriate
    deterministic scanner.

    `path` allows the caller to supply a concrete runtime path
    after resolving OpenAPI placeholders such as {vehicleId}.
    """

    category = normalize_category(test.category)

    execution_path = path or test.path

    if "{" in execution_path or "}" in execution_path:
        raise ValueError(
            f"Unresolved path parameter in execution path: "
            f"{execution_path}"
        )

    if category == "BOLA":
        if not victim_headers or not attacker_headers:
            raise ValueError(
                "BOLA tests require victim and attacker headers."
            )

        execution = execute_bola_test(
            executor=executor,
            test_id=test.test_id,
            path=execution_path,
            victim_headers=victim_headers,
            attacker_headers=attacker_headers,
        )

    elif category == "RATE_LIMITING":
        execution = execute_rate_limit_test(
            executor=executor,
            test_id=test.test_id,
            path=execution_path,
            headers=authenticated_headers or {},
            request_count=rate_limit_request_count,
        )

    elif category == "AUTHENTICATION":
        execution = execute_authentication_test(
            executor=executor,
            test_id=test.test_id,
            path=execution_path,
            authenticated_headers=authenticated_headers or {},
        )

    elif category == "INFORMATION_DISCLOSURE":
        execution = execute_information_disclosure_test(
            executor=executor,
            test_id=test.test_id,
            path=execution_path,
            headers=authenticated_headers or {},
        )

    else:
        raise ValueError(
            f"Unsupported security test category: {test.category}"
        )

    return DispatchResult(
        test=test,
        category=category,
        execution=execution,
    )
