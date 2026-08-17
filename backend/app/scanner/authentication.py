from dataclasses import dataclass

from backend.app.scanner.executor import (
    ExecutionResult,
    SecurityTestExecutor,
)


@dataclass
class AuthenticationExecution:
    result: ExecutionResult
    authenticated_status: int | None
    unauthenticated_status: int | None


def execute_authentication_test(
    executor: SecurityTestExecutor,
    test_id: str,
    path: str,
    authenticated_headers: dict[str, str] | None = None,
) -> AuthenticationExecution:
    """
    Compare an authenticated request with a request that
    contains no authentication credentials.
    """

    authenticated = executor.execute(
        test_id=f"{test_id}-AUTHENTICATED",
        method="GET",
        path=path,
        headers=authenticated_headers or {},
    )

    unauthenticated = executor.execute(
        test_id=f"{test_id}-UNAUTHENTICATED",
        method="GET",
        path=path,
        headers={},
    )

    return AuthenticationExecution(
        result=unauthenticated,
        authenticated_status=authenticated.status_code,
        unauthenticated_status=unauthenticated.status_code,
    )
