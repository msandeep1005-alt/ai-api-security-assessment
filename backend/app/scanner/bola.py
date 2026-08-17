from dataclasses import dataclass

from backend.app.scanner.executor import (
    ExecutionResult,
    SecurityTestExecutor,
)
from backend.app.validation.bola_validator import (
    ValidationResult,
    validate_bola,
)


@dataclass
class BOLAExecution:
    victim: ExecutionResult
    attacker: ExecutionResult
    validation: ValidationResult


def execute_bola_test(
    executor: SecurityTestExecutor,
    test_id: str,
    path: str,
    victim_headers: dict[str, str],
    attacker_headers: dict[str, str],
) -> BOLAExecution:
    """
    Execute a BOLA test by requesting the same object with
    two different authorization contexts.

    The victim request establishes expected object access.
    The attacker request checks whether the same object can
    be accessed across authorization boundaries.
    """

    victim_result = executor.execute(
        test_id=f"{test_id}-VICTIM",
        method="GET",
        path=path,
        headers=victim_headers,
    )

    attacker_result = executor.execute(
        test_id=f"{test_id}-ATTACKER",
        method="GET",
        path=path,
        headers=attacker_headers,
    )

    validation = validate_bola(
        attacker_status=attacker_result.status_code,
        attacker_body=attacker_result.response_body,
    )

    return BOLAExecution(
        victim=victim_result,
        attacker=attacker_result,
        validation=validation,
    )
