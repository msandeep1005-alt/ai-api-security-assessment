from dataclasses import dataclass

from backend.app.scanner.executor import (
    ExecutionResult,
    SecurityTestExecutor,
)


@dataclass
class InformationDisclosureExecution:
    result: ExecutionResult
    exposed_fields: list[str]


def execute_information_disclosure_test(
    executor: SecurityTestExecutor,
    test_id: str,
    path: str,
    headers: dict[str, str] | None = None,
    fields_to_check: list[str] | None = None,
) -> InformationDisclosureExecution:
    """
    Execute an authorized request and inspect the response
    for explicitly specified potentially sensitive fields.

    This scanner identifies exposed fields but does not by
    itself determine whether their exposure is a confirmed
    vulnerability.
    """

    import json

    fields_to_check = fields_to_check or [
        "fullName",
        "email",
    ]

    result = executor.execute(
        test_id=test_id,
        method="GET",
        path=path,
        headers=headers or {},
    )

    exposed_fields = []

    if result.response_body:
        try:
            payload = json.loads(result.response_body)

            for field in fields_to_check:
                if field in payload:
                    exposed_fields.append(field)

        except (json.JSONDecodeError, TypeError):
            pass

    return InformationDisclosureExecution(
        result=result,
        exposed_fields=exposed_fields,
    )
