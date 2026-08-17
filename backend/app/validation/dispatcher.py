from typing import Any

from backend.app.scanner.authentication import AuthenticationExecution
from backend.app.scanner.bola import BOLAExecution
from backend.app.scanner.information_disclosure import (
    InformationDisclosureExecution,
)
from backend.app.scanner.rate_limit import RateLimitExecution

from backend.app.validation.authentication_validator import (
    validate_authentication,
)
from backend.app.validation.bola_validator import validate_bola
from backend.app.validation.information_disclosure_validator import (
    validate_information_disclosure,
)
from backend.app.validation.rate_limit_validator import (
    validate_rate_limit,
)


def validate_dispatch_result(
    category: str,
    execution: Any,
):
    normalized = category.strip().upper()

    if normalized == "BOLA":
        if not isinstance(execution, BOLAExecution):
            raise TypeError("Expected BOLAExecution.")

        return validate_bola(
            attacker_status=execution.attacker.status_code,
            attacker_body=execution.attacker.response_body,
        )

    if normalized == "RATE_LIMITING":
        if not isinstance(execution, RateLimitExecution):
            raise TypeError("Expected RateLimitExecution.")

        statuses = [
            result.status_code
            for result in execution.results
        ]

        return validate_rate_limit(statuses)

    if normalized == "AUTHENTICATION":
        if not isinstance(execution, AuthenticationExecution):
            raise TypeError("Expected AuthenticationExecution.")

        return validate_authentication(
            authenticated_status=execution.authenticated_status,
            unauthenticated_status=execution.unauthenticated_status,
        )

    if normalized == "INFORMATION_DISCLOSURE":
        if not isinstance(
            execution,
            InformationDisclosureExecution,
        ):
            raise TypeError(
                "Expected InformationDisclosureExecution."
            )

        return validate_information_disclosure(
            exposed_fields=execution.exposed_fields,
        )

    raise ValueError(
        f"Unsupported validation category: {category}"
    )
