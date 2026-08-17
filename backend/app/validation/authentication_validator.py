from dataclasses import dataclass


@dataclass
class AuthenticationValidationResult:
    confirmed: bool
    severity: str
    title: str
    explanation: str
    evidence: dict


def validate_authentication(
    authenticated_status: int | None,
    unauthenticated_status: int | None,
) -> AuthenticationValidationResult:

    # A successful unauthenticated response to an endpoint
    # that is expected to require authentication is evidence
    # of a missing authentication control.
    if (
        authenticated_status is not None
        and 200 <= authenticated_status < 300
        and unauthenticated_status is not None
        and 200 <= unauthenticated_status < 300
    ):
        return AuthenticationValidationResult(
            confirmed=True,
            severity="HIGH",
            title="Broken Authentication Control",
            explanation=(
                "The endpoint returned a successful response "
                "without authentication even though an "
                "authenticated request was expected."
            ),
            evidence={
                "authenticated_status": authenticated_status,
                "unauthenticated_status": unauthenticated_status,
            },
        )

    return AuthenticationValidationResult(
        confirmed=False,
        severity="INFO",
        title="Authentication Control Not Confirmed Broken",
        explanation=(
            "The unauthenticated request did not receive a "
            "successful response."
        ),
        evidence={
            "authenticated_status": authenticated_status,
            "unauthenticated_status": unauthenticated_status,
        },
    )
