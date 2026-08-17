from dataclasses import dataclass


@dataclass
class ValidationResult:
    confirmed: bool
    severity: str
    title: str
    explanation: str
    evidence: dict


def validate_bola(
    attacker_status: int | None,
    attacker_body: str,
    expected_denied_statuses: set[int] | None = None,
) -> ValidationResult:

    if expected_denied_statuses is None:
        expected_denied_statuses = {401, 403, 404}

    if attacker_status in expected_denied_statuses:
        return ValidationResult(
            confirmed=False,
            severity="HIGH",
            title="BOLA not confirmed",
            explanation=(
                "The cross-user request was rejected by the API."
            ),
            evidence={
                "attacker_status": attacker_status,
                "expected_denied_statuses": sorted(
                    expected_denied_statuses
                ),
            },
        )

    if attacker_status is not None and 200 <= attacker_status < 300:
        return ValidationResult(
            confirmed=True,
            severity="HIGH",
            title="Broken Object Level Authorization",
            explanation=(
                "An authenticated user received a successful "
                "response for an object belonging to another "
                "authorization context."
            ),
            evidence={
                "attacker_status": attacker_status,
                "response_body": attacker_body[:5000],
            },
        )

    return ValidationResult(
        confirmed=False,
        severity="MEDIUM",
        title="BOLA requires manual review",
        explanation=(
            "The response did not match the expected deny or "
            "successful-access conditions."
        ),
        evidence={
            "attacker_status": attacker_status,
            "response_body": attacker_body[:5000],
        },
    )
