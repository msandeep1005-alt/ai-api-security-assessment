from dataclasses import dataclass


@dataclass
class InformationDisclosureValidationResult:
    confirmed: bool
    severity: str
    title: str
    explanation: str
    evidence: dict


def validate_information_disclosure(
    exposed_fields: list[str],
    expected_sensitive_fields: list[str] | None = None,
) -> InformationDisclosureValidationResult:

    if expected_sensitive_fields is None:
        expected_sensitive_fields = [
            "fullName",
            "email",
        ]

    relevant_fields = [
        field
        for field in exposed_fields
        if field in expected_sensitive_fields
    ]

    if relevant_fields:
        return InformationDisclosureValidationResult(
            confirmed=False,
            severity="MEDIUM",
            title="Potential Excessive Data Exposure",
            explanation=(
                "The endpoint response contains fields that "
                "may expose additional user information. "
                "Business justification is required before "
                "classifying the exposure as a confirmed "
                "vulnerability."
            ),
            evidence={
                "exposed_fields": relevant_fields,
                "expected_sensitive_fields": (
                    expected_sensitive_fields
                ),
            },
        )

    return InformationDisclosureValidationResult(
        confirmed=False,
        severity="INFO",
        title="Excessive Data Exposure Not Observed",
        explanation=(
            "No explicitly monitored potentially sensitive "
            "fields were observed in the response."
        ),
        evidence={
            "exposed_fields": exposed_fields,
            "expected_sensitive_fields": (
                expected_sensitive_fields
            ),
        },
    )
