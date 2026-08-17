from dataclasses import asdict, dataclass
from typing import Any

from backend.app.scanner.executor import ExecutionResult
from backend.app.validation.authentication_validator import (
    AuthenticationValidationResult,
)
from backend.app.validation.bola_validator import ValidationResult
from backend.app.validation.information_disclosure_validator import (
    InformationDisclosureValidationResult,
)


@dataclass
class SecurityFinding:
    finding_id: str
    test_id: str
    category: str
    title: str
    severity: str
    endpoint: str
    method: str
    description: str
    impact: str
    remediation: str
    confirmed: bool
    evidence: dict[str, Any]


def create_bola_finding(
    *,
    finding_id: str,
    test_id: str,
    endpoint: str,
    victim: ExecutionResult,
    attacker: ExecutionResult,
    validation: ValidationResult,
    victim_identity: str = "victim",
    attacker_identity: str = "attacker",
) -> SecurityFinding:

    evidence = {
        "victim": {
            "identity": victim_identity,
            "method": victim.method,
            "url": victim.url,
            "status_code": victim.status_code,
            "response_body": victim.response_body[:5000],
            "response_time_ms": victim.response_time_ms,
        },
        "attacker": {
            "identity": attacker_identity,
            "method": attacker.method,
            "url": attacker.url,
            "status_code": attacker.status_code,
            "response_body": attacker.response_body[:5000],
            "response_time_ms": attacker.response_time_ms,
        },
        "validation": {
            "confirmed": validation.confirmed,
            "severity": validation.severity,
            "title": validation.title,
        },
    }

    return SecurityFinding(
        finding_id=finding_id,
        test_id=test_id,
        category="BOLA",
        title=validation.title,
        severity=validation.severity,
        endpoint=endpoint,
        method="GET",
        description=(
            "An authenticated user was able to access a vehicle "
            "object belonging to another authorization context."
        ),
        impact=(
            "An attacker can access another user's vehicle data, "
            "including vehicle location and associated user "
            "information."
        ),
        remediation=(
            "Enforce server-side object-level authorization on "
            "the vehicle endpoint. The API must verify that the "
            "authenticated user owns or is explicitly authorized "
            "to access the requested vehicle before returning "
            "its data."
        ),
        confirmed=validation.confirmed,
        evidence=evidence,
    )


def create_authentication_finding(
    *,
    finding_id: str,
    test_id: str,
    endpoint: str,
    execution: Any,
    validation: AuthenticationValidationResult,
) -> SecurityFinding:

    result = execution.result

    evidence = {
        "authenticated_status": execution.authenticated_status,
        "unauthenticated": {
            "method": result.method,
            "url": result.url,
            "status_code": result.status_code,
            "response_body": result.response_body[:5000],
            "response_time_ms": result.response_time_ms,
        },
        "validation": {
            "confirmed": validation.confirmed,
            "severity": validation.severity,
            "title": validation.title,
        },
    }

    return SecurityFinding(
        finding_id=finding_id,
        test_id=test_id,
        category="AUTHENTICATION",
        title=validation.title,
        severity=validation.severity,
        endpoint=endpoint,
        method=result.method,
        description=(
            "The endpoint was tested with and without "
            "authentication credentials to determine whether "
            "the authentication control is enforced."
        ),
        impact=(
            "If authentication is not enforced, an unauthenticated "
            "attacker may access protected API functionality or "
            "sensitive resources."
        ),
        remediation=(
            "Enforce server-side authentication on endpoints "
            "that require authenticated access. Reject requests "
            "without valid authentication credentials with an "
            "appropriate 401 Unauthorized response."
        ),
        confirmed=validation.confirmed,
        evidence=evidence,
    )


def create_information_disclosure_finding(
    *,
    finding_id: str,
    test_id: str,
    endpoint: str,
    execution: Any,
    validation: InformationDisclosureValidationResult,
) -> SecurityFinding:

    result = execution.result

    evidence = {
        "exposed_fields": execution.exposed_fields,
        "response": {
            "method": result.method,
            "url": result.url,
            "status_code": result.status_code,
            "response_body": result.response_body[:5000],
            "response_time_ms": result.response_time_ms,
        },
        "validation": {
            "confirmed": validation.confirmed,
            "severity": validation.severity,
            "title": validation.title,
        },
    }

    return SecurityFinding(
        finding_id=finding_id,
        test_id=test_id,
        category="INFORMATION_DISCLOSURE",
        title=validation.title,
        severity=validation.severity,
        endpoint=endpoint,
        method=result.method,
        description=(
            "The endpoint response was inspected for potentially "
            "sensitive fields that may exceed the minimum data "
            "required by the API operation."
        ),
        impact=(
            "Unnecessary exposure of user information may increase "
            "privacy and data-disclosure risk if the returned "
            "fields are not required by the business function."
        ),
        remediation=(
            "Return only the data required by the API operation. "
            "Review whether exposed user fields such as fullName "
            "and email are necessary and remove unnecessary "
            "personally identifiable information."
        ),
        confirmed=validation.confirmed,
        evidence=evidence,
    )


def finding_to_dict(
    finding: SecurityFinding,
) -> dict[str, Any]:
    return asdict(finding)
