from dataclasses import dataclass


@dataclass
class RateLimitValidationResult:
    confirmed: bool
    severity: str
    title: str
    explanation: str
    evidence: dict


def validate_rate_limit(
    statuses: list[int | None],
) -> RateLimitValidationResult:

    total = len(statuses)

    successful = sum(
        1
        for status in statuses
        if status is not None
        and 200 <= status < 300
    )

    throttled = sum(
        1
        for status in statuses
        if status == 429
    )

    failed = total - successful - throttled

    # Evidence threshold used by this assessment:
    # all requests succeeded and none were throttled.
    confirmed = (
        total >= 20
        and successful == total
        and throttled == 0
    )

    if confirmed:
        return RateLimitValidationResult(
            confirmed=True,
            severity="MEDIUM",
            title="No Effective Rate Limiting Observed",
            explanation=(
                f"{total} consecutive authenticated requests "
                "were accepted without an HTTP 429 response. "
                "No effective request throttling was observed "
                "during this test."
            ),
            evidence={
                "total_requests": total,
                "successful_requests": successful,
                "throttled_requests": throttled,
                "other_responses": failed,
                "status_codes": statuses,
            },
        )

    return RateLimitValidationResult(
        confirmed=False,
        severity="INFO",
        title="Rate Limiting Not Confirmed",
        explanation=(
            "The observed request sequence did not provide "
            "sufficient evidence to confirm missing rate limiting."
        ),
        evidence={
            "total_requests": total,
            "successful_requests": successful,
            "throttled_requests": throttled,
            "other_responses": failed,
            "status_codes": statuses,
        },
    )
