import os

from backend.app.ai.schemas import SecurityAnalysis
from backend.app.ai.test_schemas import SecurityTest, SecurityTestPlan
from backend.app.ai.analyzer import analyze_endpoint
from backend.app.ai.generator import generate_test_plan
from backend.app.discovery.parser import load_and_discover

from backend.app.scanner.dispatcher import dispatch_security_test
from backend.app.scanner.executor import SecurityTestExecutor

from backend.app.validation.dispatcher import validate_dispatch_result

from backend.app.findings.manager import (
    create_bola_finding,
    create_authentication_finding,
    create_information_disclosure_finding,
    finding_to_dict,
)

from backend.app.findings.rate_limit import (
    create_rate_limit_finding,
    rate_limit_finding_to_dict,
)

from backend.app.reporting.generator import (
    build_report,
    save_json_report,
    render_html_report,
)


# ============================================================
# CONFIGURATION
# ============================================================

SPEC = r".\examples\crapi\crapi-openapi-spec.json"

TARGET = os.getenv(
    "TARGET_URL",
    "http://localhost:8888",
)

VICTIM_IDENTITY = "adam007@example.com"
ATTACKER_IDENTITY = "test@example.com"

VICTIM_TOKEN = os.environ["CRAPI_VICTIM_TOKEN"]
ATTACKER_TOKEN = os.environ["CRAPI_ATTACKER_TOKEN"]

VEHICLE_ID = "f89b5f21-7829-45cb-a650-299a61090378"

RATE_LIMIT_REQUEST_COUNT = 20


# ============================================================
# FALLBACK SECURITY TEST PLAN
# ============================================================

def build_fallback_test_plan(endpoint: dict) -> SecurityTestPlan:
    """
    Deterministic fallback test plan used when the Gemini API
    is temporarily unavailable or quota-limited.

    These tests correspond to the security tests already
    identified by the AI pipeline for the selected crAPI
    endpoint.
    """

    path = endpoint["path"]

    tests = [
        SecurityTest(
            test_id="TEST-BOLA-FALLBACK-001",
            category="Broken Object Level Authorization (BOLA)",
            method="GET",
            path=path,
            objective=(
                "Verify that an authenticated user cannot access "
                "the vehicle location belonging to another user."
            ),
            severity="HIGH",
            requires_authentication=True,
            requires_multiple_users=True,
            test_steps=[
                "Authenticate as the victim user.",
                "Authenticate as the attacker user.",
                "Use the attacker token to request the victim vehicle object.",
                "Compare the response against the expected authorization behavior.",
            ],
            expected_behavior=(
                "The API should reject cross-user access with "
                "HTTP 403 Forbidden or HTTP 404 Not Found."
            ),
            validation_criteria=[
                "HTTP 403 or 404 indicates access was denied.",
                "HTTP 2xx for the cross-user request indicates potential BOLA.",
                "The response must not expose the victim vehicle location to the attacker.",
            ],
        ),
        SecurityTest(
            test_id="TEST-AUTH-FALLBACK-001",
            category="Broken Authentication",
            method="GET",
            path=path,
            objective=(
                "Verify that the endpoint rejects requests without "
                "valid authentication credentials."
            ),
            severity="HIGH",
            requires_authentication=True,
            requires_multiple_users=False,
            test_steps=[
                "Send an authenticated request to establish the expected protected response.",
                "Send the same request without an Authorization header.",
                "Compare the authenticated and unauthenticated responses.",
            ],
            expected_behavior=(
                "The unauthenticated request should be rejected "
                "with HTTP 401 Unauthorized."
            ),
            validation_criteria=[
                "Authenticated request should succeed.",
                "Unauthenticated request should not return a successful 2xx response.",
                "HTTP 401 is the expected authentication rejection.",
            ],
        ),
        SecurityTest(
            test_id="TEST-EDE-FALLBACK-001",
            category="Excessive Data Exposure",
            method="GET",
            path=path,
            objective=(
                "Inspect the authorized response for potentially "
                "unnecessary personally identifiable information."
            ),
            severity="MEDIUM",
            requires_authentication=True,
            requires_multiple_users=False,
            test_steps=[
                "Send an authenticated request for the authorized vehicle.",
                "Inspect the JSON response fields.",
                "Identify potentially sensitive fields such as fullName and email.",
                "Determine whether those fields are required by the endpoint's business purpose.",
            ],
            expected_behavior=(
                "The endpoint should return only the minimum information "
                "required for the vehicle-location operation."
            ),
            validation_criteria=[
                "Identify the presence of fullName.",
                "Identify the presence of email.",
                "Presence alone should be treated as potential exposure requiring business review.",
            ],
        ),
    ]

    return SecurityTestPlan(
        endpoint=path,
        tests=tests,
    )


# ============================================================
# SAFE AI PIPELINE
# ============================================================

def obtain_ai_test_plan(
    endpoint: dict,
    analysis: SecurityAnalysis,
) -> tuple[SecurityTestPlan, bool]:
    """
    Attempt Gemini test generation.

    Returns:
        (test_plan, ai_generation_success)
    """

    try:
        plan = generate_test_plan(
            endpoint=endpoint,
            analysis=analysis,
        )

        return plan, True

    except Exception as exc:
        print()
        print(
            "AI TEST GENERATION WARNING:",
            type(exc).__name__,
            str(exc),
        )
        print(
            "Using deterministic fallback security tests."
        )

        return (
            build_fallback_test_plan(endpoint),
            False,
        )


# ============================================================
# DISCOVERY
# ============================================================

print("=" * 70)
print("AI-ASSISTED API SECURITY ASSESSMENT")
print("=" * 70)

print("\nDISCOVERY")
print("-" * 70)

specification, endpoints = load_and_discover(SPEC)

print(
    "API:",
    specification.get("info", {}).get("title"),
)

print(
    "OpenAPI:",
    specification.get(
        "openapi",
        specification.get("swagger"),
    ),
)

print(
    "Paths:",
    len(specification.get("paths", {})),
)

print(
    "Operations:",
    len(endpoints),
)


# ============================================================
# TARGET ENDPOINT
# ============================================================

target = next(
    endpoint
    for endpoint in endpoints
    if endpoint["path"]
    == "/identity/api/v2/vehicle/{vehicleId}/location"
    and endpoint["method"] == "GET"
)

print("\nTARGET ENDPOINT")
print("-" * 70)

print(
    target["method"],
    target["path"],
)


# ============================================================
# AI ANALYSIS
# ============================================================

print("\nAI ANALYSIS")
print("-" * 70)

try:

    analysis = analyze_endpoint(target)

    ai_analysis_available = True

    print(
        "Security sensitive:",
        analysis.security_sensitive,
    )

    print(
        "Authentication required:",
        analysis.authentication_required,
    )

    print(
        "Authorization sensitive:",
        analysis.authorization_sensitive,
    )

    print(
        "Object identifier:",
        analysis.object_identifier,
    )

    print(
        "Confidence:",
        analysis.confidence,
    )

    print("\nPotential vulnerabilities:")

    for item in analysis.potential_vulnerabilities:
        print(" -", item)

    print("\nRecommended tests:")

    for item in analysis.recommended_tests:
        print(" -", item)

except Exception as exc:

    print(
        "AI ANALYSIS WARNING:",
        type(exc).__name__,
        str(exc),
    )

    print(
        "Gemini analysis unavailable."
    )

    print(
        "Using previously established endpoint security characteristics."
    )

    ai_analysis_available = False

    analysis = SecurityAnalysis(
        security_sensitive=True,
        authentication_required=True,
        authorization_sensitive=True,
        object_identifier="vehicleId",
        potential_vulnerabilities=[
            "Broken Object Level Authorization (BOLA)",
            "Excessive Data Exposure",
            "Authentication weaknesses",
            "Rate limiting / unrestricted resource consumption",
        ],
        recommended_tests=[
            "BOLA cross-user authorization test",
            "Authentication enforcement test",
            "Information disclosure test",
            "Rate limiting test",
        ],
        reasoning=(
            "The endpoint uses a security-sensitive vehicleId "
            "object identifier and returns vehicle location and "
            "user-associated information."
        ),
        confidence=0.9,
    )


# ============================================================
# AI TEST GENERATION
# ============================================================

print("\nAI TEST GENERATION")
print("-" * 70)

plan, ai_generation_available = obtain_ai_test_plan(
    endpoint=target,
    analysis=analysis,
)

print(
    "Generated tests:",
    len(plan.tests),
)

print(
    "AI generation used:",
    ai_generation_available,
)


# ============================================================
# ENSURE RATE LIMITING TEST EXISTS
# ============================================================

has_rate_limit_test = any(
    "rate limit" in test.category.lower()
    or "unrestricted resource" in test.category.lower()
    for test in plan.tests
)

if not has_rate_limit_test:

    print(
        "\nAdding deterministic rate-limiting test."
    )

    rate_test = SecurityTest(
        test_id="TEST-RATE-001",
        category="Rate Limiting",
        method="GET",
        path="/identity/api/v2/user/dashboard",
        objective=(
            "Determine whether repeated authenticated requests "
            "are effectively throttled."
        ),
        severity="MEDIUM",
        requires_authentication=True,
        requires_multiple_users=False,
        test_steps=[
            "Authenticate using a valid user token.",
            f"Send {RATE_LIMIT_REQUEST_COUNT} consecutive requests.",
            "Record all HTTP response status codes.",
            "Check whether HTTP 429 responses are returned.",
        ],
        expected_behavior=(
            "The API should apply effective request throttling "
            "when request volume exceeds the intended limit."
        ),
        validation_criteria=[
            "Repeated successful requests without throttling may indicate missing rate limiting.",
            "HTTP 429 responses provide evidence of request throttling.",
        ],
    )

    plan.tests.append(rate_test)


# ============================================================
# EXECUTOR
# ============================================================

executor = SecurityTestExecutor(
    target_url=TARGET,
    verify_ssl=False,
)


# ============================================================
# EXECUTION + VALIDATION
# ============================================================

findings = []

print("\n")
print("=" * 70)
print("SECURITY TEST EXECUTION")
print("=" * 70)


for index, test in enumerate(
    plan.tests,
    start=1,
):

    print("\n" + "-" * 70)
    print(f"TEST {index}")
    print("-" * 70)

    print(
        "Test ID:",
        test.test_id,
    )

    print(
        "Category:",
        test.category,
    )

    print(
        "Method:",
        test.method,
    )

    print(
        "Path:",
        test.path,
    )

    print(
        "Severity:",
        test.severity,
    )

    try:

        # ----------------------------------------------------
        # Resolve OpenAPI path parameters.
        # ----------------------------------------------------

        concrete_path = test.path.replace(
            "{vehicleId}",
            VEHICLE_ID,
        )

        concrete_test = test.model_copy(
            update={
                "path": concrete_path,
            }
        )

        print(
            "Concrete path:",
            concrete_test.path,
        )

        # ----------------------------------------------------
        # Dispatch
        # ----------------------------------------------------

        dispatch_result = dispatch_security_test(
            executor=executor,
            test=concrete_test,
            victim_headers={
                "Authorization": (
                    f"Bearer {VICTIM_TOKEN}"
                ),
            },
            attacker_headers={
                "Authorization": (
                    f"Bearer {ATTACKER_TOKEN}"
                ),
            },
            authenticated_headers={
                "Authorization": (
                    f"Bearer {ATTACKER_TOKEN}"
                ),
            },
            rate_limit_request_count=(
                RATE_LIMIT_REQUEST_COUNT
            ),
        )

        # ----------------------------------------------------
        # Validation
        # ----------------------------------------------------

        validation = validate_dispatch_result(
            category=dispatch_result.category,
            execution=dispatch_result.execution,
        )

        print(
            "Normalized category:",
            dispatch_result.category,
        )

        print(
            "Confirmed:",
            validation.confirmed,
        )

        print(
            "Validation severity:",
            validation.severity,
        )

        print(
            "Title:",
            validation.title,
        )

        print(
            "Explanation:",
            validation.explanation,
        )

        # ----------------------------------------------------
        # Finding ID
        # ----------------------------------------------------

        finding_number = len(findings) + 1

        finding_id = (
            f"FINDING-{finding_number:03d}"
        )

        category = dispatch_result.category

        # ----------------------------------------------------
        # BOLA
        # ----------------------------------------------------

        if category == "BOLA":

            finding = create_bola_finding(
                finding_id=finding_id,
                test_id=test.test_id,
                endpoint=target["path"],
                victim=(
                    dispatch_result.execution.victim
                ),
                attacker=(
                    dispatch_result.execution.attacker
                ),
                validation=validation,
                victim_identity=VICTIM_IDENTITY,
                attacker_identity=ATTACKER_IDENTITY,
            )

            findings.append(
                finding_to_dict(finding)
            )

        # ----------------------------------------------------
        # RATE LIMITING
        # ----------------------------------------------------

        elif category == "RATE_LIMITING":

            finding = create_rate_limit_finding(
                finding_id=finding_id,
                test_id=test.test_id,
                endpoint=concrete_test.path,
                results=(
                    dispatch_result.execution.results
                ),
                validation=validation,
            )

            findings.append(
                rate_limit_finding_to_dict(
                    finding
                )
            )

        # ----------------------------------------------------
        # AUTHENTICATION
        # ----------------------------------------------------

        elif category == "AUTHENTICATION":

            finding = create_authentication_finding(
                finding_id=finding_id,
                test_id=test.test_id,
                endpoint=target["path"],
                execution=(
                    dispatch_result.execution
                ),
                validation=validation,
            )

            findings.append(
                finding_to_dict(finding)
            )

        # ----------------------------------------------------
        # INFORMATION DISCLOSURE
        # ----------------------------------------------------

        elif category == "INFORMATION_DISCLOSURE":

            finding = (
                create_information_disclosure_finding(
                    finding_id=finding_id,
                    test_id=test.test_id,
                    endpoint=target["path"],
                    execution=(
                        dispatch_result.execution
                    ),
                    validation=validation,
                )
            )

            findings.append(
                finding_to_dict(finding)
            )

        else:

            print(
                "Execution skipped: unsupported category."
            )

    except Exception as exc:

        print(
            "TEST ERROR:",
            type(exc).__name__,
            str(exc),
        )


# ============================================================
# REPORT
# ============================================================

report = build_report(
    target=TARGET,
    findings=findings,
)


json_path = save_json_report(
    report,
    "reports/ai_security_assessment.json",
)


html_path = render_html_report(
    report,
    "reports/ai_security_assessment.html",
)


# ============================================================
# SUMMARY
# ============================================================

summary = report[
    "executive_summary"
]


print("\n")
print("=" * 70)
print("ASSESSMENT COMPLETE")
print("=" * 70)

print(
    "Overall status:",
    summary["overall_status"],
)

print(
    "Total findings:",
    summary["total_findings"],
)

print(
    "Confirmed findings:",
    summary[
        "total_tests_with_findings"
    ],
)

print(
    "Critical:",
    summary["severity_counts"]["CRITICAL"],
)

print(
    "High:",
    summary["severity_counts"]["HIGH"],
)

print(
    "Medium:",
    summary["severity_counts"]["MEDIUM"],
)

print(
    "Low:",
    summary["severity_counts"]["LOW"],
)

print(
    "Info:",
    summary["severity_counts"]["INFO"],
)


print("\nREPORTS")
print("-" * 70)

print(
    "JSON:",
    json_path,
)

print(
    "HTML:",
    html_path,
)


print("\nFINDINGS")
print("-" * 70)


for finding in findings:

    print(
        f'{finding["finding_id"]}: '
        f'{finding["title"]} '
        f'[{finding["severity"]}] '
        f'confirmed={finding["confirmed"]}'
    )


print("\nAI PIPELINE STATUS")
print("-" * 70)

print(
    "AI analysis available:",
    ai_analysis_available,
)

print(
    "AI test generation available:",
    ai_generation_available,
)

print(
    "Assessment execution:",
    "COMPLETED",
)
