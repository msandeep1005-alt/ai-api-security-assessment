import json
import os

from backend.app.findings.manager import (
    create_bola_finding,
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

from backend.app.scanner.bola import execute_bola_test
from backend.app.scanner.executor import SecurityTestExecutor
from backend.app.scanner.rate_limit import execute_rate_limit_test

from backend.app.validation.rate_limit_validator import (
    validate_rate_limit,
)


TARGET = "http://localhost:8888"

VEHICLE_ID = (
    "f89b5f21-7829-45cb-a650-299a61090378"
)

VICTIM_IDENTITY = "adam007@example.com"
ATTACKER_IDENTITY = "test@example.com"

VICTIM_TOKEN = os.environ["CRAPI_VICTIM_TOKEN"]
ATTACKER_TOKEN = os.environ["CRAPI_ATTACKER_TOKEN"]


executor = SecurityTestExecutor(
    target_url=TARGET,
    verify_ssl=False,
)


# ============================================================
# 1. BOLA TEST
# ============================================================

bola_path = (
    f"/identity/api/v2/vehicle/"
    f"{VEHICLE_ID}/location"
)

bola_endpoint = (
    "/identity/api/v2/vehicle/"
    "{vehicleId}/location"
)


bola_result = execute_bola_test(
    executor=executor,
    test_id="BOLA-001",
    path=bola_path,
    victim_headers={
        "Authorization": f"Bearer {VICTIM_TOKEN}",
    },
    attacker_headers={
        "Authorization": f"Bearer {ATTACKER_TOKEN}",
    },
)


bola_finding = create_bola_finding(
    finding_id="FINDING-001",
    test_id="BOLA-001",
    endpoint=bola_endpoint,
    victim=bola_result.victim,
    attacker=bola_result.attacker,
    validation=bola_result.validation,
    victim_identity=VICTIM_IDENTITY,
    attacker_identity=ATTACKER_IDENTITY,
)


# ============================================================
# 2. RATE LIMIT TEST
# ============================================================

rate_path = "/identity/api/v2/user/dashboard"


rate_result = execute_rate_limit_test(
    executor=executor,
    test_id="RATE-001",
    path=rate_path,
    headers={
        "Authorization": f"Bearer {ATTACKER_TOKEN}",
    },
    request_count=20,
)


rate_statuses = [
    response.status_code
    for response in rate_result.results
]


rate_validation = validate_rate_limit(
    rate_statuses
)


rate_finding = create_rate_limit_finding(
    finding_id="FINDING-002",
    test_id="RATE-001",
    endpoint=rate_path,
    results=rate_result.results,
    validation=rate_validation,
)


# ============================================================
# 3. NORMALIZE FINDINGS
# ============================================================

findings = [
    finding_to_dict(bola_finding),
    rate_limit_finding_to_dict(rate_finding),
]


# ============================================================
# 4. BUILD REPORT
# ============================================================

report = build_report(
    target=TARGET,
    findings=findings,
)


json_path = save_json_report(
    report,
    "reports/security_assessment.json",
)


html_path = render_html_report(
    report,
    "reports/security_assessment.html",
)


# ============================================================
# 5. CONSOLE SUMMARY
# ============================================================

print("=" * 70)
print("AI-ASSISTED API SECURITY ASSESSMENT")
print("=" * 70)


print("\nBOLA TEST")
print("-" * 70)
print("Test ID:", bola_finding.test_id)
print("Endpoint:", bola_finding.endpoint)
print("Victim status:", bola_result.victim.status_code)
print("Attacker status:", bola_result.attacker.status_code)
print("Confirmed:", bola_result.validation.confirmed)
print("Severity:", bola_result.validation.severity)


print("\nRATE LIMIT TEST")
print("-" * 70)
print("Test ID:", rate_finding.test_id)
print("Endpoint:", rate_finding.endpoint)
print("Requests:", rate_result.total_requests)
print("Successful:", rate_result.successful_requests)
print("Throttled:", rate_result.throttled_requests)
print("Confirmed:", rate_validation.confirmed)
print("Severity:", rate_validation.severity)


print("\nASSESSMENT SUMMARY")
print("-" * 70)
print(
    "Overall status:",
    report["executive_summary"]["overall_status"],
)

print(
    "Total findings:",
    report["executive_summary"]["total_findings"],
)

print(
    "Confirmed findings:",
    report["executive_summary"]
    ["total_tests_with_findings"],
)

print(
    "Critical:",
    report["executive_summary"]
    ["severity_counts"]["CRITICAL"],
)

print(
    "High:",
    report["executive_summary"]
    ["severity_counts"]["HIGH"],
)

print(
    "Medium:",
    report["executive_summary"]
    ["severity_counts"]["MEDIUM"],
)


print("\nREPORT")
print("-" * 70)
print("JSON:", json_path)
print("HTML:", html_path)


print("\nFINDINGS")
print("-" * 70)

for finding in findings:
    print(
        f'{finding["finding_id"]}: '
        f'{finding["title"]} '
        f'[{finding["severity"]}]'
    )
