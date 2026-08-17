import os

from backend.app.ai.test_schemas import SecurityTest
from backend.app.scanner.dispatcher import dispatch_security_test
from backend.app.scanner.executor import SecurityTestExecutor
from backend.app.validation.dispatcher import validate_dispatch_result


TARGET = "http://localhost:8888"

VEHICLE_ID = "f89b5f21-7829-45cb-a650-299a61090378"

VICTIM_TOKEN = os.environ["CRAPI_VICTIM_TOKEN"]
ATTACKER_TOKEN = os.environ["CRAPI_ATTACKER_TOKEN"]


executor = SecurityTestExecutor(
    target_url=TARGET,
    verify_ssl=False,
)


tests = [
    SecurityTest(
        test_id="TEST-BOLA-VERIFY",
        category="Broken Object Level Authorization (BOLA)",
        method="GET",
        path=f"/identity/api/v2/vehicle/{VEHICLE_ID}/location",
        objective="Verify cross-user object authorization.",
        severity="HIGH",
        requires_authentication=True,
        requires_multiple_users=True,
    ),
    SecurityTest(
        test_id="TEST-AUTH-VERIFY",
        category="Broken Authentication",
        method="GET",
        path=f"/identity/api/v2/vehicle/{VEHICLE_ID}/location",
        objective="Verify authentication enforcement.",
        severity="HIGH",
        requires_authentication=True,
    ),
    SecurityTest(
        test_id="TEST-EDE-VERIFY",
        category="Excessive Data Exposure",
        method="GET",
        path=f"/identity/api/v2/vehicle/{VEHICLE_ID}/location",
        objective="Inspect response for unnecessary sensitive fields.",
        severity="MEDIUM",
        requires_authentication=True,
    ),
    SecurityTest(
        test_id="TEST-RATE-VERIFY",
        category="Rate Limiting",
        method="GET",
        path="/identity/api/v2/user/dashboard",
        objective="Verify effective rate limiting.",
        severity="MEDIUM",
        requires_authentication=True,
    ),
]


print("=" * 70)
print("SECURITY DISPATCHER VERIFICATION")
print("=" * 70)


for test in tests:

    print("\n" + "-" * 70)
    print("Test ID:", test.test_id)
    print("Category:", test.category)
    print("Path:", test.path)

    try:

        result = dispatch_security_test(
            executor=executor,
            test=test,
            victim_headers={
                "Authorization": f"Bearer {VICTIM_TOKEN}",
            },
            attacker_headers={
                "Authorization": f"Bearer {ATTACKER_TOKEN}",
            },
            authenticated_headers={
                "Authorization": f"Bearer {ATTACKER_TOKEN}",
            },
            rate_limit_request_count=20,
        )

        validation = validate_dispatch_result(
            category=result.category,
            execution=result.execution,
        )

        print("Normalized category:", result.category)
        print("Confirmed:", validation.confirmed)
        print("Severity:", validation.severity)
        print("Title:", validation.title)
        print("Explanation:", validation.explanation)

        if result.category == "BOLA":
            print(
                "Victim status:",
                result.execution.victim.status_code,
            )
            print(
                "Attacker status:",
                result.execution.attacker.status_code,
            )

        elif result.category == "AUTHENTICATION":
            print(
                "Authenticated status:",
                result.execution.authenticated_status,
            )
            print(
                "Unauthenticated status:",
                result.execution.unauthenticated_status,
            )

        elif result.category == "INFORMATION_DISCLOSURE":
            print(
                "Exposed fields:",
                result.execution.exposed_fields,
            )
            print(
                "Response status:",
                result.execution.result.status_code,
            )

        elif result.category == "RATE_LIMITING":
            print(
                "Requests:",
                result.execution.total_requests,
            )
            print(
                "Successful:",
                result.execution.successful_requests,
            )
            print(
                "Throttled:",
                result.execution.throttled_requests,
            )

    except Exception as exc:

        print(
            "ERROR:",
            type(exc).__name__,
            str(exc),
        )


print("\n" + "=" * 70)
print("DISPATCHER VERIFICATION COMPLETE")
print("=" * 70)