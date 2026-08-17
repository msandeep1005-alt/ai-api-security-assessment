from backend.app.ai.analyzer import analyze_endpoint
from backend.app.ai.generator import generate_test_plan
from backend.app.discovery.parser import load_and_discover


SPEC = r"C:\seconize-assignment\crAPI\openapi-spec\crapi-openapi-spec.json"


specification, endpoints = load_and_discover(SPEC)

target = next(
    endpoint
    for endpoint in endpoints
    if endpoint["path"] == "/identity/api/v2/vehicle/{vehicleId}/location"
    and endpoint["method"] == "GET"
)


print("=" * 70)
print("AI ENDPOINT ANALYSIS")
print("=" * 70)

print("Endpoint:")
print(target["method"], target["path"])

analysis = analyze_endpoint(target)

print("\nSECURITY ANALYSIS")
print("-" * 70)
print("Security sensitive:", analysis.security_sensitive)
print("Authentication required:", analysis.authentication_required)
print("Authorization sensitive:", analysis.authorization_sensitive)
print("Object identifier:", analysis.object_identifier)
print("Potential vulnerabilities:")
for item in analysis.potential_vulnerabilities:
    print(" -", item)

print("Recommended tests:")
for item in analysis.recommended_tests:
    print(" -", item)

print("Reasoning:", analysis.reasoning)
print("Confidence:", analysis.confidence)


print("\nAI TEST GENERATION")
print("-" * 70)

plan = generate_test_plan(
    endpoint=target,
    analysis=analysis,
)

print("Endpoint:", plan.endpoint)
print("Generated tests:", len(plan.tests))

for test in plan.tests:
    print("\nTest ID:", test.test_id)
    print("Category:", test.category)
    print("Method:", test.method)
    print("Path:", test.path)
    print("Objective:", test.objective)
    print("Severity:", test.severity)
    print("Authentication required:", test.requires_authentication)
    print("Multiple users required:", test.requires_multiple_users)

    print("Steps:")
    for step in test.test_steps:
        print("  -", step)

    print("Expected behavior:", test.expected_behavior)

    print("Validation criteria:")
    for criterion in test.validation_criteria:
        print("  -", criterion)

print("\n" + "=" * 70)
print("AI PIPELINE TEST COMPLETE")
print("=" * 70)
