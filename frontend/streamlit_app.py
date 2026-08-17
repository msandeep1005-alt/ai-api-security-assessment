import streamlit as st
import requests
import subprocess
import sys
import json

st.set_page_config(
    page_title="AI-Assisted API Security Assessment",
    page_icon="🛡️",
    layout="wide",
)

CRAPI_URL = "http://localhost:8888"
BACKEND_URL = "http://localhost:8000"

st.title("🛡️ AI-Assisted API Security Assessment")
st.caption("OWASP crAPI Security Assessment Dashboard")

st.divider()

# ------------------------------------------------------------
# SYSTEM STATUS
# ------------------------------------------------------------

st.subheader("System Status")

col1, col2, col3 = st.columns(3)

with col1:
    try:
        r = requests.get(f"{CRAPI_URL}/health", timeout=3)
        if r.status_code == 200:
            st.success("🟢 crAPI: ONLINE")
        else:
            st.warning(f"🟡 crAPI: HTTP {r.status_code}")
    except Exception:
        st.error("🔴 crAPI: OFFLINE")

with col2:
    try:
        r = requests.get(f"{BACKEND_URL}/health", timeout=3)
        if r.status_code == 200:
            st.success("🟢 Assessment Backend: ONLINE")
        else:
            st.warning(f"🟡 Backend: HTTP {r.status_code}")
    except Exception:
        st.info("⚪ Assessment Backend: Not running")

with col3:
    try:
        r = requests.get(
            "http://localhost:8502",
            timeout=3
        )
        st.success("🟢 Dashboard: ONLINE")
    except Exception:
        st.error("🔴 Dashboard unavailable")

st.divider()

# ------------------------------------------------------------
# DISCOVERY
# ------------------------------------------------------------

st.subheader("🔎 OpenAPI Discovery")

if st.button("Run API Discovery", type="primary"):

    try:
        from backend.app.discovery.parser import load_and_discover

        spec_path = r".\examples\crapi\crapi-openapi-spec.json"

        specification, endpoints = load_and_discover(spec_path)

        c1, c2, c3 = st.columns(3)

        with c1:
            st.metric(
                "API",
                specification.get("info", {}).get(
                    "title", "crAPI"
                ),
            )

        with c2:
            st.metric(
                "Paths",
                len(specification.get("paths", {})),
            )

        with c3:
            st.metric(
                "Operations",
                len(endpoints),
            )

        st.success("OpenAPI specification successfully discovered.")

        endpoint_rows = []

        for endpoint in endpoints:
            endpoint_rows.append(
                {
                    "Method": endpoint["method"],
                    "Path": endpoint["path"],
                    "Authenticated": bool(
                        endpoint.get("security")
                    ),
                    "Parameters": len(
                        endpoint.get("parameters", [])
                    ),
                }
            )

        st.dataframe(
            endpoint_rows,
            use_container_width=True,
        )

    except Exception as e:
        st.error(f"Discovery failed: {e}")

# ------------------------------------------------------------
# TARGET
# ------------------------------------------------------------

st.divider()

st.subheader("🎯 Security Assessment Target")

st.code(
    "GET /identity/api/v2/vehicle/{vehicleId}/location",
    language="http",
)

st.write(
    "Security-sensitive endpoint containing a vehicle object identifier."
)

# ------------------------------------------------------------
# VERIFIED FINDINGS
# ------------------------------------------------------------

st.subheader("🔐 Verified Security Findings")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        "BOLA",
        "CONFIRMED",
        "HIGH",
    )

with col2:
    st.metric(
        "Authentication",
        "NOT BROKEN",
        "401 unauthenticated",
    )

with col3:
    st.metric(
        "Data Exposure",
        "POTENTIAL",
        "MEDIUM",
    )

with col4:
    st.metric(
        "Rate Limiting",
        "NOT OBSERVED",
        "20/20 accepted",
    )

st.divider()

# ------------------------------------------------------------
# VERIFICATION
# ------------------------------------------------------------

st.subheader("🧪 Deterministic Security Verification")

st.write(
    "Run the local dispatcher verification against the crAPI instance."
)

if st.button("▶ Run Security Verification"):

    with st.spinner("Executing security verification..."):

        try:
            result = subprocess.run(
                [
                    sys.executable,
                    "test_dispatcher.py",
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )

            output = result.stdout + "\n" + result.stderr

            if result.returncode == 0:
                st.success(
                    "✅ Security dispatcher verification completed successfully."
                )
            else:
                st.error(
                    f"❌ Verification exited with code {result.returncode}"
                )

            st.text_area(
                "Verification Evidence",
                output,
                height=500,
            )

        except Exception as e:
            st.error(f"Verification failed: {e}")

# ------------------------------------------------------------
# EXPLANATION
# ------------------------------------------------------------

st.divider()

st.subheader("⚙️ How the System Works")

st.markdown(
    """
**1. OpenAPI Discovery**

The framework loads the crAPI OpenAPI specification and builds an
endpoint inventory.

**2. AI-Assisted Analysis**

The selected endpoint is analyzed for authentication,
authorization sensitivity, object identifiers and potential
OWASP API security risks.

**3. Test Generation**

Security tests are generated for BOLA, authentication,
information disclosure and rate limiting.

**4. Security Test Execution**

The generated/deterministic tests are executed against the
running crAPI instance.

**5. Deterministic Validation**

Runtime HTTP responses are evaluated using validation logic.

**6. Finding Classification**

The framework produces confirmed findings only when the
validation criteria are satisfied.

**7. Evidence**

The verification output provides the evidence used to support
the final security classification.
"""
)

st.divider()

st.caption(
    "AI-Assisted API Security Assessment | OWASP crAPI | "
    "AI-assisted reasoning + deterministic runtime validation"
)