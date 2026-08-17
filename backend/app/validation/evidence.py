from datetime import datetime, timezone
from pathlib import Path
import json


def save_execution_evidence(
    test_id: str,
    request: dict,
    response: dict,
    validation: dict,
) -> Path:

    evidence_dir = Path("evidence")
    evidence_dir.mkdir(exist_ok=True)

    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%dT%H%M%SZ")

    output = {
        "test_id": test_id,
        "timestamp": timestamp,
        "request": request,
        "response": response,
        "validation": validation,
    }

    path = evidence_dir / f"{test_id}_{timestamp}.json"

    path.write_text(
        json.dumps(
            output,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    return path
