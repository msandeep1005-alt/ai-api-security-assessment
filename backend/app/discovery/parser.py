import json
from pathlib import Path
from typing import Any


HTTP_METHODS = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "options",
    "head",
    "trace",
}


def load_openapi_spec(spec_path: str | Path) -> dict[str, Any]:
    """
    Load and validate an OpenAPI JSON specification.
    """
    path = Path(spec_path)

    if not path.exists():
        raise FileNotFoundError(f"OpenAPI specification not found: {path}")

    with path.open("r", encoding="utf-8") as file:
        specification = json.load(file)

    if not isinstance(specification, dict):
        raise ValueError("OpenAPI specification must be a JSON object.")

    if "openapi" not in specification and "swagger" not in specification:
        raise ValueError(
            "The supplied document does not appear to be an OpenAPI/Swagger specification."
        )

    if "paths" not in specification:
        raise ValueError("OpenAPI specification does not contain a 'paths' section.")

    return specification


def discover_endpoints(specification: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Convert OpenAPI paths and operations into a normalized endpoint inventory.
    """
    endpoints = []

    for path, path_item in specification.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue

        path_level_parameters = path_item.get("parameters", [])

        for method, operation in path_item.items():
            method_lower = method.lower()

            if method_lower not in HTTP_METHODS:
                continue

            if not isinstance(operation, dict):
                continue

            parameters = []

            for parameter in path_level_parameters:
                if isinstance(parameter, dict):
                    parameters.append(parameter)

            for parameter in operation.get("parameters", []):
                if isinstance(parameter, dict):
                    parameters.append(parameter)

            security = operation.get(
                "security",
                specification.get("security", [])
            )

            endpoints.append(
                {
                    "method": method.upper(),
                    "path": path,
                    "operation_id": operation.get("operationId"),
                    "summary": operation.get("summary"),
                    "description": operation.get("description"),
                    "tags": operation.get("tags", []),
                    "security": security,
                    "parameters": parameters,
                    "request_body": operation.get("requestBody"),
                    "responses": operation.get("responses", {}),
                }
            )

    return endpoints


def load_and_discover(spec_path: str | Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """
    Load an OpenAPI specification and return both the specification
    and normalized endpoint inventory.
    """
    specification = load_openapi_spec(spec_path)
    endpoints = discover_endpoints(specification)

    return specification, endpoints


def print_inventory(spec_path: str | Path) -> None:
    """
    CLI-friendly endpoint inventory output.
    """
    specification, endpoints = load_and_discover(spec_path)

    print("[+] OpenAPI specification loaded")
    print(f"[+] OpenAPI version: {specification.get('openapi', specification.get('swagger'))}")
    print(f"[+] API title: {specification.get('info', {}).get('title', 'Unknown')}")
    print(f"[+] Paths discovered: {len(specification.get('paths', {}))}")
    print(f"[+] Operations discovered: {len(endpoints)}")
    print()

    for index, endpoint in enumerate(endpoints, start=1):
        auth = "AUTH" if endpoint["security"] else "PUBLIC"

        print(
            f"[{index:02d}] "
            f"{endpoint['method']:<7} "
            f"{endpoint['path']:<65} "
            f"{auth}"
        )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Parse an OpenAPI specification and discover API endpoints."
    )

    parser.add_argument(
        "--spec",
        required=True,
        help="Path to the OpenAPI JSON specification.",
    )

    args = parser.parse_args()

    print_inventory(args.spec)
