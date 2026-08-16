from pydantic import BaseModel, Field


class SecurityAnalysis(BaseModel):
    security_sensitive: bool = False

    authentication_required: bool = False

    authorization_sensitive: bool = False

    object_identifier: str | None = None

    potential_vulnerabilities: list[str] = Field(
        default_factory=list
    )

    recommended_tests: list[str] = Field(
        default_factory=list
    )

    reasoning: str = ""

    confidence: float = 0.0
