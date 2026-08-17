from pydantic import BaseModel, Field


class SecurityTest(BaseModel):
    test_id: str
    category: str
    method: str
    path: str
    objective: str
    severity: str = "MEDIUM"
    requires_authentication: bool = False
    requires_multiple_users: bool = False
    test_steps: list[str] = Field(default_factory=list)
    expected_behavior: str = ""
    validation_criteria: list[str] = Field(default_factory=list)


class SecurityTestPlan(BaseModel):
    endpoint: str
    tests: list[SecurityTest] = Field(default_factory=list)
