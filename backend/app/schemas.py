import datetime as dt
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class SignupRequest(BaseModel):
    email: EmailStr
    password: str = Field(max_length=1024)
    organization_name: str = Field(min_length=1, max_length=200)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(max_length=1024)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    organization_id: str
    user_id: str


class SignupResponse(TokenResponse):
    verification_email_sent: bool = False


class InviteRequest(BaseModel):
    email: EmailStr
    role: str = Field(default="member", pattern="^(member|admin)$")


class InviteTokenRequest(BaseModel):
    token: str = Field(min_length=20, max_length=100)


class InviteAcceptRequest(BaseModel):
    token: str = Field(min_length=20, max_length=100)
    password: str = Field(max_length=1024)


class SwitchWorkspaceRequest(BaseModel):
    organization_id: str = Field(min_length=3, max_length=100)


class RoleChangeRequest(BaseModel):
    role: str = Field(pattern="^(member|admin)$")


class MfaChallenge(BaseModel):
    mfa_required: bool = True
    mfa_token: str


class Login2FARequest(BaseModel):
    mfa_token: str = Field(min_length=20, max_length=2000)
    code: str = Field(min_length=1, max_length=40)


class TwoFactorPasswordRequest(BaseModel):
    password: str = Field(max_length=1024)


class TwoFactorEnableRequest(BaseModel):
    code: str = Field(min_length=1, max_length=40)


class TwoFactorConfirmRequest(BaseModel):
    password: str = Field(max_length=1024)
    code: str = Field(min_length=1, max_length=40)


class SignupPending(BaseModel):
    """Identical answer for new and already-registered addresses (account-enumeration protection)."""
    check_email: bool = True
    detail: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=20, max_length=100)
    new_password: str = Field(max_length=1024)


class VerifyEmailRequest(BaseModel):
    token: str = Field(min_length=20, max_length=100)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(max_length=1024)
    new_password: str = Field(max_length=1024)


class RepositoryCreate(BaseModel):
    repo_url: str
    repo_name: str | None = None
    provider: str = "github"


class RepositoryOut(BaseModel):
    id: str
    repo_name: str
    repo_url: str
    provider: str
    last_scanned_at: dt.datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class ScanOut(BaseModel):
    id: str
    repository_id: str
    status: str
    started_at: dt.datetime
    finished_at: dt.datetime | None = None
    score: int | None = None
    error: str | None = None
    coverage: dict | None = None

    model_config = ConfigDict(from_attributes=True)

    @field_validator("coverage", mode="before")
    @classmethod
    def _parse_coverage(cls, value):
        if isinstance(value, str):
            import json
            try:
                parsed = json.loads(value)
            except ValueError:
                return None
            return parsed if isinstance(parsed, dict) else None
        return value


class FindingOut(BaseModel):
    id: str
    scan_id: str
    severity: str
    category: str
    finding_domain: str
    title: str
    description: str | None = None
    evidence: list | None = None
    recommendation: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    confidence: float | None = None
    ai_provider: str | None = None
    capability: str | None = None
    ai_controlled: bool | None = None
    control_confidence: float | None = None
    consequence: str | None = None
    impact_level: str | None = None
    control_status: str | None = None
    capability_chain: list | None = None
    scored: bool = True
    potential_points: int | None = None
    snippet: str | None = None
    status: str

    model_config = ConfigDict(from_attributes=True)


class FindingUpdate(BaseModel):
    status: str  # open | resolved | ignored


class ScoreOut(BaseModel):
    score: int
    label: str
    counts: dict
    unscored_count: int = 0
    tier_deductions: dict = {}

class DomainScoresOut(BaseModel):
    overall: ScoreOut
    ai_safety: ScoreOut
    project_security: ScoreOut


class DataDeletionRequest(BaseModel):
    confirmation: str
