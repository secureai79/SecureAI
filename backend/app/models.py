import uuid
import datetime as dt

from sqlalchemy import (
    Column, String, DateTime, ForeignKey, Integer, Float, Text, JSON, Boolean, UniqueConstraint
)
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()


def gen_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class Organization(Base):
    __tablename__ = "organizations"
    id = Column(String, primary_key=True, default=lambda: gen_id("org"))
    name = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.UTC))
    # Scan/size limits scale with the plan (see app/limits.py). Everyone is on "pilot" until billing exists.
    plan = Column(String, nullable=True, default="pilot")

    users = relationship("User", back_populates="organization", cascade="all, delete-orphan")
    repositories = relationship("Repository", back_populates="organization", cascade="all, delete-orphan")
    integrations = relationship("Integration", back_populates="organization", cascade="all, delete-orphan")
    oauth_states = relationship("OAuthState", back_populates="organization", cascade="all, delete-orphan")
    invitations = relationship("Invitation", back_populates="organization", cascade="all, delete-orphan")
    memberships = relationship("Membership", back_populates="organization", cascade="all, delete-orphan")


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=lambda: gen_id("user"))
    organization_id = Column(String, ForeignKey("organizations.id"))
    email = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="owner")
    created_at = Column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.UTC))
    token_version = Column(Integer, nullable=False, default=0)
    failed_login_count = Column(Integer, nullable=False, default=0)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    email_verified_at = Column(DateTime(timezone=True), nullable=True)
    # Two-factor authentication (TOTP). The seed is encrypted; enabled_at stays NULL while setup is pending.
    totp_secret_enc = Column(Text, nullable=True)
    totp_enabled_at = Column(DateTime(timezone=True), nullable=True)
    totp_last_step = Column(Integer, nullable=True, default=0)

    organization = relationship("Organization", back_populates="users")
    email_tokens = relationship("EmailToken", back_populates="user", cascade="all, delete-orphan")
    recovery_codes = relationship("MfaRecoveryCode", back_populates="user", cascade="all, delete-orphan")
    memberships = relationship("Membership", back_populates="user", cascade="all, delete-orphan")

    @property
    def mfa_enabled(self) -> bool:
        return self.totp_enabled_at is not None and bool(self.totp_secret_enc)

    @property
    def email_verified(self) -> bool:
        return self.email_verified_at is not None


class EmailToken(Base):
    """One-time, expiring tokens for e-mail verification and password reset.

    Only a SHA-256 digest is stored, so a database leak cannot be used to take over accounts.
    """
    __tablename__ = "email_tokens"
    id = Column(String, primary_key=True, default=lambda: gen_id("etok"))
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    purpose = Column(String, nullable=False, index=True)  # verify_email | reset_password
    token_hash = Column(String, unique=True, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.UTC), index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)

    user = relationship("User", back_populates="email_tokens")


class Membership(Base):
    """Which workspaces a user belongs to, and their role in each.

    ``User.organization_id`` / ``User.role`` remain the *active* workspace (the one every request is scoped
    to); switching workspaces copies the chosen membership into them.
    """
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("user_id", "organization_id", name="uq_membership_user_org"),)
    id = Column(String, primary_key=True, default=lambda: gen_id("mem"))
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=False, index=True)
    role = Column(String, nullable=False, default="member")        # owner | admin | member
    created_at = Column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.UTC))

    user = relationship("User", back_populates="memberships")
    organization = relationship("Organization", back_populates="memberships")


class Invitation(Base):
    """An invitation to join an organisation. Only a SHA-256 digest of the e-mailed token is stored."""
    __tablename__ = "invitations"
    id = Column(String, primary_key=True, default=lambda: gen_id("inv"))
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=False, index=True)
    email = Column(String, nullable=False, index=True)
    role = Column(String, nullable=False, default="member")        # member | admin
    token_hash = Column(String, unique=True, nullable=False, index=True)
    invited_by = Column(String, nullable=True)                      # user id (no FK: survives removal of the inviter)
    created_at = Column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.UTC), index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    accepted_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)

    organization = relationship("Organization", back_populates="invitations")


class MfaRecoveryCode(Base):
    """Single-use backup codes for two-factor sign-in (only a SHA-256 digest is stored)."""
    __tablename__ = "mfa_recovery_codes"
    id = Column(String, primary_key=True, default=lambda: gen_id("rc"))
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    code_hash = Column(String, unique=True, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.UTC))
    used_at = Column(DateTime(timezone=True), nullable=True)

    user = relationship("User", back_populates="recovery_codes")


class Repository(Base):
    __tablename__ = "repositories"
    id = Column(String, primary_key=True, default=lambda: gen_id("repo"))
    organization_id = Column(String, ForeignKey("organizations.id"))
    provider = Column(String, default="github")
    repo_name = Column(String, nullable=False)
    repo_url = Column(String, nullable=False)
    last_scanned_at = Column(DateTime(timezone=True), nullable=True)

    organization = relationship("Organization", back_populates="repositories")
    scans = relationship("Scan", back_populates="repository", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"
    id = Column(String, primary_key=True, default=lambda: gen_id("scan"))
    repository_id = Column(String, ForeignKey("repositories.id"))
    status = Column(String, default="processing")  # queued | processing | completed | failed
    started_at = Column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.UTC))
    finished_at = Column(DateTime(timezone=True), nullable=True)
    score = Column(Integer, nullable=True)
    error = Column(Text, nullable=True)
    # JSON, set only when the scan did not cover the whole repository (size/time limits). NULL = complete.
    coverage = Column(Text, nullable=True)

    repository = relationship("Repository", back_populates="scans")
    agents = relationship("Agent", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class Agent(Base):
    __tablename__ = "agents"
    id = Column(String, primary_key=True, default=lambda: gen_id("agent"))
    scan_id = Column(String, ForeignKey("scans.id"))
    repository_id = Column(String, ForeignKey("repositories.id"))
    name = Column(String)
    framework = Column(String)
    model_provider = Column(String)
    file_path = Column(String)

    scan = relationship("Scan", back_populates="agents")
    capabilities = relationship("Capability", back_populates="agent", cascade="all, delete-orphan")


class Capability(Base):
    __tablename__ = "capabilities"
    id = Column(String, primary_key=True, default=lambda: gen_id("cap"))
    agent_id = Column(String, ForeignKey("agents.id"))
    category = Column(String)      # financial | data | communication | infrastructure | code
    provider = Column(String)      # stripe, boto3, subprocess, etc.
    operation = Column(String)     # refund, delete, send_email, execute...
    ai_controlled = Column(Boolean, nullable=True)   # None = unknown (regex fallback path)
    control_confidence = Column(Float, nullable=True)
    capability_chain = Column(JSON, nullable=True)   # ordered list of node labels, e.g.
                                                      # ["SupportAgent","OpenAI","AI-generated decision","refund_customer()","Stripe","REFUND"]
    file_path = Column(String)
    line_number = Column(Integer)
    evidence = Column(JSON, nullable=True)

    agent = relationship("Agent", back_populates="capabilities")


class Finding(Base):
    __tablename__ = "findings"
    id = Column(String, primary_key=True, default=lambda: gen_id("find"))
    scan_id = Column(String, ForeignKey("scans.id"))
    severity = Column(String)   # CRITICAL | HIGH | MEDIUM | LOW
    category = Column(String)   # FINANCIAL | DATA | COMMUNICATION | INFRASTRUCTURE | CODE
    finding_domain = Column(
    String,
    nullable=False,
    default="PROJECT_SECURITY",
)
    title = Column(String)
    description = Column(Text)
    evidence = Column(JSON)
    recommendation = Column(Text)
    file_path = Column(String)
    line_number = Column(Integer)
    confidence = Column(Float)
    ai_provider = Column(String, nullable=True)
    capability = Column(String, nullable=True)
    ai_controlled = Column(Boolean, nullable=True)
    control_confidence = Column(Float, nullable=True)
    consequence = Column(String, nullable=True)
    impact_level = Column(String, nullable=True)
    control_status = Column(String, nullable=True)
    capability_chain = Column(JSON, nullable=True)
    function_name = Column(String, nullable=True)
    call_chain = Column(String, nullable=True)
    _snippet_ciphertext = Column("snippet", Text, nullable=True)
    @property
    def snippet(self):
        from .source_crypto import decrypt
        return decrypt(self._snippet_ciphertext)

    @snippet.setter
    def snippet(self, value):
        from .source_crypto import encrypt
        self._snippet_ciphertext = encrypt(value)

    scored = Column(Boolean, default=True)  # False = regex-fallback or non-runtime path (test/docs/etc);
                                             # shown as a finding but excluded from the Safety Score
    fingerprint = Column(String, nullable=True, index=True)  # stable id for baseline diffing
    potential_points = Column(Integer, default=0)
    status = Column(String, default="open")  # open | resolved | ignored

    scan = relationship("Scan", back_populates="findings")


class OAuthState(Base):
    __tablename__ = "oauth_states"
    id = Column(String, primary_key=True, default=lambda: gen_id("oauth"))
    state_hash = Column(String, unique=True, nullable=False, index=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    github_account_login = Column(String, nullable=True)

    organization = relationship("Organization", back_populates="oauth_states")
    user = relationship("User")


class Integration(Base):
    __tablename__ = "integrations"
    id = Column(String, primary_key=True, default=lambda: gen_id("integ"))
    organization_id = Column(String, ForeignKey("organizations.id"))
    type = Column(String)
    encrypted_credentials = Column(Text, nullable=True)
    status = Column(String, default="active")

    organization = relationship("Organization", back_populates="integrations")


class AuditEvent(Base):
    """Security audit trail. Deliberately has no foreign keys so the record of an
    organisation's deletion survives the deletion itself."""
    __tablename__ = "audit_events"
    id = Column(String, primary_key=True, default=lambda: gen_id("aud"))
    organization_id = Column(String, nullable=True, index=True)
    user_id = Column(String, nullable=True)
    action = Column(String, nullable=False, index=True)
    detail = Column(JSON, nullable=True)
    ip = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: dt.datetime.now(dt.UTC), index=True)