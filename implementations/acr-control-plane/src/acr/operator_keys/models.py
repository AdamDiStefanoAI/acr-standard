from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, model_validator


class OperatorKeyCreateRequest(BaseModel):
    name: str
    subject: str
    roles: list[str] = Field(default_factory=list)


class AuditorGrantCreateRequest(BaseModel):
    """Issue a time-boxed, read-only auditor grant.

    Exactly one of `expires_at` / `lifetime_hours` must be supplied: a
    grant without a stated end is a standing credential, which is what
    this type exists to prevent. The service additionally caps the
    resulting lifetime at the deployment's configured maximum.
    """

    name: str
    subject: str
    expires_at: datetime | None = None
    lifetime_hours: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def _exactly_one_expiry_form(self) -> AuditorGrantCreateRequest:
        if (self.expires_at is None) == (self.lifetime_hours is None):
            raise ValueError("supply exactly one of expires_at or lifetime_hours")
        return self


class OperatorKeyRotateRequest(BaseModel):
    reason: str | None = None


class OperatorKeyResponse(BaseModel):
    key_id: str
    name: str
    subject: str
    roles: list[str]
    is_active: bool
    created_by: str | None
    revoked_by: str | None
    revoked_at: datetime | None
    expires_at: datetime | None = None
    last_used_at: datetime | None
    created_at: datetime | None

    model_config = {"from_attributes": True}


class OperatorKeyCreateResponse(OperatorKeyResponse):
    api_key: str
