"""Provided request/output contracts; no password field in UserPublic."""
from pydantic import (
    BaseModel, ConfigDict, EmailStr, Field, SecretStr, StrictInt, field_validator,
)

from app.security.passwords import password_bytes


class AccountModel(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class UserCreate(AccountModel):
    name: str = Field(min_length=1, max_length=120, strict=True)
    email: EmailStr = Field(max_length=254)
    login: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,31}$", strict=True)
    password: SecretStr
    status_id: StrictInt = Field(default=0, ge=0, le=2)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        value = value.strip()
        if not value or "\x00" in value:
            raise ValueError("name invalid")
        return value

    @field_validator("email")
    @classmethod
    def canonical_email(cls, value: str) -> str:
        # Local lab uniqueness rule, not a universal rule for email addresses.
        return str(value).casefold()

    @field_validator("password")
    @classmethod
    def check_password(cls, value: SecretStr) -> SecretStr:
        password_bytes(value.get_secret_value(), registration=True)
        return value


class LoginRequest(AccountModel):
    login: str = Field(min_length=1, max_length=128, strict=True)
    password: SecretStr

    @field_validator("password")
    @classmethod
    def check_password(cls, value: SecretStr) -> SecretStr:
        password_bytes(value.get_secret_value())
        return value


class UserPublic(AccountModel):
    id: StrictInt = Field(gt=0)
    name: str
    email: str
    login: str
    status_id: StrictInt = Field(ge=0, le=2)
