from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, EmailStr


class StrictModel(BaseModel):
    """Базова модель, яка не приймає невідомих полів."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True
    )


class StudentCreate(StrictModel):
    full_name: str = Field(min_length=3, max_length=100)
    email: EmailStr
    group_code: str = Field(min_length=2, max_length=20)
    enrollment_year: int = Field(ge=2000, le=2100)


class StudentRead(StudentCreate):
    id: UUID


class StudentUpdate(StrictModel):
    full_name: str | None = Field(
        default=None, min_length=3, max_length=100
    )
    email: EmailStr | None = None
    group_code: str | None = Field(
        default=None, min_length=2, max_length=20
    )
    enrollment_year: int | None = Field(
        default=None, ge=2000, le=2100
    )