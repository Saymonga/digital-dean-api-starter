from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, status

from app.schemas.student import (
    StudentCreate,
    StudentRead,
    StudentUpdate,
)
from app.repositories.student_repository import (
    student_repository,
    StudentNotFoundError,
    DuplicateEmailError,
)


router = APIRouter(
    prefix="/api/v1/students",
    tags=["students"]
)


@router.post(
    "",
    response_model=StudentRead,
    status_code=status.HTTP_201_CREATED
)
def create_student(payload: StudentCreate):
    try:
        return student_repository.create(payload)
    except DuplicateEmailError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already exists"
        )


@router.get(
    "",
    response_model=list[StudentRead]
)
def list_students(
    enrollment_year: int | None = Query(
        default=None,
        ge=2000,
        le=2100
    )
):
    return student_repository.list(
        enrollment_year=enrollment_year
    )


@router.get(
    "/{student_id}",
    response_model=StudentRead
)
def get_student(student_id: UUID):
    try:
        return student_repository.get(student_id)
    except StudentNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Student not found"
        )


@router.patch(
    "/{student_id}",
    response_model=StudentRead
)
def update_student(
    student_id: UUID,
    payload: StudentUpdate
):
    try:
        return student_repository.update(
            student_id,
            payload
        )
    except StudentNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Student not found"
        )
    except DuplicateEmailError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already exists"
        )