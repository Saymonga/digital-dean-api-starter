from uuid import UUID, uuid4

from app.schemas.student import (
    StudentCreate,
    StudentRead,
    StudentUpdate,
)


class StudentNotFoundError(KeyError):
    """Запис студента не знайдено."""


class DuplicateEmailError(ValueError):
    """Електронна адреса вже використовується."""


class InMemoryStudentRepository:

    def __init__(self) -> None:
        self._students: dict[UUID, StudentRead] = {}

    def create(self, payload: StudentCreate) -> StudentRead:
        for student in self._students.values():
            if student.email == payload.email:
                raise DuplicateEmailError(payload.email)

        student = StudentRead(
            id=uuid4(),
            **payload.model_dump()
        )

        self._students[student.id] = student
        return student

    def list(
        self,
        *,
        enrollment_year: int | None = None
    ) -> list[StudentRead]:

        students = list(self._students.values())

        if enrollment_year is not None:
            students = [
                student
                for student in students
                if student.enrollment_year == enrollment_year
            ]

        return students

    def get(self, student_id: UUID) -> StudentRead:
        student = self._students.get(student_id)

        if student is None:
            raise StudentNotFoundError(student_id)

        return student

    def update(
        self,
        student_id: UUID,
        payload: StudentUpdate
    ) -> StudentRead:

        student = self.get(student_id)

        update_data = payload.model_dump(exclude_unset=True)

        if not update_data:
            return student

        new_email = update_data.get("email")

        if new_email is not None:
            for existing in self._students.values():
                if (
                    existing.id != student_id
                    and existing.email == new_email
                ):
                    raise DuplicateEmailError(new_email)

        updated_student = student.model_copy(
            update=update_data
        )

        self._students[student_id] = updated_student

        return updated_student

    def clear(self) -> None:
        self._students.clear()


student_repository = InMemoryStudentRepository()