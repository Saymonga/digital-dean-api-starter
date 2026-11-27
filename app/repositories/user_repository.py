
"""SQLite repository for user accounts."""
import sqlite3
from pathlib import Path

from app.db.connection import DB_PATH, open_database, write_transaction
from app.schemas.user_account import UserCreate, UserPublic
from app.security.passwords import make_password_record, verify_password


class UserConflict(Exception):
    """Login or email already exists."""


class UserNotFound(Exception):
    """User does not exist."""


class UserReferenced(Exception):
    """User is referenced by a grade and cannot be deleted."""


class UserRepository:
    def __init__(self, database_path: Path = DB_PATH):
        self.database_path = Path(database_path)

    @staticmethod
    def _public(row: sqlite3.Row) -> UserPublic:
        return UserPublic(
            id=row["id"],
            name=row["name"],
            email=row["email"],
            login=row["login"],
            status_id=row["status_id"],
        )

    def register_user(self, data: UserCreate) -> UserPublic:
        password = data.password.get_secret_value()
        password_record, salt = make_password_record(password)

        try:
            with open_database(self.database_path) as con:
                with write_transaction(con):
                    cursor = con.execute(
                        """
                        INSERT INTO "user"
                            (name, email, login, password, salt, status_id)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            data.name,
                            str(data.email).casefold(),
                            data.login,
                            password_record,
                            salt,
                            data.status_id,
                        ),
                    )
                    row = con.execute(
                        """
                        SELECT id, name, email, login, status_id
                        FROM "user" WHERE id = ?
                        """,
                        (cursor.lastrowid,),
                    ).fetchone()
                    return self._public(row)
        except sqlite3.IntegrityError as exc:
            if "unique" in str(exc).lower():
                raise UserConflict("Login or email already exists") from exc
            raise

    def get_user(self, user_id: int) -> UserPublic | None:
        with open_database(self.database_path) as con:
            row = con.execute(
                """
                SELECT id, name, email, login, status_id
                FROM "user" WHERE id = ?
                """,
                (user_id,),
            ).fetchone()
            return self._public(row) if row else None

    def get_credentials(self, login: str):
        with open_database(self.database_path) as con:
            return con.execute(
                """
                SELECT id, login, password, salt, status_id
                FROM "user" WHERE login = ?
                """,
                (login,),
            ).fetchone()

    def login(self, login: str, password: str) -> bool:
        row = self.get_credentials(login)
        if row is None or row["status_id"] != 1:
            return False
        return verify_password(password, row["password"], row["salt"])

    def authenticate(self, login: str, password: str) -> bool:
        return self.login(login, password)

    def block_user(self, user_id: int) -> UserPublic:
        with open_database(self.database_path) as con:
            with write_transaction(con):
                con.execute(
                    'UPDATE "user" SET status_id = 2 WHERE id = ?',
                    (user_id,),
                )
                row = con.execute(
                    """
                    SELECT id, name, email, login, status_id
                    FROM "user" WHERE id = ?
                    """,
                    (user_id,),
                ).fetchone()
                if row is None:
                    raise UserNotFound("User not found")
                return self._public(row)

    def delete_user(self, user_id: int) -> None:
        try:
            with open_database(self.database_path) as con:
                with write_transaction(con):
                    cursor = con.execute(
                        'DELETE FROM "user" WHERE id = ?',
                        (user_id,),
                    )
                    if cursor.rowcount == 0:
                        raise UserNotFound("User not found")
        except sqlite3.IntegrityError as exc:
            if "foreign key" in str(exc).lower():
                raise UserReferenced("User is referenced") from exc
            raise
