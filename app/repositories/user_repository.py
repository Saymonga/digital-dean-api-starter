"""Student task: persistent account operations on separate short connections."""
from pathlib import Path

from app.db.connection import open_database, write_transaction
from app.schemas.user_account import UserCreate, UserPublic
from app.security.passwords import make_password_record, verify_password


class UserNotFound(Exception):
    """No account with the requested id."""


class UserConflict(Exception):
    """The canonical login or email is already used."""


class UserReferenced(Exception):
    """Academic records prohibit physical deletion."""


class UserRepository:
    def __init__(self, database_path: Path):
        self.database_path = Path(database_path)

    def register_user(self, data: UserCreate) -> UserPublic:
        """TODO: hash, parameterized INSERT, transaction, safe output.

        Do not assign privileged roles or accept client id/hash/salt fields.
        Return only id, name, email, login, status_id. Map UNIQUE conflicts to
        UserConflict; preserve the database on failure. No shared connection.
        """
        raise NotImplementedError("TODO: register a persistent user")

    def delete_user(self, user_id: int) -> None:
        """TODO: DELETE in one transaction; missing -> UserNotFound.

        A grade reference to this user as student OR teacher -> UserReferenced.
        Check user existence and grade references inside the SAME write
        transaction as DELETE; retain FK enforcement as the database backstop.
        Roll back the whole transaction, including any role cascades. Never
        manually delete grades to make the account DELETE succeed.
        """
        raise NotImplementedError("TODO: delete an unreferenced user")

    def block_user(self, user_id: int) -> UserPublic:
        """TODO: set status_id=2, preserve other fields; repeat is safe."""
        raise NotImplementedError("TODO: persist the blocked status")

    def login(self, login: str, password: str) -> bool:
        """TODO: parameterized lookup, verify password AND status_id == 1.

        Unknown login, wrong password, malformed stored record, inactive or
        blocked user -> False. Do not return the row, account id or secrets.
        No session or access token is issued by this educational operation.
        """
        raise NotImplementedError("TODO: check credentials and active status")
