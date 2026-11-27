"""Student task: atomic, repeatable schema creation and lookup initialization."""
from pathlib import Path

from app.db.connection import DB_PATH, open_database, write_transaction
from app.db.schema import DDL_STATEMENTS, ROLE_ROWS, STATUS_ROWS


def initialize_database(path: Path = DB_PATH) -> None:
    """Create parent directory and all tables; preserve users on repeat runs.

    TODO: run each DDL statement and parameterized seed insert inside one
    write_transaction. Never use INSERT OR REPLACE. Verify the exact fixed
    lookup rows; reject a mismatch instead of overwriting it. Do not use
    executescript for this transaction. No DROP or DELETE of user data.
    """
    raise NotImplementedError("TODO: initialize the six-table database")


if __name__ == "__main__":
    initialize_database()
    print("Database initialized; no default accounts created.")
