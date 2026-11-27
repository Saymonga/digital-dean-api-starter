
"""Atomic, repeatable schema creation and lookup initialization."""
from pathlib import Path

from app.db.connection import DB_PATH, open_database, write_transaction
from app.db.schema import DDL_STATEMENTS, ROLE_ROWS, STATUS_ROWS


def initialize_database(path: Path = DB_PATH) -> None:
    """Create schema and immutable lookup rows without changing user data."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open_database(path) as connection:
        with write_transaction(connection):
            for statement in DDL_STATEMENTS:
                connection.execute(statement)

            connection.executemany(
                """
                INSERT INTO status (id, name) VALUES (?, ?)
                ON CONFLICT(id) DO NOTHING
                """,
                STATUS_ROWS,
            )
            connection.executemany(
                """
                INSERT INTO role (id, name) VALUES (?, ?)
                ON CONFLICT(id) DO NOTHING
                """,
                ROLE_ROWS,
            )

            statuses = tuple(
                tuple(row)
                for row in connection.execute(
                    "SELECT id, name FROM status ORDER BY id"
                ).fetchall()
            )
            roles = tuple(
                tuple(row)
                for row in connection.execute(
                    "SELECT id, name FROM role ORDER BY id"
                ).fetchall()
            )

            if statuses != tuple(sorted(STATUS_ROWS)):
                raise ValueError("Status lookup data does not match required values")

            if roles != tuple(sorted(ROLE_ROWS)):
                raise ValueError("Role lookup data does not match required values")


if __name__ == "__main__":
    initialize_database()
    print("Database initialized; no default accounts created.")
