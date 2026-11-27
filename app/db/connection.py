"""Provided connection and explicit-transaction infrastructure, Python 3.12+."""
from contextlib import contextmanager
from pathlib import Path
import sqlite3


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DB_PATH = PROJECT_ROOT / "var" / "digital-dean.sqlite3"
MIN_SQLITE_VERSION = (3, 24, 0)


@contextmanager
def open_database(path: Path):
    """Create/use the connection in one thread; always close it afterwards."""
    if sqlite3.sqlite_version_info < MIN_SQLITE_VERSION:
        raise sqlite3.DatabaseError("SQLite 3.24.0 or newer required")
    connection = sqlite3.connect(path, timeout=5.0, autocommit=True)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        flag = connection.execute("PRAGMA foreign_keys").fetchone()
        if flag is None or flag[0] != 1:
            raise sqlite3.DatabaseError("foreign key enforcement required")
        yield connection
    finally:
        connection.close()


@contextmanager
def write_transaction(connection: sqlite3.Connection):
    """Use SQL COMMIT/ROLLBACK: connection autocommit is deliberately True."""
    if connection.in_transaction:
        raise RuntimeError("nested transaction not supported")
    connection.execute("BEGIN IMMEDIATE")
    try:
        yield connection
        connection.execute("COMMIT")
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
