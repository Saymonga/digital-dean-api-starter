"""Runnable isolated example, not the implementation of the account API."""
import sqlite3


def main() -> None:
    connection = sqlite3.connect(":memory:", autocommit=True)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("BEGIN")
        connection.execute("CREATE TABLE demo_status(id INTEGER PRIMARY KEY, name TEXT)")
        connection.executemany("INSERT INTO demo_status VALUES (?, ?)",
                               [(0, "inactive"), (1, "active"), (2, "blocked")])
        row = connection.execute("SELECT name FROM demo_status WHERE id=?", (2,)).fetchone()
        assert row == ("blocked",)
        connection.execute("COMMIT")
        print("SQLite example passed; no file or real account was created.")
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()


if __name__ == "__main__":
    main()
