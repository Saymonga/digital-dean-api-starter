"""Initial acceptance checks; add your own negative and concurrency cases."""
import sqlite3
import pytest

from app.db.connection import open_database, write_transaction
from app.db.initialize import initialize_database
from app.db.schema import ROLE_ROWS, STATUS_ROWS
from app.repositories.user_repository import UserReferenced, UserRepository
from tests.practice05_support import (
    account_database, account_repository, account_data,
)

EXPECTED_COLUMNS = {
    "status": ["id", "name"],
    "user": ["id", "name", "email", "login", "password", "salt", "status_id"],
    "role": ["id", "name"], "user_role": ["user_id", "role_id"],
    "course": ["id", "name"],
    "grade": ["student_id", "teacher_id", "course_id", "grade"],
}


def test_exact_tables_and_seeds(account_database):
    with open_database(account_database) as con:
        names = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert names == set(EXPECTED_COLUMNS)
        for name, columns in EXPECTED_COLUMNS.items():
            # name is from a fixed developer-owned allowlist, not request input.
            assert [r[1] for r in con.execute(f'PRAGMA table_info("{name}")')] == columns
        assert [tuple(r) for r in con.execute("SELECT * FROM status ORDER BY id")] == list(STATUS_ROWS)
        assert [tuple(r) for r in con.execute("SELECT * FROM role ORDER BY id")] == list(ROLE_ROWS)
        assert con.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert con.execute("PRAGMA foreign_key_check").fetchall() == []


def test_repeat_initialization_preserves_user(account_repository, account_database):
    user = account_repository.register_user(account_data())
    initialize_database(account_database)
    with open_database(account_database) as con:
        assert con.execute('SELECT id FROM "user"').fetchone()[0] == user.id
        assert con.execute('SELECT count(*) FROM "user"').fetchone()[0] == 1


def test_new_repository_reads_persisted_credentials(account_repository, account_database):
    account_repository.register_user(account_data(status_id=1))
    other = UserRepository(account_database)
    assert other.login("demo_student", "Learning only 05!") is True


def test_transaction_rolls_back_and_connection_closes(account_database):
    with pytest.raises(RuntimeError):
        with open_database(account_database) as con:
            saved = con
            with write_transaction(con):
                con.execute("INSERT INTO course(id,name) VALUES (?,?)", (1, "Synthetic"))
                raise RuntimeError("synthetic rollback")
    with pytest.raises(sqlite3.ProgrammingError):
        saved.execute("SELECT 1")
    with open_database(account_database) as con:
        assert con.execute("SELECT count(*) FROM course").fetchone()[0] == 0


def test_role_link_cascades_when_user_deleted(account_repository, account_database):
    user = account_repository.register_user(account_data())
    with open_database(account_database) as con, write_transaction(con):
        con.execute("INSERT INTO user_role VALUES (?,?)", (user.id, 4))
    account_repository.delete_user(user.id)
    with open_database(account_database) as con:
        assert con.execute("SELECT count(*) FROM user_role").fetchone()[0] == 0


@pytest.mark.parametrize("referenced_role", ["student", "teacher"])
def test_grade_prevents_delete_and_preserves_roles(
        account_repository, account_database, referenced_role):
    student = account_repository.register_user(account_data("demo_student"))
    teacher = account_repository.register_user(account_data("demo_teacher"))
    target = student if referenced_role == "student" else teacher
    with open_database(account_database) as con, write_transaction(con):
        con.execute("INSERT INTO course VALUES (?,?)", (1, "Synthetic course"))
        con.execute("INSERT INTO user_role VALUES (?,?)", (target.id, 4 if referenced_role == "student" else 3))
        con.execute("INSERT INTO grade VALUES (?,?,?,?)", (student.id, teacher.id, 1, 90))
    with pytest.raises(UserReferenced):
        account_repository.delete_user(target.id)
    with open_database(account_database) as con:
        assert con.execute('SELECT count(*) FROM "user" WHERE id=?', (target.id,)).fetchone()[0] == 1
        assert con.execute("SELECT count(*) FROM grade").fetchone()[0] == 1
        assert con.execute("SELECT count(*) FROM user_role WHERE user_id=?", (target.id,)).fetchone()[0] == 1


def test_grade_limits_key_and_foreign_keys(account_repository, account_database):
    student = account_repository.register_user(account_data("demo_student"))
    teacher = account_repository.register_user(account_data("demo_teacher"))
    with open_database(account_database) as con, write_transaction(con):
        con.execute("INSERT INTO course VALUES (?,?)", (1, "Synthetic course"))
    for value in (-1, 101, None, "not-a-number", 1.5):
        with pytest.raises(sqlite3.IntegrityError):
            with open_database(account_database) as con, write_transaction(con):
                con.execute("INSERT INTO grade VALUES (?,?,?,?)", (student.id, teacher.id, 1, value))
    with pytest.raises(sqlite3.IntegrityError):
        with open_database(account_database) as con, write_transaction(con):
            con.execute("INSERT INTO grade VALUES (?,?,?,?)", (student.id, teacher.id, 9999, 90))
    with open_database(account_database) as con, write_transaction(con):
        con.execute("INSERT INTO grade VALUES (?,?,?,?)", (student.id, teacher.id, 1, 90))
    with pytest.raises(sqlite3.IntegrityError):
        with open_database(account_database) as con, write_transaction(con):
            con.execute("INSERT INTO grade VALUES (?,?,?,?)", (student.id, teacher.id, 1, 91))


def test_lookup_mismatch_is_not_silently_overwritten(account_database):
    with open_database(account_database) as con, write_transaction(con):
        con.execute("UPDATE status SET name=? WHERE id=?", ("wrong", 0))
    with pytest.raises(ValueError):
        initialize_database(account_database)
    with open_database(account_database) as con:
        assert con.execute("SELECT name FROM status WHERE id=0").fetchone()[0] == "wrong"
