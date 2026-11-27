"""The six agreed tables and immutable lookup seeds; no user data."""

STATUS_ROWS = ((0, "inactive"), (1, "active"), (2, "blocked"))
ROLE_ROWS = ((1, "admin"), (2, "manager"), (3, "teacher"), (4, "student"))

DDL_STATEMENTS = (
    """CREATE TABLE IF NOT EXISTS status (
        id INTEGER PRIMARY KEY CHECK (id IN (0, 1, 2)),
        name TEXT NOT NULL UNIQUE
    )""",
    """CREATE TABLE IF NOT EXISTS "user" (
        id INTEGER PRIMARY KEY CHECK (id > 0),
        name TEXT NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 120),
        email TEXT NOT NULL UNIQUE,
        login TEXT NOT NULL UNIQUE CHECK (
            length(login) BETWEEN 3 AND 32
            AND substr(login, 1, 1) GLOB '[a-z]'
            AND login NOT GLOB '*[^a-z0-9_.-]*'),
        password TEXT NOT NULL,
        salt TEXT NOT NULL,
        status_id INTEGER NOT NULL DEFAULT 0 CHECK (status_id IN (0, 1, 2)),
        FOREIGN KEY (status_id) REFERENCES status(id) ON DELETE RESTRICT
    )""",
    """CREATE TABLE IF NOT EXISTS role (
        id INTEGER PRIMARY KEY CHECK (id > 0),
        name TEXT NOT NULL UNIQUE
    )""",
    """CREATE TABLE IF NOT EXISTS user_role (
        user_id INTEGER NOT NULL,
        role_id INTEGER NOT NULL,
        PRIMARY KEY (user_id, role_id),
        FOREIGN KEY (user_id) REFERENCES "user"(id) ON DELETE CASCADE,
        FOREIGN KEY (role_id) REFERENCES role(id) ON DELETE RESTRICT
    )""",
    """CREATE TABLE IF NOT EXISTS course (
        id INTEGER PRIMARY KEY CHECK (id > 0),
        name TEXT NOT NULL CHECK (length(trim(name)) > 0)
    )""",
    """CREATE TABLE IF NOT EXISTS grade (
        student_id INTEGER NOT NULL,
        teacher_id INTEGER NOT NULL,
        course_id INTEGER NOT NULL,
        grade INTEGER NOT NULL CHECK (
            typeof(grade) = 'integer' AND grade BETWEEN 0 AND 100),
        PRIMARY KEY (student_id, course_id),
        FOREIGN KEY (student_id) REFERENCES "user"(id) ON DELETE RESTRICT,
        FOREIGN KEY (teacher_id) REFERENCES "user"(id) ON DELETE RESTRICT,
        FOREIGN KEY (course_id) REFERENCES course(id) ON DELETE RESTRICT
    )""",
    "CREATE INDEX IF NOT EXISTS ix_grade_teacher ON grade(teacher_id)",
    "CREATE INDEX IF NOT EXISTS ix_grade_course ON grade(course_id)",
)
