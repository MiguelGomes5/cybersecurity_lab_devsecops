import dataclasses
import pathlib
import typing

import flask
import werkzeug.exceptions

app = flask.Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-key" #Isto deveria estar num env, e não hard coded

# -----------------------------------------------------------------------------
# Intentionally small in-memory "database"
# -----------------------------------------------------------------------------

BASE_DIR = pathlib.Path(__file__).resolve().parent
MATERIALS_DIR = BASE_DIR / "materials"
MATERIALS_DIR.mkdir(exist_ok=True)

# Seed a couple of demo files.
(MATERIALS_DIR / "srs-summary.txt").write_text(
    "Secure Requirements Engineering summary", encoding="utf-8"
)
(MATERIALS_DIR / "secure-coding.txt").write_text(
    "Secure coding practices notes", encoding="utf-8"
)


@dataclasses.dataclass
class User:
    username: str
    password: str
    role: str
    student_id: typing.Optional[int] = None
    courses: typing.Optional[list[str]] = None


# Passwords guardadas em texto simples (deviam estar em hash)
USERS = {
    "alice": User(username="alice", password="alicepw", role="student", student_id=1001),
    "bob": User(username="bob", password="bobpw", role="student", student_id=1002),
    "prof_srs": User(
        username="prof_srs", password="profpw", role="professor", courses=["SRS"]
    ),
    "admin1": User(username="admin1", password="adminpw", role="admin"),
}

STUDENT_PROFILES = {
    1001: {"student_id": 1001, "name": "Alice", "email": "alice@uc.pt", "program": "MEI"},
    1002: {"student_id": 1002, "name": "Bob", "email": "bob@uc.pt", "program": "MEI"},
}

GRADES = [
    {"student_id": 1001, "course_id": "SRS", "grade": 14},
    {"student_id": 1002, "course_id": "SRS", "grade": 15},
    {"student_id": 1001, "course_id": "SSD", "grade": 16},
]

def find_grade(student_id, course_id):
    for row in GRADES:
        if row["student_id"] == student_id and row["course_id"] == course_id:
            return row
    return None


def current_user():
    """Return the server-side User record for the session, or None.

    Role and courses are read from USERS, not from the session copy, so
    authorization always reflects the current account state.
    """
    username = flask.session.get("user")
    if username is None:
        return None
    return USERS.get(username)


def can_update_grade(user, course_id):
    """R3: admins may update any grade; professors only their own courses."""
    if user.role == "admin":
        return True
    if user.role == "professor":
        return course_id in (user.courses or [])
    return False


# -----------------------------------------------------------------------------
# REST API Endpoints
# -----------------------------------------------------------------------------

@app.get("/")
def index():
    return {
        "message": "Baseline Secure Coding API",
        "endpoints": [
            "POST /login",
            "POST /logout",
            "GET /me",
            "GET /students/<student_id>/profile",
            "POST /grades/update",
            "GET /grades/<student_id>",
            "GET /files?path=<name>",
        ],
    }

# Comparação de password em texto simples e não em tempo constante, sem rate limiting (brute force),
# e a sessão não é renovada após login (session fixation) nem há proteção CSRF no form
@app.post("/login")
def login():
    username = flask.request.form.get("username", "")
    password = flask.request.form.get("password", "")

    user = USERS.get(username)
    if user is None or user.password != password:
        return {"error": "invalid credentials"}, 401

    flask.session["user"] = user.username
    flask.session["role"] = user.role
    flask.session["student_id"] = user.student_id
    flask.session["courses"] = user.courses or []

    return flask.redirect("/me")

@app.post("/logout")
def logout():
    flask.session.clear()
    return {"status": "logged out"}

@app.get("/me")
def me():
    if "user" not in flask.session:
        return {"user": None}

    return {
        "user": flask.session.get("user"),
        "role": flask.session.get("role"),
        "student_id": flask.session.get("student_id"),
        "courses": flask.session.get("courses"),
    }

# Não faz sentido outros students verem os perfis tas de outros students
# Nem sequer há verificação de login: qualquer pessoa anónima lê nome/email (IDOR).
# int(student_id) sem validação -> "abc" dá ValueError e devolve 500 (devia ser 400; o handler já não mostra detalhes)
@app.get("/students/<student_id>/profile")
def get_profile(student_id):
    profile = STUDENT_PROFILES.get(int(student_id))
    if profile is None:
        return {"error": "student not found"}, 404
    return flask.jsonify(profile)

# Não faz sentido um student ver as grades de outros students
# Também sem login. Um professor só devia ver notas das cadeiras que leciona (filtrar por courses)
@app.get("/grades/<student_id>")
def get_grades(student_id):
    sid = int(student_id)
    rows = [row for row in GRADES if row["student_id"] == sid]
    return flask.jsonify(rows)

# Corrigido (V1): exige login (401) e só admin ou professor do curso podem dar updates (403)
# Ainda sem validação: a nota pode ser -5, 999 ou "abc" (devia ser 0-20) e aceita alunos/cursos que não existem
@app.post("/grades/update")
def update_grade():
    # R1/R7: authenticate before touching the request body or GRADES.
    user = current_user()
    if user is None:
        return {"error": "authentication required"}, 401

    # Students (and any unknown role) can never update grades.
    if user.role not in ("admin", "professor"):
        return {"error": "forbidden"}, 403

    data = flask.request.get_json()

    student_id = data["student_id"]
    course_id = data["course_id"]
    grade = data["grade"]

    # R3/R4: per-record check against the target course, before any write
    # (covers both the update and the append branch below).
    if not can_update_grade(user, course_id):
        return {"error": "forbidden"}, 403

    row = find_grade(student_id, course_id)
    if row is None:
        GRADES.append({"student_id": student_id, "course_id": course_id, "grade": grade})
    else:
        row["grade"] = grade

    return {"status": "ok", "student_id": student_id, "course_id": course_id, "grade": grade}

# Corrigido (V2): exige login (401) e faz resolve() + is_relative_to() para bloquear path traversal
# ("../" ou caminhos absolutos); ficheiros fora de MATERIALS_DIR ou inexistentes dão 404
@app.get("/files")
def download_file():
    # R1/R7: authenticate before touching the filesystem.
    if current_user() is None:
        return {"error": "authentication required"}, 401

    raw_path = flask.request.args.get("path", "")

    # R6: resolve against the module-level MATERIALS_DIR at request time and
    # require the canonical target to stay inside it. resolve() collapses
    # "../" and follows symlinks; an absolute raw_path resolves to itself and
    # fails the containment check. Every rejection is the same 404 so the
    # response does not reveal whether a file exists outside the directory.
    base = pathlib.Path(MATERIALS_DIR).resolve()
    try:
        target = (base / raw_path).resolve()
    except (OSError, ValueError):  # e.g. embedded NUL byte
        return {"error": "file not found"}, 404

    if not target.is_relative_to(base) or not target.is_file():
        return {"error": "file not found"}, 404

    return flask.send_file(target)

@app.errorhandler(Exception)
def handle_error(exc):
    # R7: keep HTTP errors (404, 405, 415...) as client errors, and never send
    # exception text, types or paths to the client. Details go to the log.
    if isinstance(exc, werkzeug.exceptions.HTTPException):
        return {"error": exc.name}, exc.code
    app.logger.exception("Unhandled exception")
    return {"error": "internal server error"}, 500

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)