I’ll write the patch, apply it to a copy of your files, and run the security tests to confirm it.

All four V1 tests pass; the four remaining failures are the separate `/files` finding (V2), which this patch deliberately doesn’t touch. Let me check the extra regression tests I’m going to suggest.

I applied the patch to a copy of your files and ran the tests. All four V1 tests now pass (`test_update_requires_login`, `test_student_cannot_update_grade`, `test_professor_cannot_update_other_course`, `test_admin_can_update_any_course`). The four `/files` tests still fail. That is expected: they cover V2, which is outside this repair.

## Unified diff

```diff
--- a/baseline_secure_coding_api.py
+++ b/baseline_secure_coding_api.py
@@ -61,6 +61,27 @@
     return None
 
 
+def current_user():
+    """Return the server-side User record for the session, or None.
+
+    Role and courses are read from USERS, not from the session copy, so
+    authorization always reflects the current account state.
+    """
+    username = flask.session.get("user")
+    if username is None:
+        return None
+    return USERS.get(username)
+
+
+def can_update_grade(user, course_id):
+    """R3: admins may update any grade; professors only their own courses."""
+    if user.role == "admin":
+        return True
+    if user.role == "professor":
+        return course_id in (user.courses or [])
+    return False
+
+
 # -----------------------------------------------------------------------------
 # REST API Endpoints
 # -----------------------------------------------------------------------------
@@ -139,12 +160,26 @@
 # Não tem autenticação 
 @app.post("/grades/update")
 def update_grade():
+    # R1/R7: authenticate before touching the request body or GRADES.
+    user = current_user()
+    if user is None:
+        return {"error": "authentication required"}, 401
+
+    # Students (and any unknown role) can never update grades.
+    if user.role not in ("admin", "professor"):
+        return {"error": "forbidden"}, 403
+
     data = flask.request.get_json()
 
     student_id = data["student_id"]
     course_id = data["course_id"]
     grade = data["grade"]
 
+    # R3/R4: per-record check against the target course, before any write
+    # (covers both the update and the append branch below).
+    if not can_update_grade(user, course_id):
+        return {"error": "forbidden"}, 403
+
     row = find_grade(student_id, course_id)
     if row is None:
         GRADES.append({"student_id": student_id, "course_id": course_id, "grade": grade})
```

## The control

Every request runs three checks, in order and server-side, before any write to `GRADES`.

1. **Authentication (R1 → 401).** `current_user()` resolves the session’s username against `USERS`. A missing session, or a username that no longer exists, counts as unauthenticated. This check runs before the body is parsed, so an anonymous caller gets nothing beyond the 401.
2. **Role gate (R3 → 403).** Only the `admin` and `professor` roles go further. Students and any unknown role are denied.
3. **Per-record authorization (R3/R4 → 403).** `can_update_grade()` checks the target `course_id` against the professor’s assigned courses. Admins are allowed for any course.

There are two design choices worth reviewing:

- **Role and courses come from the `USERS` record, not from `session["role"]` / `session["courses"]`.** The session copy is a snapshot taken at login. If an account is demoted or loses a course, the old snapshot would still grant access. Reading the record also means that a session holding a role it shouldn’t have (for example, if the hard-coded `SECRET_KEY` leaks) cannot escalate privilege. This is what R4 means by “a role name alone does not establish permission”.
- **One check covers both write paths.** The endpoint has two write branches: updating an existing row and appending a new one. The append branch is just as serious, because it lets a caller create grades in arbitrary courses. Placing the check before `find_grade()` guards both branches.

The response contracts are unchanged: the 200 body is the same, and errors use the same `{"error": ...}` shape as `/login`.

## Affected paths

`POST /grades/update` is the only path that writes grades. Inside it, both the update branch and the append branch needed the control, and both now have it. No other endpoint modifies `GRADES`.

The two helpers are separate functions so they can be reused when the related read-side findings get fixed. Those findings are out of scope here, but they are the same class of problem:

- `GET /grades/<student_id>` has no authentication, students can read other students’ grades, and professors aren’t filtered by course.
- `GET /students/<id>/profile` is an IDOR with no authentication.

## Assumptions and limitations

- **Course membership is exact and case-sensitive.** `"srs"`, `"SRS "` and `["SRS"]` are all denied to `prof_srs`. This is safe, but if clients send other spellings it will reject legitimate calls. Normalizing course IDs belongs to the input-validation work.
- **A professor can update any student in an assigned course.** That includes appending a row for a student who isn’t enrolled, or who doesn’t exist. Enrollment checks and value validation (0–20, types, unknown IDs) were excluded from scope, so they remain open.
- **A malformed body sent by an authorized user still returns 500 with exception details.** This comes from the generic `errorhandler(Exception)` (e.g. `KeyError`, or a 415 being turned into a 500). No data changes in that case, but the response leaks internals. This belongs to R7 error handling and input validation.
- **Out of scope but relevant to how strong this control is:** the hard-coded `SECRET_KEY`, the missing CSRF protection on a cookie-authenticated state-changing POST, the session not being regenerated at login, and plaintext passwords.
- **Admins have no course restriction and there is no audit log of grade changes.** Logging who changed what would be a cheap follow-up.

## Additional regression tests

These are in `test_grade_update_authz.py`, and they reuse `login`/`update` from your test module. All 7 pass on the patched code. Six of them fail on the original code; the seventh is the legitimate-use case, so it passes either way.

| Test | What it pins down |
|---|---|
| `test_professor_can_update_own_course` | Legitimate use case: prof_srs → SRS → 200, stored |
| `test_professor_cannot_create_row_in_other_course` | Append branch is guarded too; GRADES unchanged |
| `test_student_cannot_create_row` | A student can’t append a new row; GRADES unchanged |
| `test_update_denied_after_logout` | Logout really revokes access → 401 |
| `test_forged_session_role_is_ignored` | A session claiming role=admin doesn’t grant access (server-side lookup) |
| `test_unknown_session_user_is_unauthenticated` | A session for a nonexistent user → 401 |
| `test_course_id_case_variant_denied` | `"srs"`, `"SRS "`, `["SRS"]` can’t bypass the course check |

The forged-session tests use Flask’s `session_transaction()` to simulate a tampered or stale session. This is the regression that would catch someone later “simplifying” the fix to read `flask.session["role"]`.

## Patch (File provided by the LLM)

```diff
--- a/baseline_secure_coding_api.py
+++ b/baseline_secure_coding_api.py
@@ -61,6 +61,27 @@
     return None
 
 
+def current_user():
+    """Return the server-side User record for the session, or None.
+
+    Role and courses are read from USERS, not from the session copy, so
+    authorization always reflects the current account state.
+    """
+    username = flask.session.get("user")
+    if username is None:
+        return None
+    return USERS.get(username)
+
+
+def can_update_grade(user, course_id):
+    """R3: admins may update any grade; professors only their own courses."""
+    if user.role == "admin":
+        return True
+    if user.role == "professor":
+        return course_id in (user.courses or [])
+    return False
+
+
 # -----------------------------------------------------------------------------
 # REST API Endpoints
 # -----------------------------------------------------------------------------
@@ -139,12 +160,26 @@
 # Não tem autenticação 
 @app.post("/grades/update")
 def update_grade():
+    # R1/R7: authenticate before touching the request body or GRADES.
+    user = current_user()
+    if user is None:
+        return {"error": "authentication required"}, 401
+
+    # Students (and any unknown role) can never update grades.
+    if user.role not in ("admin", "professor"):
+        return {"error": "forbidden"}, 403
+
     data = flask.request.get_json()
 
     student_id = data["student_id"]
     course_id = data["course_id"]
     grade = data["grade"]
 
+    # R3/R4: per-record check against the target course, before any write
+    # (covers both the update and the append branch below).
+    if not can_update_grade(user, course_id):
+        return {"error": "forbidden"}, 403
+
     row = find_grade(student_id, course_id)
     if row is None:
         GRADES.append({"student_id": student_id, "course_id": course_id, "grade": grade})
```

## Test grade update authz (File provided by the LLM)

```python
import copy
import baseline_secure_coding_api as api
from test_security_requirements import login, update


def test_professor_can_update_own_course(client):
    login(client, "prof_srs", "profpw")
    r = update(client, {"student_id": 1001, "course_id": "SRS", "grade": 18})
    assert r.status_code == 200
    assert api.find_grade(1001, "SRS")["grade"] == 18


def test_professor_cannot_create_row_in_other_course(client):
    login(client, "prof_srs", "profpw")
    before = copy.deepcopy(api.GRADES)
    r = update(client, {"student_id": 1002, "course_id": "SSD", "grade": 10})
    assert r.status_code == 403
    assert api.GRADES == before


def test_student_cannot_create_row(client):
    login(client, "bob", "bobpw")
    before = copy.deepcopy(api.GRADES)
    r = update(client, {"student_id": 1002, "course_id": "XYZ", "grade": 20})
    assert r.status_code == 403
    assert api.GRADES == before


def test_update_denied_after_logout(client):
    login(client, "admin1", "adminpw")
    client.post("/logout")
    before = copy.deepcopy(api.GRADES)
    r = update(client, {"student_id": 1001, "course_id": "SRS", "grade": 0})
    assert r.status_code == 401
    assert api.GRADES == before


def test_forged_session_role_is_ignored(client):
    login(client, "alice", "alicepw")
    with client.session_transaction() as s:
        s["role"] = "admin"
        s["courses"] = ["SRS", "SSD"]
    r = update(client, {"student_id": 1001, "course_id": "SRS", "grade": 20})
    assert r.status_code == 403
    assert api.find_grade(1001, "SRS")["grade"] == 14


def test_unknown_session_user_is_unauthenticated(client):
    with client.session_transaction() as s:
        s["user"] = "ghost"
        s["role"] = "admin"
    r = update(client, {"student_id": 1001, "course_id": "SRS", "grade": 0})
    assert r.status_code == 401


def test_course_id_case_variant_denied(client):
    login(client, "prof_srs", "profpw")
    before = copy.deepcopy(api.GRADES)
    for cid in ("srs", "SRS ", ["SRS"]):
        r = update(client, {"student_id": 1001, "course_id": cid, "grade": 0})
        assert r.status_code == 403, cid
    assert api.GRADES == before
```
