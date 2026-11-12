We are now repairing a confirmed vulnerability in the supplied application.
This is repair assistance, not an independent discovery review.

Confirmed finding:
V1 - Missing authorization on grade updates (POST /grades/update)

Affected code: baseline_secure_coding_api.py, function update_grade().

Root cause: update_grade() reads student_id, course_id and grade from the
JSON body and writes them to the global GRADES list (updating an existing
row or appending a new one). It never checks whether a user is logged in,
what role the user has, or whether a professor is assigned to the course.
Any client can change any grade.

Reproduction (Flask test client, tests_security/test_security_requirements.py):
- No login, POST {"student_id": 1001, "course_id": "SRS", "grade": 0}
  -> expected 401, got 200, grade changed.
- Logged in as alice (student 1001), POST {"student_id": 1001, "course_id": "SRS", "grade": 20}
  -> expected 403, got 200, grade changed from 14 to 20.
- Logged in as prof_srs (assigned courses: ["SRS"]), POST {"student_id": 1001, "course_id": "SSD", "grade": 0}
  -> expected 403, got 200, grade changed from 16 to 0.

CI failure output (security-regression job, before patching):
test_update_requires_login                  assert 200 == 401
test_student_cannot_update_grade            assert 200 == 403
test_professor_cannot_update_other_course   assert 200 == 403

Required behavior:
R1 - Grade updates require an authenticated user.
R3 - Professors may update grades only for their assigned courses.
     Administrators may update grades.
R4 - Check authorization on every relevant request. Login alone, a valid
     identifier, or a role name alone does not establish permission for a
     particular record.
R7 - Unauthenticated requests return 401; authenticated but unauthorized
     requests return 403. A denied update must leave stored data unchanged.

Legitimate use cases that must keep working:
- prof_srs updates a grade in SRS -> 200 and the grade is stored.
- admin1 updates a grade in any course (e.g. SSD) -> 200 and the grade is stored.

Scope: fix authentication and authorization of /grades/update only.
Input validation of the update body is not part of this repair.

Propose a minimal, reviewable patch addressing the root cause.
Preserve the API's legitimate functionality and relevant response contracts.
Do not delete endpoints, disable features, weaken tests, or suppress scanner
rules to hide the issue. Identify all affected paths that need the same
control.

Return a unified diff, explain the control being implemented, and identify
remaining assumptions or limitations. Suggest additional regression tests.

Attached:
- baseline_secure_coding_api.py
- tests_security/conftest.py
- tests_security/test_security_requirements.py
