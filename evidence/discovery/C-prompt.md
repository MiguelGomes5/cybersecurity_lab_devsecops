Perform a static security review of the attached application source. Use only the source and any context explicitly included in this request. Do not execute code, use tools, browse, or rely on published solutions. For each potential vulnerability, provide: 1. A short finding identifier and title. 2. Affected file, function, and line location where available. 3. Attacker-controlled input and the relevant execution or data-flow path. 4. The missing or incorrect security control and the root cause. 5. Preconditions and potential impact. 6. A proposed test that could confirm or reject the claim. 7. Assumptions, uncertainty, and confidence. Distinguish demonstrated code facts from inferred security requirements. If the policy is unknown, state the assumption rather than inventing it. Do not generate patches yet. Return a concise findings table followed by supporting explanations. Do not treat an absence of findings as proof of safety.

Application context
This is an academic-services REST API.
It supports login/logout, inspection of the current session, student
profiles,
grade retrieval and updates, and downloads of teaching materials.
Users have student, professor, or administrator roles. Student accounts have
an associated student identifier. Professor accounts have assigned courses.
Grade records associate a student, a course, and a grade. Teaching materials
are stored in the application's materials directory.
The application is used by multiple users. The in-memory records and small
dataset simplify the teaching environment; they are not a production
database.

Security requirements for this exercise
R1 — Authentication:
Profile access, grade access, grade updates, and material downloads require
an authenticated user. The index and login endpoint may remain public.
The /me endpoint may return {"user": null} when no user is authenticated.
R2 — Student privacy:
Students may read only their own profile and grades.
R3 — Academic staff scope:
Professors may read and update grades only for their assigned courses.
In this simplified exercise, professors are not permitted to read student
profile records. Administrators may read profiles and grades and update
grades.
R4 — Complete authorization:
Check authorization on every relevant request. Login alone, a valid
identifier,
or a role name alone does not establish permission for a particular record.
For a grade-list response, return only records the requester is authorized
to
read. Deny a request that has no permitted records; do not disclose other
grades.
R5 — Input validation:
Student identifiers must be positive integers. Grade updates require a JSON
object with an existing student identifier, a known course identifier, and a
numeric grade from 0 to 20 inclusive. Boolean values are not valid grades.
Reject missing fields and malformed input without applying an update.
Known courses for this baseline are SRS and SSD.
R6 — File access:
Authenticated users may download teaching materials within the materials
directory. Requests must not read files outside that directory.
R7 — Error handling:
Invalid requests must return appropriate client errors without exposing internal paths, tracebacks, or implementation exception details.
Unauthenticated protected requests return 401; authenticated but
unauthorized
requests return 403. A denied or invalid update must leave stored data
unchanged.

Attached:
    - baseline_secure_coding_api.py