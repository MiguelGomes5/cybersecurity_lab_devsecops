Static Security Review: baseline_secure_coding_api.py

Method. I read the attached source only. Nothing was executed. Line numbers are counted from the file as attached (line 1 is import dataclasses).

Labels used below:

Code fact: what the source demonstrably does.
Requirement: the stated rule (R1–R7) being violated.
Inference: behavior I reason about from library semantics, or a security expectation not stated in R1–R7. Where Flask or Werkzeug version matters, I say so.

Severity is a qualitative judgment for the stated multi-user deployment, not a CVSS score.

Findings table
ID	Title	Location	Req.	Severity	Confidence
F01	Anyone can create or modify any grade without authentication or authorization	update_grade, L128–142	R1, R3, R4, R7	Critical	High
F02	Path traversal / arbitrary file read in material download	download_file, L144–148	R6	Critical	High
F03	Grade update performs no input validation (type, range, course, student existence) and silently inserts rows	update_grade, L130–140; find_grade, L56–60	R5, R7	High	High
F04	Profile endpoint lacks authentication and object-level authorization (IDOR)	get_profile, L115–120	R1, R2, R3, R4	High	High
F05	Grade-read endpoint lacks authentication, ownership and course scoping, and denial of empty results	get_grades, L122–126	R1, R2, R3, R4	High	High
F06	Material download requires no authentication	download_file, L144–148	R1	Medium	High
F07	Hard-coded, publicly known SECRET_KEY lets clients forge sessions, including role claims	L8; session use L91–94	R1, R4 (latent)	High	High (fact) / Medium (impact today)
F08	Global error handler leaks exception details and turns every error, including 4xx, into 500	handle_error, L150–155	R7	Medium	High
F09	Student ID parsing accepts non-positive and non-canonical values; non-numeric input yields 500	L117, L124	R5, R7	Low–Medium	High
F10	Debug mode enabled and bound to all interfaces	L158–159	R7 (inference)	Medium (conditional)	Medium
F11	Plaintext, hard-coded credentials; no login throttling	L36–43, L84–89	Outside R1–R7 (inference)	Low	High (fact)
F12	Session lifecycle weaknesses: no server-side revocation, stale role and course claims, unset cookie hardening	L91–94, L98–101, app config	R1, R4 (inference)	Low	Medium
F13	Unsynchronized mutation of shared in-memory grade store	L136–140	R7 “leave data unchanged” (inference)	Informational	Low–Medium
Supporting explanations
F01 — Unauthenticated, unauthorized grade modification
Location: update_grade, L128–142.
Input and flow: The JSON body student_id, course_id and grade (L132–134) goes to find_grade (L136), then either GRADES.append (L138) or row["grade"] = grade (L140).
Missing control / root cause:
Code fact: the function never reads flask.session, and no decorator or before_request hook exists anywhere in the file.
Requirement: R1 requires authentication. R3 limits updates to admins and to professors for their assigned courses only, so students may never update. R4 requires a per-record check. R7 requires 401 or 403 with stored data unchanged.
Preconditions and impact: Only network reachability is needed; any anonymous client can set any student’s grade in any course. This is complete loss of grade integrity.
Test:
Send an anonymous POST /grades/update with {"student_id":1001,"course_id":"SRS","grade":20}. Expect 401 and the grade still 14.
Repeat logged in as bob (expect 403) and as prof_srs against course_id:"SSD" (expect 403).
Logged in as prof_srs on SRS, and as admin1, the update should succeed.
Assumptions and confidence: None needed. High.
F02 — Path traversal / arbitrary file read
Location: download_file, L146–148.
Input and flow: The query parameter path (L146) is joined as MATERIALS_DIR / raw_path (L147) and passed to flask.send_file (L148).
Missing control / root cause:
Code fact: there is no canonicalization or containment check.
Inference from pathlib semantics: if raw_path is absolute, MATERIALS_DIR / "/etc/passwd" discards the base entirely and yields /etc/passwd. Relative ../ segments are kept unnormalized and resolved by the OS when the file is opened.
Inference: send_file given a filesystem path performs no directory confinement. A containment-enforcing API was not used.
Requirement: R6.
Preconditions and impact:
No authentication is needed (see F06).
An attacker can read any file readable by the process. That includes ../baseline_secure_coding_api.py, which discloses all passwords (F11) and the SECRET_KEY (F07), plus OS files.
Symlinks placed inside materials/ would also escape. This is an inference; none exist in the seeded data.
Test: Send each of GET /files?path=../baseline_secure_coding_api.py, ?path=/etc/passwd, ?path=..%2F..%2Fetc%2Fpasswd, and a symlink inside materials/ pointing outside. Each should be rejected (403 or 404) without file content. ?path=srs-summary.txt should succeed when authenticated.
Assumptions and confidence: Assumes a typical POSIX host. High.
F03 — Missing validation on grade update, with silent insert
Location: L130–140 and find_grade L56–60.
Input and flow: The raw JSON values are compared with == in find_grade and stored unchanged.
Missing control / root cause (code facts, against R5):
There is no check that the body is a JSON object. A list, string or null raises a TypeError, which produces a 500 rather than a 400.
Missing keys raise KeyError, which also produces a 500.
course_id is never checked against {SRS, SSD}.
student_id is never checked against existing students. When no row matches, L137–138 inserts a new row instead of rejecting.
grade has no type or range check. true, -5, 999, "A", null and nested objects are all stored.
Type confusion follows from Python’s ==:
"1001" (a string) does not match int 1001, so a phantom row is appended that GET /grades/1001 will never show.
1001.0 does match int 1001 and updates the real row.
Inference: Python’s json module accepts NaN and Infinity by default, so grade: NaN can be stored and later re-emitted as non-standard JSON.
Preconditions and impact: Combined with F01, this is anonymous data corruption and unbounded memory growth from inserted rows. Even with authorization in place, an authorized professor could store invalid grades. R7’s “invalid update leaves data unchanged” is violated because invalid values are persisted.
Test: Using a table-driven test, snapshot GRADES before each request. Payloads:
[], a non-JSON body, {}, and each payload with one field removed.
course_id:"XYZ", student_id:9999, student_id:"1001", student_id:true.
grade set to each of true, -1, 21, 20.5, "15", null, NaN.
Expect 400 or 422 and an unchanged GRADES. Boundary values 0 and 20 should succeed for an authorized user.
Assumptions and confidence:
Assumption: R5 says only “numeric,” so fractional grades like 20.5 are treated as allowed.
Assumption: whether the response for a nonexistent student should be 400, 404 or 422 is unspecified.
High.
F04 — Profile access: no authentication, IDOR
Location: get_profile, L115–120.
Input and flow: The path segment student_id goes through int() into STUDENT_PROFILES.get and is returned in full.
Missing control / root cause:
Code fact: there is no session check, no comparison with session["student_id"], and no role check.
Requirement: R1 (401 when anonymous), R2 (a student may read only their own profile), R3 (professors are denied, admins allowed), R4.
Preconditions and impact:
Anyone can enumerate IDs and harvest names, emails and programs, which is personal data.
The 404-versus-200 distinction is an existence oracle for student IDs. Whether that matters under the policy is not stated.
Test:
Anonymous request to /students/1001/profile: expect 401.
bob requesting 1001: expect 403. alice requesting 1001: expect 200.
prof_srs requesting 1001: expect 403. admin1: expect 200.
Assumptions and confidence:
Assumption: the policy does not say whether an unauthorized request for a nonexistent ID should get 403 or 404, so the test should accept either but must not leak data.
High.
F05 — Grade read: no authentication, ownership or course scoping
Location: get_grades, L122–126.
Input and flow: The path student_id goes through int(), then every matching row in all courses is returned.
Missing control / root cause:
Code fact: there are no session or role checks and no filtering by session["courses"].
Code fact: an empty result returns 200 [].
Requirement:
R1: authentication is required.
R2: a student may read only their own grades.
R3: a professor may read only courses in their courses list. prof_srs must not see Alice’s SSD grade of 16.
R4: return only authorized records, and deny when none are permitted.
Preconditions and impact: Anonymous disclosure of all grades. The [] versus non-empty response also reveals which students have records.
Test:
Anonymous request: expect 401. bob requesting /grades/1001: expect 403.
prof_srs requesting /grades/1001: expect only the SRS row. prof_srs requesting a student with only SSD grades (add a fixture): expect 403.
admin1: expect all rows.
Assumptions and confidence:
Assumption: when a student requests their own grades and has none, the policy is ambiguous. R4’s “deny when no permitted records” reads as applying to scope filtering, not to an empty own-record list. This needs clarification.
High.
F06 — Material download unauthenticated
Location: L144–148.
Root cause: Code fact: no session check. Requirement: R1.
Impact: Teaching materials are publicly readable, and F02 becomes exploitable anonymously.
Test: Anonymous GET /files?path=srs-summary.txt should return 401.
Confidence: High.
F07 — Known SECRET_KEY, session forgery
Location: L8, with session writes at L91–94.
Input and flow: The client-supplied session cookie is verified with the constant "dev-secret-key".
Missing control / root cause:
Code fact: the key is hard-coded in source, and it is also disclosed via F02.
Inference: Flask’s default session is a client-side signed cookie. Anyone holding the key can mint a valid cookie with arbitrary user, role, student_id and courses values.
Code fact: those values are copied into the session at login and never re-checked against USERS.
Preconditions and impact:
Today no endpoint reads the session for authorization, so the impact is latent.
Once authorization checks are added that trust session claims, this becomes a full privilege escalation to role: admin.
Test: Build a cookie signed with the known key containing {"user":"x","role":"admin"} and call a protected endpoint. Expect 401 or 403 once authorization exists. The test also confirms whether authorization re-derives the role from the server-side user record.
Assumptions and confidence: Assumes Flask’s default session interface. High that forgery is possible; Medium on current impact.
F08 — Error handler leaks details; wrong status codes
Location: L150–155.
Missing control / root cause:
Code fact: the handler catches all exceptions and returns str(exc) and the class name with status 500.
Inference: in Flask, a handler for Exception also catches HTTPException. That means 404 for unknown routes, 405, and 400 or 415 from get_json all become 500.
Inference: messages like FileNotFoundError: [Errno 2] No such file or directory: '/abs/path/materials/x' disclose absolute server paths. Similarly, IsADirectoryError occurs for an empty path, and ValueError: invalid literal for int()... occurs for bad IDs.
Requirement: R7 (client errors without internal details).
Test:
GET /files?path=nope.txt and GET /files?path= should not return 500 or include any filesystem path.
GET /students/abc/profile and a non-JSON POST /grades/update should return 400 with a generic message.
GET /nonexistent should return 404.
Assumptions and confidence: The exact get_json behavior varies by version. Newer Flask raises 415 or 400; older versions return None, which causes a TypeError. Both paths end in 500 here. High.
F09 — Student ID parsing
Location: L117, L124.
Code facts:
The route uses the string converter followed by int(). Python’s int() accepts -5, 0, +1001, 01001, 1_001 and Unicode digits (inference about Python semantics).
Non-numeric input raises ValueError, which reaches F08 as a 500.
Requirement: R5 (positive integers) and R7 (400 for invalid input).
Impact: Mostly a correctness issue. Non-canonical aliases could bypass naive string-based authorization or logging added later.
Test: Request IDs 0, -1, abc, 1_001, +1001 and 01001. Expect 400, or the policy-defined handling for non-canonical forms. Normalization behavior is an open policy question.
Confidence: High.
F10 — Debug mode on all interfaces
Location: L159.
Code fact: debug=True, host="0.0.0.0".
Inference:
The Werkzeug debugger and its PIN-protected console become network-reachable.
The custom handler at L150 likely suppresses traceback pages for in-request exceptions, but the debugger itself remains enabled.
Precondition: The app is started via __main__, not through a production WSGI server.
Impact: Possible code execution if the PIN is obtained or derived, which F02 may help with. The reloader and verbose behavior are also active.
Test: Configuration assertion that debug is off and the app binds to localhost in non-development configs. Probe for the debugger console endpoint.
Confidence: Medium (deployment-dependent).
F11 — Credential handling
Code facts: Plaintext passwords in source (L37–42), compared with != (L88). No throttling or lockout.
Not explicitly required by R1–R7. It is listed as an inferred baseline expectation.
Impact: Credentials are exposed through F02 or a source leak, and online guessing is unrestricted.
Test: Repeated failed logins should be rate-limited. Stored credentials should not be recoverable plaintext.
Confidence: High for the facts; the policy relevance is assumed.
F12 — Session lifecycle
Code facts:
logout only clears the client cookie (L100).
Role and course claims are snapshotted at login (L92–94).
No SESSION_COOKIE_SECURE, SAMESITE or lifetime configuration is set.
Inference:
A captured cookie stays valid after logout until it expires, because there is no server-side revocation.
Role or course changes would not take effect until the user logs in again.
Form-encoded /login and /logout may be susceptible to login or logout CSRF, depending on browser SameSite defaults.
Test: Capture a cookie, log out, replay it against /me, and observe whether the user is still present.
Confidence: Medium. The policy on revocation is unstated.
F13 — Concurrency on shared state
Code fact: GRADES is mutated via a check-then-act sequence (L136–140) with no lock.
Inference: Under a threaded server, concurrent updates to the same key could create duplicate rows. After that, find_grade returns only the first match while get_grades returns both.
Relevance: Low, given the teaching-only store.
Test: Fire concurrent identical first-time inserts and assert exactly one row exists.
Confidence: Low–Medium.
Limits of this review
This review covers only the attached file and the stated R1–R7. Dependency versions, deployment configuration (TLS, reverse proxy, WSGI server) and the contents of materials/ were not examined.
Library-behavior claims marked as inference should be confirmed by the proposed tests.
Areas not found vulnerable, such as the fixed redirect in login or /me returning {"user": null}, are not proven safe. Additional issues may exist beyond those listed.