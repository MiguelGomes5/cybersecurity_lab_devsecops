I reviewed the attached source statically and did not execute anything. Line numbers are counted from the file as attached.

Assumed authorization policy. The source does not state an access policy. The policy below is my inference from the application context, and findings marked policy-dependent rest on it:

P1. A student may read only their own profile and grades.
P2. A professor may read and modify grades only for courses in their courses list. Reading profiles of students enrolled in those courses is plausible but unconfirmed.
P3. An administrator may read and modify all records.
P4. Teaching materials are readable by authenticated users, or possibly by anyone; this is unknown. Files outside the materials directory are never readable.
P5. Unauthenticated callers can reach only /, /login, and possibly /files.
Findings table
ID	Title	Location	Est. severity	Confidence
F1	Missing authentication and authorization on grade update	update_grade, L128–142	Critical	High
F2	Path traversal / arbitrary file read in materials download	download_file, L144–148	Critical	High
F3	Missing authorization on grade read (IDOR)	get_grades, L122–126	High	High (code fact); policy-dependent impact
F4	Missing authorization on profile read (IDOR, PII)	get_profile, L115–120	High	High (code fact); policy-dependent impact
F5	Hard-coded, guessable session signing key; client-side session state	L8; login L91–94; logout L98–101	High (latent)	High that the key is weak; impact depends on future authorization relying on the session
F6	Debug mode enabled and bound to all interfaces	L159	High in deployment, otherwise N/A	Medium
F7	Verbose exception disclosure and status-code collapse	handle_error, L150–155	Medium	High
F8	Missing input validation on grade update (type, range, existence)	update_grade, L130–140	Medium	High
F9	Plaintext, hard-coded credentials; no brute-force protection	L36–43, login L82–96	Medium	High (code fact); policy-dependent impact
F10	No CSRF protection or explicit cookie hardening	login, logout, update_grade; app config	Low	Medium
F11	Unsynchronized mutation of shared state	update_grade, L136–140	Low	Low–Medium
Supporting explanations
F1 — Missing authentication and authorization on grade update
Location: update_grade, L128–142. The data store is GRADES (L50–54), modified via find_grade (L56–60).
Input and data flow: The JSON body fields student_id, course_id, and grade (L130–134) go to find_grade (L136), then to GRADES.append (L138) or row["grade"] = grade (L140).
Missing control: Code fact: the function never reads flask.session, so no identity or role check exists. Inferred requirement (P2/P3): only professors assigned to course_id, or admins, may write. Root cause: authorization is not enforced at the handler. The session is populated at login but never consulted.
Preconditions and impact: No preconditions; the attacker needs only network access. Anyone, including unauthenticated users and students, can change any grade or create grade records for arbitrary student/course pairs. That is full loss of grade integrity.
Proposed test:
Send POST /grades/update with no cookie and body {"student_id":1001,"course_id":"SRS","grade":20}. Expect 401/403. A 200 response, followed by GET /grades/1001 showing grade 20, confirms the finding.
Repeat as alice, and as prof_srs with course_id:"SSD", which is not in that professor’s courses.
Assumptions: The precise write policy (P2/P3) is inferred. That the endpoint has no check at all is a code fact.
F2 — Path traversal / arbitrary file read in materials download
Location: download_file, L144–148.
Input and data flow: The query parameter path (L146) goes to MATERIALS_DIR / raw_path (L147), then to flask.send_file(target) (L148).
Missing control: Code fact: there is no normalization, no containment check, and no allow-list. With pathlib, joining an absolute path discards the base: MATERIALS_DIR / "/etc/passwd" yields /etc/passwd. Relative ../ segments are not resolved or rejected either. Root cause: untrusted input is used directly as a filesystem path, and send_file is used instead of a directory-confined helper.
Preconditions and impact: None. Any file readable by the process can be retrieved. That includes the application source, and therefore the SECRET_KEY (chains with F5), plus OS and configuration files. Authentication is also absent here, though whether materials should be public is unknown (P4).
Proposed test:
GET /files?path=../baseline_secure_coding_api.py and GET /files?path=/etc/hostname (or a canary file placed outside materials/). Receiving the file contents confirms the finding; a 400/403/404 rejects it.
Also try URL-encoded variants (..%2F).
Assumptions: Exploitability is subject to OS file permissions of the process user. The pathlib absolute-path behavior and the absence of validation are code facts. I have not verified version-specific behavior of send_file with absolute paths, so confidence that it succeeds is high but not certain.
F3 — Missing authorization on grade read (IDOR)
Location: get_grades, L122–126.
Input and data flow: The path parameter student_id goes to int() (L124), then filters GRADES (L125), then the response.
Missing control: Code fact: no session check. Inferred requirement (P1–P3): a student can read only their own grades, and a professor only grades for their courses. Root cause: object-level authorization is missing, and the identifier is taken from the URL rather than bound to the session.
Preconditions and impact: None. Any caller can enumerate sequential IDs (1001, 1002, …) and read every student’s grades, which is confidential academic data.
Proposed test:
Logged in as alice, request GET /grades/1002. Expect 403; Bob’s grades in the response confirm the finding.
Also request with no cookie, and as prof_srs, checking whether the SSD row for 1001 is returned.
Assumptions: The policy is inferred. The absence of any check is a code fact.
F4 — Missing authorization on profile read (IDOR, PII)
Location: get_profile, L115–120.
Input and data flow: The path parameter student_id goes to int() (L117), then STUDENT_PROFILES.get (L117), then the response.
Missing control: Same as F3: no session or ownership check. Distinct 404 vs 200 responses also permit enumeration of valid student IDs.
Preconditions and impact: None. Any caller can read names, emails, and programs of all students. This is personal data, likely subject to GDPR given a uc.pt deployment, but that is an assumption.
Proposed test: Unauthenticated GET /students/1001/profile, then the same as bob. A 200 response with Alice’s email confirms the finding.
Assumptions: Professor read access to profiles is undefined in the context, so the expected result for professors is uncertain.
F5 — Hard-coded, guessable session signing key; client-side session state
Location: L8 (SECRET_KEY = "dev-secret-key"); session writes at L91–94; logout at L98–101.
Input and data flow: The session cookie is attacker-supplied and verified with the key from L8. Its claims (user, role, student_id, courses) feed back into me() (L108–113).
Missing control: Code facts:
The signing key is a constant in source and is trivially guessable.
Flask’s default session is a signed, unencrypted client-side cookie, so role and authorization attributes live client-side.
logout clears only the client’s copy, so a previously captured cookie stays valid.
No session lifetime is configured.
Root cause: the secret is not managed outside the code, and authorization data is stored in a forgeable token.
Preconditions and impact: The attacker needs the key, which is guessable or obtainable via F2. Today no endpoint enforces authorization from the session, so the practical impact is limited to /me spoofing. However, any fix to F1/F3/F4 that trusts session["role"] or session["student_id"] would be fully bypassable. An attacker could mint {"role":"admin"}. I rate this a latent high.
Proposed test: Use itsdangerous/Flask’s serializer offline with key dev-secret-key to sign {"user":"x","role":"admin","student_id":null,"courses":["SRS","SSD"]}. Send it to GET /me. Being reported as admin confirms forgeability. Separately, capture a cookie, call /logout, then replay the old cookie to /me.
Assumptions: Production may override the key via configuration, but nothing in the source suggests so. Medium-high confidence on impact, given the latent dependency.
F6 — Debug mode enabled and bound to all interfaces
Location: L159, app.run(debug=True, host="0.0.0.0", ...).
Input and data flow: Any network client reaches the Werkzeug development server and its debugger routes.
Missing control: Code fact: debug is enabled and the server listens on all interfaces. Root cause: development configuration is used as the runtime entry point.
Preconditions and impact: This applies only when the app is launched as python file.py, not under a production WSGI server. The interactive debugger is PIN-protected by default, but a disclosed or derivable PIN gives remote code execution. F2 can leak inputs often used in PIN derivation (machine-id, MAC address, username), which strengthens this chain. Note that the catch-all errorhandler(Exception) (F7) likely prevents traceback pages for view exceptions, so the debugger console route is the more relevant exposure. The auto-reloader and verbose behavior also apply.
Proposed test: Start via __main__ and request GET /console from another host. A Werkzeug console/PIN prompt confirms exposure.
Assumptions: The deployment method is unknown. Medium confidence because exploit depth depends on Werkzeug version and PIN handling.
F7 — Verbose exception disclosure and status-code collapse
Location: handle_error, L150–155.
Input and data flow: Any input that raises an exception reaches the handler, which returns str(exc) and the exception class name. Examples:
int("abc") at L117/L124
a missing JSON key at L132–134
get_json() returning None at L130
a file not found at L148
send_file on a directory, e.g. path= empty
Missing control: Code fact: raw exception text is returned to clients. Because the handler is registered for Exception, it most likely also intercepts HTTPExceptions (404, 405, 415), converting them to 500 and exposing their messages. Root cause: there is no separation between internal diagnostics and client-safe errors.
Preconditions and impact: None. This leaks absolute filesystem paths (e.g., FileNotFoundError reveals the full path of MATERIALS_DIR), internal key names, and library details. That aids F2 and F6, and wrong status codes hamper monitoring.
Proposed test:
GET /files?path=nonexistent.txt: a full absolute path in the error field confirms the finding.
GET /grades/abc: a ValueError text response confirms it.
GET /nonexistent-route: a 500 instead of 404 confirms the status collapse.
Assumptions: Interception of HTTPException depends on Flask version (≥1.1 behavior assumed). Medium confidence on that sub-claim; high on the disclosure itself.
F8 — Missing input validation on grade update
Location: update_grade, L130–140.
Input and data flow: Arbitrary JSON values flow into GRADES without checks.
Missing controls: Code facts:
grade can be any JSON type (string, negative number, 1000, object).
student_id may be a string, so "1001" does not equal 1001, which creates a duplicate, shadow row that get_grades won’t return. Inferred: this is integrity confusion.
Records can be created for nonexistent students or courses.
A non-dict body causes an exception, handled per F7.
The valid grade scale is not stated. A 0–20 scale is plausible for a Portuguese university, but that is an assumption. Root cause: there is no schema or domain validation and no referential checks.
Preconditions and impact: Reaching this requires write access, which F1 currently gives to anyone. Impact: corrupted or inconsistent grade data, and possible downstream failures in consumers that expect numeric grades.
Proposed test: POST {"student_id":"1001","course_id":"SRS","grade":"A+"}, then {"student_id":9999,"course_id":"XYZ","grade":-5}. A 200 for each, followed by inspection of GRADES via /grades/1001 and /grades/9999, confirms the finding.
Assumptions: The grade domain is unspecified. High confidence that validation is absent.
F9 — Plaintext, hard-coded credentials; no brute-force protection
Location: L36–43 (credentials in source), L88 (plaintext != comparison), login L82–96.
Input and data flow: Form fields username and password are compared directly to stored plaintext.
Missing controls: Code facts: passwords are stored in plaintext in source, with no hashing (e.g., a slow KDF) and no constant-time comparison. The code has no rate limiting, lockout, or logging of failures. Root cause: the credential store is designed for convenience only.
Preconditions and impact: Anyone with source access, including via F2, obtains all passwords, admin included. Online guessing is unthrottled. The timing side channel from != is minor and of low practical concern. Identical error messages for unknown user and wrong password are a positive code fact.
Proposed test:
Script around 100 rapid wrong-password attempts for admin1. The absence of throttling or lockout confirms the brute-force gap.
Read the source via F2 and log in as admin1.
Assumptions: The context says the in-memory store is a teaching simplification, so severity may be intentionally accepted. I flag it because the store’s design pattern would carry over.
F10 — No CSRF protection or explicit cookie hardening
Location: login (form-encoded POST), logout, update_grade; no SESSION_COOKIE_* configuration.
Input and data flow: Cross-site requests from a victim’s browser carry the session cookie.
Missing control: Code facts: there are no CSRF tokens, and SESSION_COOKIE_SECURE and SESSION_COOKIE_SAMESITE are not set. Mitigating fact: update_grade uses get_json() without force=True, so a cross-site simple form post probably won’t parse as JSON. Classic CSRF on that endpoint is likely blocked by CORS preflight requirements, and is moot today because of F1. Login CSRF, which logs a victim into an attacker’s account, and forced logout are feasible.
Impact: Low today. This becomes relevant once session-based authorization is added.
Proposed test: Host a page that auto-submits a form to /login with attacker credentials, visit it in a browser, then check /me. Separately, attempt a text/plain cross-origin POST to /grades/update and observe whether it is parsed.
Assumptions: Behavior depends on browser SameSite defaults and Flask version. Medium confidence.
F11 — Unsynchronized mutation of shared state
Location: update_grade, L136–140, a check-then-act on the global GRADES.
Issue: Under a threaded server, concurrent updates for the same key can both observe row is None and append duplicate rows. That is a code fact about the pattern. Python’s GIL limits damage, but it does not make the check-then-append atomic.
Impact: Duplicate or inconsistent grade rows. This is low severity and partly an artifact of the in-memory teaching design.
Proposed test: Fire around 50 concurrent identical POSTs for a new (student, course) pair, then count rows via GET /grades/<id>.
Confidence: Low–medium. Whether it reproduces depends on the server’s threading mode.
Notable chains
F2 → F5: Reading the source yields the signing key, which allows forging an admin session. This becomes decisive once F1, F3, and F4 are fixed using session claims.
F2 → F9: Reading the source yields all plaintext passwords, giving legitimate admin login.
F2 + F7 → F6: Path disclosure and system-file reads aid derivation of the debugger PIN.
Scope limits

This is a single-file static review. I could not assess:

Flask and Werkzeug versions, which affect F6, F7, and F10.
The deployment configuration: WSGI server, TLS, reverse proxy, environment overrides of SECRET_KEY.
File permissions and the contents of materials/.
Logging and auditing requirements, which are entirely absent. Grade changes are not attributed to anyone, a likely requirement gap for academic records but not stated in the context.

The absence of further findings does not establish that the application is otherwise safe.