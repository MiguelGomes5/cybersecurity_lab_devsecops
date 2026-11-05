Static Security Review: baseline_secure_coding_api.py

Scope and method. I reviewed only the attached source, without running it. Line numbers are counted from the attachment, so they may be off by one or two if the file has different line endings or a header. The Flask and Werkzeug versions are not stated, and some behaviour depends on them; I flag this where it matters.

Assumed authorization policy. No policy is given, so I assume a typical academic-records model. Every finding that relies on it is marked inferred.

P1: Students may read only their own profile and grades.
P2: Professors may read and update grades only for courses in their courses list.
P3: Admins may do everything.
P4: Course materials may be downloaded only from materials/, possibly only by authenticated users.
P5: Grades are bounded values on a known scale. Portuguese 0–20 is suggested by the sample data, but that is an assumption.
Findings table
ID	Title	Location	Severity (est.)	Confidence
F1	Path traversal / arbitrary file read	download_file, L144–148	Critical	High
F2	Unauthenticated, unauthorized grade modification	update_grade, L128–142	Critical	High
F3	Unauthenticated grade disclosure (IDOR)	get_grades, L122–126	High	High (fact) / policy inferred
F4	Unauthenticated profile/PII disclosure (IDOR)	get_profile, L115–120	High	High (fact) / policy inferred
F5	Hard-coded Flask SECRET_KEY → session forgery	L8	High	High
F6	Debug mode on all interfaces → debugger exposure, possible RCE chain	L159	High (if run as script)	Medium
F7	Verbose error disclosure; all errors become 500	handle_error, L150–155	Medium	High
F8	Missing input validation / type confusion in grade update	update_grade, L130–140	Medium	High
F9	Plaintext, hard-coded credentials; non-constant-time compare	L36–43, L88	Medium	High (fact) / Low (timing)
F10	Weak session lifecycle and cookie hardening	login/logout, L91–100; app config	Low–Medium	Medium
F11	No brute-force protection on login	login, L82–96	Low–Medium	High (fact)
F12	Login/logout CSRF	login, logout	Low	Medium
F13	No audit trail; unsynchronized shared mutable state	update_grade, global GRADES	Low	Medium
Supporting explanations
F1 — Path traversal / arbitrary file read (download_file, L144–148)
Input and flow: The query parameter path is read as raw_path (L146). It is joined as MATERIALS_DIR / raw_path (L147) and passed to flask.send_file(target) (L148).
Code fact: The resolved path is never normalized or contained, there is no allow-list, and there is no authentication check.
Two pathlib behaviours make this exploitable:
.. segments are preserved, so ../baseline_secure_coding_api.py escapes the directory.
An absolute right operand replaces the base entirely, so Path("/x/materials") / "/etc/passwd" becomes /etc/passwd.
Root cause: User-controlled input is trusted as a filesystem path. send_file is used instead of a contained helper such as send_from_directory, and there is no check like resolved.is_relative_to(MATERIALS_DIR).
Preconditions: Network access only. No login is needed. Only files readable by the process user are exposed.
Impact: Disclosure of application source (including credentials and the secret key, see F5 and F9), OS files, environment files, and any inputs to the Werkzeug PIN calculation (F6).
Test:
GET /files?path=../baseline_secure_coding_api.py
GET /files?path=/etc/passwd
GET /files?path=..%2F..%2Fetc%2Fhostname
Control case: GET /files?path=srs-summary.txt should succeed, and every out-of-directory request should be rejected.
Uncertainty: On Windows, absolute and drive paths behave differently, but traversal is still likely. Confidence: high.
F2 — Unauthenticated, unauthorized grade modification (update_grade, L128–142)
Input and flow: The JSON body fields student_id, course_id, and grade (L132–134) go to find_grade and then either GRADES.append (L138) or an in-place update (L140).
Code fact: The handler never reads flask.session at all. There is no role check, no course-ownership check, and no check that the student exists.
Inferred requirement: P2 and P3.
Root cause: No authentication or authorization layer exists on a state-changing endpoint.
Preconditions: Network access only.
Impact:
Anyone, including students, can change any grade or create arbitrary grade records.
Even with authentication added, there is no check for a professor writing to another course, such as prof_srs writing SSD.
Test:
Send POST /grades/update with no cookie and body {"student_id":1002,"course_id":"SRS","grade":20}, then confirm the change with GET /grades/1002. The expected secure result is 401.
Repeat the request as alice; the expected secure result is 403.
Repeat as prof_srs on course SSD; the expected secure result is 403.
Confidence: High.
F3 — Grade disclosure / IDOR (get_grades, L122–126)
Input and flow: The path segment student_id is converted with int() and used to filter GRADES.
Code fact: No session or ownership check.
Inferred requirement: P1–P3.
Impact:
Any unauthenticated caller can read any student’s grades.
Sequential IDs make enumeration trivial.
Test:
GET /grades/1001 without a cookie, and again as bob. The expected secure result is 401 and 403 respectively.
Enumerate IDs 1000–1010.
Confidence: High that access is unrestricted. Whether this is a violation depends on the policy, which I assumed.
F4 — Profile/PII disclosure / IDOR (get_profile, L115–120)
Flow and control: Same pattern as F3, but it exposes name, email, and program.
Impact:
Unauthenticated PII disclosure.
Possible data-protection (GDPR) relevance, which is an inference.
The 404 vs 200 difference lets an attacker confirm which student IDs exist.
Test: GET /students/1002/profile as anonymous and as alice.
Confidence: High for the code fact; the policy is inferred.
F5 — Hard-coded SECRET_KEY (L8)
Code fact: The key is the constant "dev-secret-key". Flask’s default sessions are client-side cookies signed with this key.
Root cause: A secret is embedded in source, it is low-entropy and guessable, and there is no environment or secret-store configuration.
Impact:
Anyone who knows or guesses the key can forge a session such as {"user":"admin1","role":"admin"}.
The key is also readable via F1.
Today no endpoint enforces roles, so the current impact is spoofing /me. Any authorization added later that trusts session["role"] would be bypassable. Session values are also copied at login and never re-checked against USERS.
Test: Sign a crafted session with itsdangerous or Flask’s SecureCookieSessionInterface using the known key, then send it to /me and check that it is accepted as admin1.
Confidence: High.
F6 — debug=True on 0.0.0.0 (L159)
Code fact: When run as a script, the app enables Werkzeug’s debugger and reloader and binds all interfaces.
Impact:
The debugger console is PIN-protected.
However, the PIN is derived from values that F1 may let an attacker read: the username, module path, MAC address, and machine-id. That makes a plausible chain to remote code execution.
Nuance: The catch-all errorhandler(Exception) likely stops the traceback debugger page from appearing on errors. The standalone /console route may still be served, depending on the Werkzeug version.
Preconditions: The app is started via __main__ rather than through a WSGI server, and it is network-reachable.
Test:
Check whether GET /console is served.
Use F1 to retrieve the PIN inputs, such as /sys/class/net/*/address and /etc/machine-id (Linux).
Check for the Debugger is active banner in startup output, as a configuration review.
Confidence: Medium. The exposure is certain when run as a script; the full chain depends on version and OS.
F7 — Verbose error handler (L150–155)
Code fact: Every exception returns str(exc) and the exception class name.
What leaks:
FileNotFoundError and IsADirectoryError messages include absolute paths, which reveal BASE_DIR and help with F1. For example, GET /files?path= resolves to the directory itself.
KeyError messages reveal expected field names.
ValueError messages come from int() on non-numeric IDs.
Status-code issue: In current Flask versions a handler for Exception also catches HTTPException, so 404, 405, and 415 responses likely become 500s. This is version-dependent, medium confidence.
Test:
GET /files?path=nonexistent
GET /files?path=
GET /grades/abc
GET /nope (check whether it returns 500 instead of 404)
F8 — Missing input validation in grade update (L130–140)
Code facts:
The type, range, and existence of grade, student_id, and course_id are not checked.
get_json() may return None or raise an error, depending on the Flask version.
Missing keys raise KeyError, which then flows into F7.
Consequences:
Grades can be negative, strings, nested objects, or values above the assumed scale (P5).
A string "1001" will not match the integer 1001, so it creates a duplicate orphan row instead of updating. This is an integrity issue.
Large payloads can grow memory without bound.
If grades are later rendered in HTML, stored XSS is possible. That is inferred; the current output is JSON only.
Test:
Send {"student_id":"1001","course_id":"SRS","grade":"<script>"}, then inspect GRADES through GET /grades/1001.
Send {"grade":-5,...}.
Send a body that is not JSON.
Confidence: High.
F9 — Credential storage and comparison (L36–43, L88)
Code facts:
Passwords are stored in plaintext in source and are weak (e.g., adminpw).
The comparison uses !=, which is not constant-time.
Impact:
Direct credential exposure via F1 or source access.
A timing side channel is theoretically present, but practical exploitability over a network is low.
Test:
Code review should confirm no hashing (e.g., bcrypt or argon2) is used.
Optionally, statistical timing measurement on /login. I expect inconclusive results.
Confidence: High for storage; low for timing exploitability.
F10 — Session lifecycle and cookie hardening
Code facts:
Sessions are stateless signed cookies.
logout only clears the client cookie, so a captured cookie stays valid until the key changes.
No SESSION_COOKIE_SECURE, SESSION_COOKIE_SAMESITE, or lifetime settings are configured.
Session claims (role, courses) are fixed at login and never re-validated.
Impact: Cookie replay after logout, exposure over plain HTTP, and stale privileges.
Test:
Log in, copy the cookie, log out, then replay the cookie on /me.
Inspect the Set-Cookie attributes.
Uncertainty: Default cookie flags depend on the Flask version and the deployment, such as whether a TLS-terminating proxy is in front.
F11 — No brute-force protection (login)
Code fact: There is no rate limiting, lockout, or delay on login attempts.
Impact: Combined with weak passwords, online guessing is practical.
Test: Make N rapid failed logins and observe whether any throttling or lockout occurs. The expected secure behaviour is that it does.
Note: Upstream controls such as a WAF or reverse proxy are unknown.
F12 — CSRF on login/logout
Code fact: /login accepts form-encoded POST without a CSRF token or Origin check.
Impact: A cross-site form can log the victim into an attacker’s account (login CSRF), or force a logout.
Why it is low: /grades/update requires JSON. That limits classic cross-site forging, and since F2 needs no session at all, CSRF is moot there.
Test: Submit a cross-origin HTML form to /login, then check the victim’s /me.
F13 — No audit logging; unsynchronized shared state
Code facts:
Grade changes are not logged.
GRADES is a global list, mutated without a lock.
Inferred requirement: Grade changes should be non-repudiable and attributable.
Impact:
No forensic trail for F2 abuse.
Possible lost or duplicate updates under a threaded server. This depends on the server and is low impact for an in-memory demo.
Test:
Review the code for logging.
Send concurrent updates to the same (student_id, course_id) and check for duplicate rows.
Notes and limits
Attack chain: The highest-risk combination is F1, then F5 and F9 (secrets from the source), then F6 (PIN inputs leading to possible code execution), all reachable without authentication.
Not found: I found no SQL or command injection, and no open redirect (redirect("/me") is a constant). This reflects the code’s small surface, not proof of safety.
Out of scope: Dependencies, deployment configuration, TLS, and the versions behind version-dependent behaviours are unknown and could change severity.
Severity ratings are estimates under the assumed policy P1–P5. A real policy or threat model could raise or lower them.