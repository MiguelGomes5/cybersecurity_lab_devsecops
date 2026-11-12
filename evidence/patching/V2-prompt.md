We are now repairing a confirmed vulnerability in the supplied application.
This is repair assistance, not an independent discovery review.

Confirmed finding:
V2 - Path traversal and missing authentication on file downloads (GET /files)

Affected code: baseline_secure_coding_api.py, function download_file(),
and the global error handler handle_error().

Root cause: download_file() builds the target as MATERIALS_DIR / raw_path,
where raw_path comes directly from the "path" query parameter, and passes it
to flask.send_file() without checking that the resolved path stays inside
MATERIALS_DIR. "../" sequences escape the directory, and an absolute path
replaces MATERIALS_DIR entirely (pathlib "/" semantics). The endpoint also
does not require login. When the file does not exist, the exception reaches
handle_error(), which returns a 500 with str(exc), exposing the absolute
server path.

Reproduction (Flask test client, tests_security/test_security_requirements.py).
The tests use tmp_path and monkeypatch api.MATERIALS_DIR to a temporary
"materials" directory containing notes.txt, with secret.txt one level above it:
- Logged in as alice, GET /files?path=../secret.txt
  -> expected 400/403/404, got 200 with the contents of secret.txt.
- Logged in as alice, GET /files?path=<absolute path of secret.txt>
  -> expected 400/403/404, got 200 with the contents of secret.txt.
- No login, GET /files?path=notes.txt
  -> expected 401, got 200.
- Logged in as alice, GET /files?path=nao-existe.txt
  -> expected 404, got 500 with the absolute path in the body.

CI failure output (security-regression job, before patching):
test_files_require_login                 assert 200 == 401
test_path_traversal_blocked              assert 200 in (400, 403, 404)
test_absolute_path_blocked               assert 200 in (400, 403, 404)
test_missing_file_does_not_expose_path   assert 500 == 404

Required behavior:
R1 - Material downloads require an authenticated user.
R6 - Authenticated users may download teaching materials within the
     materials directory. Requests must not read files outside that directory.
R7 - Invalid requests must return appropriate client errors without exposing
     internal paths, tracebacks, or implementation exception details.
     Unauthenticated protected requests return 401.

Legitimate use case that must keep working:
- Any logged-in user downloads a file inside the materials directory
  (e.g. GET /files?path=notes.txt) -> 200 with the file contents.

Constraint: the tests replace api.MATERIALS_DIR with monkeypatch, so the
function must use the module-level MATERIALS_DIR at request time.

Propose a minimal, reviewable patch addressing the root cause.
Preserve the API's legitimate functionality and relevant response contracts.
Do not delete endpoints, disable features, weaken tests, or suppress scanner
rules to hide the issue. Identify all affected paths that need the same
control.

Return a unified diff, explain the control being implemented, and identify
remaining assumptions or limitations. Suggest additional regression tests.

Attached:
- baseline_secure_coding_api.py (already including the applied V1 patch)
- tests_security/conftest.py
- tests_security/test_security_requirements.py
