import copy

import pytest

import baseline_secure_coding_api as api


def login(client, username, password):
    response = client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert response.get_json()["user"] == username


def update(client, payload):
    return client.post("/grades/update", json=payload)


@pytest.fixture
def materials(tmp_path, monkeypatch):
    materials_dir = tmp_path / "materials"
    materials_dir.mkdir()
    (materials_dir / "notes.txt").write_text("allowed material")
    (tmp_path / "secret.txt").write_text("top secret")
    monkeypatch.setattr(api, "MATERIALS_DIR", materials_dir)
    return materials_dir


# Vulnerability 1 - Grade update authorization (/grades/update)

# R1 - Authentication (unauthenticated -> 401)

def test_update_requires_login(client):
    before = copy.deepcopy(api.GRADES)
    response = update(client, {"student_id": 1001, "course_id": "SRS", "grade": 0})
    assert response.status_code == 401
    assert api.GRADES == before


# R3/R4 - Authorization (authenticated but not allowed -> 403)

def test_student_cannot_update_grade(client):
    login(client, "alice", "alicepw")
    response = update(client, {"student_id": 1001, "course_id": "SRS", "grade": 20})
    assert response.status_code == 403
    assert api.find_grade(1001, "SRS")["grade"] == 14


def test_professor_cannot_update_other_course(client):
    login(client, "prof_srs", "profpw")
    response = update(client, {"student_id": 1001, "course_id": "SSD", "grade": 0})
    assert response.status_code == 403
    assert api.find_grade(1001, "SSD")["grade"] == 16


def test_admin_can_update_any_course(client):
    login(client, "admin1", "adminpw")
    response = update(client, {"student_id": 1001, "course_id": "SSD", "grade": 19})
    assert response.status_code == 200
    assert api.find_grade(1001, "SSD")["grade"] == 19


# Vulnerability 2 - File access / path traversal (/files)

# R1 - Authentication (unauthenticated -> 401)

def test_files_require_login(client, materials):
    response = client.get("/files?path=notes.txt")
    assert response.status_code == 401
    assert b"allowed material" not in response.data


# R6 - File access

def test_user_can_download_material(client, materials):
    login(client, "alice", "alicepw")
    response = client.get("/files?path=notes.txt")
    assert response.status_code == 200
    assert response.data == b"allowed material"


def test_path_traversal_blocked(client, materials):
    login(client, "alice", "alicepw")
    response = client.get("/files?path=../secret.txt")
    assert response.status_code in (400, 403, 404)
    assert b"top secret" not in response.data


def test_absolute_path_blocked(client, materials):
    login(client, "alice", "alicepw")
    response = client.get("/files", query_string={"path": str(materials.parent / "secret.txt")})
    assert response.status_code in (400, 403, 404)
    assert b"top secret" not in response.data


# R7 - Error handling

def test_missing_file_does_not_expose_path(client, materials):
    login(client, "alice", "alicepw")
    response = client.get("/files?path=nao-existe.txt")
    assert response.status_code == 404
    assert str(materials) not in response.get_data(as_text=True)
