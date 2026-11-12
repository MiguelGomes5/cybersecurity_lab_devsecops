import baseline_secure_coding_api as api

def login(client, username, password):
 response = client.post(
 "/login",
 data={"username": username, "password": password},
 follow_redirects=True,
 )
 assert response.status_code == 200
 assert response.get_json()["user"] == username
def test_assigned_professor_can_update_grade(client):
 login(client, "prof_srs", "profpw")
 response = client.post(
 "/grades/update",
 json={"student_id": 1001, "course_id": "SRS", "grade": 18},
 )
 assert response.status_code == 200
 assert api.find_grade(1001, "SRS")["grade"] == 18