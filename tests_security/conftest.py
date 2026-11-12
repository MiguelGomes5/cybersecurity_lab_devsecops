import copy
import pytest
import baseline_secure_coding_api as api

@pytest.fixture(autouse=True)
def restore_grades():
    original = copy.deepcopy(api.GRADES)
    yield
    api.GRADES[:] = original
 
@pytest.fixture
def client():
    with api.app.test_client() as client:
        yield client