import pytest
from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_app_exists():
    assert app is not None

def test_user_route(client):
    response = client.get('/user?id=1')
    assert response.status_code == 200

def test_safe_user_route(client):
    response = client.get('/user/safe?id=1')
    assert response.status_code == 200

def test_ping_route_exists(client):
    response = client.get('/ping?host=localhost')
    assert response.status_code in [200, 500]

def test_ping_invalid_host(client):
    response = client.get('/ping?host=; rm -rf /')
    assert response.status_code == 400

def test_file_route_blocked(client):
    response = client.get('/file?name=../../etc/passwd')
    assert response.status_code == 403

def test_file_route_blocked_unknown(client):
    response = client.get('/file?name=unknown.txt')
    assert response.status_code == 403

def test_file_route_allowed_not_found(client):
    response = client.get('/file?name=report')
    assert response.status_code in [200, 500]
