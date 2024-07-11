import pytest
from flask_jwt_extended import create_access_token
import time
from models import User, Organisation, jwt, app
from tests.conftest import client


def test_token_generation(client):
    user_id = 1
    token = create_access_token(identity=user_id)
    payload = jwt.decode(token, app.config['SECRET_KEY'])
    assert payload['user_id'] == user_id
    assert payload['exp'] > time.time()

def test_token_expiration():
    user_id = 1
    token = create_access_token(identity=user_id, expires_in=1)
    time.sleep(2)
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
    token = create_access_token(identity=user_id, expires_in=60)
    payload = jwt.decode(token, app.config['SECRET_KEY'])
    assert payload['user_id'] == user_id
    assert payload['exp'] > time.time()

def test_organisation_access_control():
    user = User.query.get(1)
    organisation = Organisation.query.get(2)
    with pytest.raises(AssertionError):
        organisation.users.append(user)
    assert user not in organisation.users



@pytest.mark.parametrize("data, expected_status, expected_message", [
    ({'first_name': 'John', 'last_name': 'Doe', 'email': 'john@example.com', 'password': 'password'}, 201, 'Registration successful'),
    ({'first_name': 'John', 'last_name': 'Doe', 'email': '', 'password': 'password'}, 422, 'Validation error'),
    ({'first_name': 'John', 'last_name': 'Doe', 'email': 'john@example.com', 'password': ''}, 422, 'Validation error'),
    ({'first_name': '', 'last_name': 'Doe', 'email': 'john@example.com', 'password': 'password'}, 422, 'Validation error'),
    ({'first_name': 'John', 'last_name': '', 'email': 'john@example.com', 'password': 'password'}, 422, 'Validation error'),
    ({'first_name': 'John', 'last_name': 'Doe', 'email': 'john@example.com', 'password': 'password', 'organisation_name': 'My Organisation'}, 201, 'Registration successful'),
    ({'first_name': 'John', 'last_name': 'Doe', 'email': 'john@example.com', 'password': 'password', 'organisation_name': 'My Organisation', 'user_id': 1}, 422, 'User with this email already exists.'),
])
def test_register_endpoint(data, expected_status, expected_message):
    response = client.get("/auth/register")
    assert response.status_code == expected_status 
    assert response.json()['message'] == expected_message
    if expected_status == 201:
        assert 'access_token' in response.json()
        assert 'user' in response.json()
        assert response.json()['user']['firstName'] == data['first_name']
        assert response.json()['user']['lastName'] == data['last_name']
        assert response.json()['user']['email'] == data['email']

def test_login_endpoint(client):
    response = client.get("/auth/register")
    data = {'email': 'john@example.com', 'password': 'password'}
    response = app.post('/auth/login', json=data)
    assert response.status_code == 200
    assert response.json()['message'] == 'Login successful'

    data = {'email': 'john@example.com', 'password': 'invalid_password'}
    response = app.post('/auth/login', json=data)
    assert response.status_code == 401
    assert response.json()['message'] == 'Authentication failed'