import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from flask import url_for, session
from flask_testing import TestCase
import pytest
from app import create_app, db, bcrypt
from datetime import datetime
from app.models import User
from werkzeug.security import generate_password_hash
from flask_bcrypt import Bcrypt

@pytest.fixture
def app():
    """Create a Flask application instance for testing."""
    app = create_app()
    app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "WTF_CSRF_ENABLED": False, 
        "SECRET_KEY": 'mysecretkey',
    })

    with app.app_context():
        db.create_all()
        # Create a test user
        hashed_password = bcrypt.generate_password_hash('testpassword').decode('utf-8')
        test_user = User(
            username='testuser',
            email='testuser@example.com',
            password=hashed_password,
            role='user',
            contact='1234567890',
            location='Test Location',
            dob=datetime.strptime('2000-01-01', '%Y-%m-%d').date(),
            gender='Other'
        )
        db.session.add(test_user)
        db.session.commit()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    """Provide a test client for the app."""
    return app.test_client()

class TestLogin:
    # def test_login_success(self, client):
    #     """Test successful login."""
    #     response = client.post(
    #         url_for('auth.login'),
    #         data={
    #             'email': 'testuser@example.com',
    #             'password': 'testpassword'
    #         },
    #         follow_redirects=True        
    #     )

    #     # Check if the login was successful (by redirecting to home page)
    #     assert response.status_code == 200
    #     assert response.request.path == url_for('main.home')

    #     # Check if the flash message is in the response data
    #     assert b'Login successful!' in response.data, "Flash message not found in response!"
        
    #     # Check if session values are set correctly (debug step)
    #     with client.session_transaction() as sess:
    #         assert 'role' in sess
    #         assert sess['role'] == 'user'
    #         assert 'user_id' in sess
    #         assert 'username' in sess

    def test_login_empty_form(self, client):
        """Test login with an empty form."""
        response = client.post(
            url_for('auth.login'),
            data={},  # Empty form data
            follow_redirects=True
        )
        assert b'This field is required.' in response.data
        assert response.status_code == 200


    def test_login_invalid_email(self, client):
        """Test login with an invalid email."""
        response = client.post(
            url_for('auth.login'),
            data={
                'email': 'wrongemail@example.com',
                'password': 'testpassword'
            },
            follow_redirects=True
        )
        assert b'Invalid email or password!' in response.data
        assert response.status_code == 200

    def test_login_invalid_password(self, client):
        """Test login with an invalid password."""
        response = client.post(
            url_for('auth.login'),
            data={
                'email': 'testuser@example.com',
                'password': 'wrongpassword'
            },
            follow_redirects=True
        )
        assert b'Invalid email or password!' in response.data
        assert response.status_code == 200


    def test_login_get_request(self, client):
        """Test accessing the login page with a GET request."""
        response = client.get(url_for('auth.login'))
        assert b'Login' in response.data
        assert response.status_code == 200
