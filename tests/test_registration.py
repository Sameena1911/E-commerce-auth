import sys
import os
# Add app path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from datetime import date  # Import date class for handling dob
from flask import url_for
from flask_login import login_user
from flask_testing import TestCase
import pytest
from app import create_app, db
from app.models import User

@pytest.fixture
def app():
    """Create a Flask application instance for testing."""
    app = create_app()
    app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",  # Use in-memory SQLite for testing
        "WTF_CSRF_ENABLED": False,  # Disable CSRF for easier form testing
    })
    
    # Set up the database
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    """Provide a test client for the app."""
    return app.test_client()

@pytest.fixture
def runner(app):
    """Provide a test CLI runner for the app."""
    return app.test_cli_runner()

def test_register_success(client):
    """Test successful registration."""
    response = client.post(
        url_for('auth.register'),
        data={
            'username': 'testuser',
            'email': 'testuser@example.com',
            'password': 'password123',
            'confirm_password': 'password123',
            'role': 'customer',
            'contact': '1234567890',
            'location': 'Test City',
            'dob': '2000-01-01',
            'gender': 'male'
        },
        follow_redirects=True
    )
    assert response.status_code == 200
    assert b'Registration successful!' in response.data

    # Verify the user is added to the database
    with client.application.app_context():
        user = User.query.filter_by(email='testuser@example.com').first()
        assert user is not None
        assert user.username == 'testuser'

def test_register_missing_field(client):
    """Test registration with missing fields."""
    response = client.post(
        url_for('auth.register'),
        data={
            'username': '',
            'email': 'testuser@example.com',
            'password': 'password123',
            'confirm_password': 'password123',
            'role': 'customer',
            'contact': '1234567890',
            'location': 'Test City',
            'dob': '2000-01-01',
            'gender': 'male'
        },
        follow_redirects=True
    )
    assert response.status_code == 200
    assert b'This field is required.' in response.data  # Check for form validation error

def test_register_password_mismatch(client):
    """Test registration with mismatched passwords."""
    response = client.post(
        url_for('auth.register'),
        data={
            'username': 'testuser',
            'email': 'testuser@example.com',
            'password': 'password123',
            'confirm_password': 'password321',  # Mismatched passwords
            'role': 'customer',
            'contact': '1234567890',
            'location': 'Test City',
            'dob': '2000-01-01',
            'gender': 'male'
        },
        follow_redirects=True
    )
    assert response.status_code == 200
    assert b'Passwords must match.' in response.data

def test_register_duplicate_email(client):
    """Test registration with an email that already exists."""
    # Create a user in the database
    with client.application.app_context():
        user = User(
            username='existinguser',
            email='existing@example.com',
            password='hashedpassword',
            role='admin',
            contact='1234567890',
            location='Existing City',
            dob=date(1990, 1, 1),
            gender='female'
        )
        db.session.add(user)
        db.session.commit()

    # Attempt to register with the same email
    response = client.post(
        url_for('auth.register'),
        data={
            'username': 'newuser',
            'email': 'existing@example.com',
            'password': 'newpassword123',
            'confirm_password': 'newpassword123',
            'role': 'customer',
            'contact': '0987654321',
            'location': 'New City',
            'dob': '1995-05-15',
            'gender': 'male'
        },
        follow_redirects=True
    )
    assert response.status_code == 200
    assert b'This email is already registered.' in response.data


def test_register_invalid_email_format(client):
    """Test registration with an invalid email format."""
    
    # Simulate form data with an invalid email
    response = client.post(
        url_for('auth.register'),
        data={
            'username': 'testuser',
            'email': 'invalid-email',  # Invalid email format
            'password': 'password123',
            'confirm_password': 'password123',
            'role': 'customer',
            'contact': '1234567890',
            'location': 'Test City',
            'dob': '2000-01-01',
            'gender': 'male'
        },
        follow_redirects=True
    )

    # Assert that the form submission returns a 200 status code (success).
    assert response.status_code == 200

    # Check if the error message for invalid email format is rendered.
    assert b'Enter a valid email address.' in response.data



