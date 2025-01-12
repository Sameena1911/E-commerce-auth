import sys
import os
# Add app path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


from flask import url_for, session
from flask_login import login_user,current_user
from flask_testing import TestCase
import pytest
from app import create_app, db
from app.models import User
from datetime import date,datetime
from sqlalchemy.orm import make_transient

@pytest.fixture
def app():
    """Create a Flask application instance for testing."""
    app = create_app()
    app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
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
def init_data(app):
    """Set up initial test data."""
    with app.app_context():
        # Create a normal user for testing
        normal_user = User(
            username='testuser',
            email='testuser@example.com',
            password='password123',
            role='customer',
            contact='1234567890',
            location='Test City',
            dob=datetime(2000, 1, 1).date(),
            gender='female'
        )
        db.session.add(normal_user)
        db.session.commit()

        # Ensure instances are attached to the session
        db.session.refresh(normal_user)

        return {
            "user": normal_user
        }


def test_logout(client, init_data):
    """Test the logout functionality."""
    user = init_data["user"]

    # Log in as the normal user       
    with client.session_transaction() as session:
        session['_user_id'] = user.id 

    # Ensure user is logged in by checking the session
    with client.session_transaction() as session:
        assert session['_user_id'] == user.id

    # Request logout
    response = client.get(url_for('auth.logout'))

    # Assert that user is redirected to the home page or login page after logout
    assert response.status_code == 200
    assert b"You have been logged out." in response.data  # Check if flash message appears

    # Check if session is cleared (user is logged out)
    with client.session_transaction() as session:
        assert '_user_id' not in session


def test_logout_without_login(client):
    """Test the logout functionality when user is not logged in."""
    response = client.get(url_for('auth.logout'))
    
    # Assert that the response redirects to the login page with the 'next' parameter
    assert response.status_code == 302  # Redirect
    # Check that the location includes the 'next' query parameter with the current URL
    assert '/auth/login' in response.location
    assert 'next=%2Fauth%2Flogout' in response.location

def test_logout_flash_message(client, init_data):
    """Test that a flash message appears when logging out."""
    user = init_data["user"]

    # Log in as the user
    with client.session_transaction() as session:
        session['_user_id'] = user.id

    # Request logout
    response = client.get(url_for('auth.logout'))

    # Ensure the flash message is present in the response data
    assert b'You have been logged out.' in response.data