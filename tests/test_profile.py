import sys
import os
# Add app path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from flask import url_for, session
from flask_login import login_user
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
        # Create admin user
        admin_user = User(
            username='admin',
            email='admin@example.com',
            password='admin123',
            role='admin',
            contact='1111111111',
            location='Admin City',
            dob=datetime(1990, 1, 1).date(),
            gender='male'
        )
        
        # Create a normal user
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

        db.session.add(admin_user)
        db.session.add(normal_user)
        db.session.commit()

        # Ensure instances are attached to the session
        db.session.refresh(admin_user)
        db.session.refresh(normal_user)

        return {
            "admin": admin_user,
            "user": normal_user
        }

def test_profile_access_as_owner(client, init_data):
    """Test profile access by the profile owner."""
    user = init_data["user"]

    # Log in as the normal user
    with client.session_transaction() as session:
        session['_user_id'] = user.id

    response = client.get(url_for('auth.profile', id=user.id))
    assert response.status_code == 200
    assert bytes(f"{user.username}'s Profile", 'utf-8') in response.data

def test_profile_access_as_admin(client, init_data):
    """Test profile access by an admin user."""
    admin = init_data["admin"]
    user = init_data["user"]

    # Log in as the admin user
    with client.session_transaction() as session:
        session['_user_id'] = admin.id

    response = client.get(url_for('auth.profile', id=user.id))
    assert response.status_code == 200
    assert bytes(f"{user.username}'s Profile", 'utf-8') in response.data

def test_profile_access_denied(client, init_data):
    """Test profile access denied for non-owner non-admin user."""
    user = init_data["user"]

    # Simulate not logged in
    with client.session_transaction() as session:
        session.clear()

    response = client.get(url_for('auth.profile', id=user.id), follow_redirects=False)
    assert response.status_code == 302  # Expecting a redirect to login


def test_profile_not_found(client, init_data):
    """Test profile access for a non-existent user."""
    admin = init_data["admin"]

    # Log in as the admin user
    with client.session_transaction() as session:
        session['_user_id'] = admin.id

    response = client.get(url_for('auth.profile', id=9999))  # Non-existent user ID
    assert response.status_code == 404
