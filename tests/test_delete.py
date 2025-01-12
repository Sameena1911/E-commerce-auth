import sys
import os
# Add app path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from flask import url_for, session, flash
from flask_login import login_user, current_user
from flask_testing import TestCase
import pytest
from app import create_app, db
from app.models import User
from datetime import datetime
from flask_bcrypt import Bcrypt
# Fixtures for app, client, and initial test data
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
    bcrypt = Bcrypt(app)  # Initialize bcrypt with app context
    with app.app_context():
        # Create admin user with hashed password
        admin_user = User(
            username='admin',
            email='admin@example.com',
            password=bcrypt.generate_password_hash('admin123').decode('utf-8'),
            role='admin',
            contact='1111111111',
            location='Admin City',
            dob=datetime(1990, 1, 1).date(),
            gender='male'
        )
        
        # Create normal user with hashed password
        normal_user = User(
            username='testuser',
            email='testuser@example.com',
            password=bcrypt.generate_password_hash('password123').decode('utf-8'),
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

def test_confirm_delete_as_admin(client, init_data):
    """Test account deletion attempt by an admin for another user (should fail)."""
    admin = init_data["admin"]
    user = init_data["user"]

    # Log in as admin user
    with client.session_transaction() as session:
        session['_user_id'] = admin.id

    # Admin should not be able to delete a user's account
    response = client.post(url_for('auth.confirm_delete', id=user.id), data={
        'password': 'password123'
    })
    assert response.status_code == 403  # Forbidden error

def test_confirm_delete_not_logged_in(client, init_data):
    """Test account deletion when user is not logged in."""
    user = init_data["user"]

    # Simulate not logged in
    with client.session_transaction() as session:
        session.clear()

    response = client.get(url_for('auth.confirm_delete', id=user.id), follow_redirects=False)
    assert response.status_code == 302  # Expecting redirect to login page
    
    
    
def test_confirm_delete_access_control(client, init_data):
    """Test that a user cannot delete another user's account."""
    user = init_data["user"]
    other_user = User(
        username='otheruser',
        email='otheruser@example.com',
        password='password123',
        role='customer',
        contact='0987654321',
        location='Other City',
        dob=datetime(1995, 5, 5).date(),
        gender='female'
    )
    db.session.add(other_user)
    db.session.commit()    
def test_confirm_delete_nonexistent_user(client, init_data):
    """Test account deletion attempt for a non-existent user."""
    admin = init_data["admin"]

    # Log in as admin user
    with client.session_transaction() as session:
        session['_user_id'] = admin.id

    response = client.get(url_for('auth.confirm_delete', id=9999))  # Non-existent user ID

    # Expect a redirect to login page
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]

def test_confirm_delete_incorrect_password(client, init_data):
    """Test account deletion with incorrect password."""
    user = init_data["user"]

    # Log in as the normal user
    with client.session_transaction() as session:
        session['_user_id'] = user.id

    # Attempt to delete account with incorrect password
    response = client.post(url_for('auth.confirm_delete', id=user.id), data={
        'password': 'wrongpassword'
    })

    # Expect a redirect to the confirmation page again, not login
    assert response.status_code == 302
    assert "/auth/confirm_delete" in response.headers["Location"]
