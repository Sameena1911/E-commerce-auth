import sys
import os
# Add app path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import pytest
from flask import url_for, session, flash, redirect
from flask_testing import TestCase
from app import create_app, db, bcrypt
from app.models import User
from flask_mail import Message
from app.auth import send_password_change_email
from unittest.mock import patch
from datetime import date, datetime
from flask_bcrypt import Bcrypt

# Fixture to set up the application and database
@pytest.fixture
def app():
    app = create_app()
    app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "WTF_CSRF_ENABLED": False,  # Disable CSRF for easier form testing
        "MAIL_SUPPRESS_SEND": True,  # Disable email sending during tests
    })
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def init_data(app):
    """Initialize the database with a test user."""
    with app.app_context():
        # Create a hashed password
        hashed_password = bcrypt.generate_password_hash('password123').decode('utf-8')

        # Ensure that all required fields are set, including `contact`, `location`, `dob`, and `gender`
        user = User(
            username='testuser',
            email='testuser@example.com', 
            password=hashed_password,  # Use the hashed password here
            role='customer',
            contact='1234567890',  # Providing a contact number
            location='Test City',  # Providing a location
            dob=datetime(1990, 1, 1).date(),  # Providing a date of birth
            gender='male'  # Providing gender
        )

        # Add the user to the session and commit
        db.session.add(user)
        db.session.commit()

        # Make sure the user is reloaded into the session to avoid detachment
        db.session.refresh(user)

        return user


# Test case for incorrect current password
def test_change_password_incorrect_current(client, init_data):
    user = init_data
    with client.session_transaction() as session:
        session['_user_id'] = user.id

    # Simulate a POST request with an incorrect current password
    response = client.post(url_for('auth.change_password'), data={
        'current-password': 'wrongpassword',
        'new-password': 'newpassword123',
        'confirm-password': 'newpassword123'
    }, follow_redirects=True)

    # Assert that an error message is shown for the incorrect password
    assert response.status_code == 200
    assert b"Current password is incorrect!" in response.data

# Test case for new password and confirm password mismatch
def test_change_password_mismatch(client, init_data):
    user = init_data
    with client.session_transaction() as session:
        session['_user_id'] = user.id

    # Simulate a POST request with mismatched new password and confirm password
    response = client.post(url_for('auth.change_password'), data={
        'current-password': 'password123',
        'new-password': 'newpassword123',
        'confirm-password': 'mismatchpassword123'
    }, follow_redirects=True)

    # Assert that an error message is shown for password mismatch
    assert response.status_code == 200
    assert b"New password and confirm password do not match!" in response.data

# Test case for access control (ensuring user must be logged in)
def test_change_password_not_logged_in(client, init_data):
    # Simulate not logged in
    with client.session_transaction() as session:
        session.clear()

    # Attempt to access the change password page
    response = client.get(url_for('auth.change_password'), follow_redirects=True)

    # Assert that the user is redirected to the login page
    assert response.status_code == 200
    assert b"Please log in to access this page" in response.data

# Test case for sending the password change email (mocking the email sending)
@patch('app.auth.send_password_change_email')
def test_send_password_change_email(mock_send_email, client, init_data):
    user = init_data
    with client.session_transaction() as session:
        session['_user_id'] = user.id

    # Simulate a POST request to change the password
    client.post(url_for('auth.change_password'), data={
        'current-password': 'password123',
        'new-password': 'newpassword123',
        'confirm-password': 'newpassword123'
    })

    # Assert that the email sending function is called
    mock_send_email.assert_called_once_with(user)
