import sys
import os
# Add app path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from datetime import date
from flask import Flask
from flask.testing import FlaskClient
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy
from app import create_app, db
from app.models import User
from app.password import send_reset_email
from unittest.mock import patch

# Configure the Flask app for testing
@pytest.fixture
def app():
    app = create_app()
    
    # Disable CSRF protection for testing purposes
    app.config['WTF_CSRF_ENABLED'] = False

    # Override the database URI to use a testing database
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
    app.config['TESTING'] = True
    app.config['MAIL_SUPPRESS_SEND'] = True  # Don't send real emails during testing
    app.config['MAIL_DEFAULT_SENDER'] = 'test@example.com'  # Default sender for tests
    
    with app.app_context():
        db.create_all()  # Set up the database before the test
        yield app
        db.drop_all()  # Clean up after the test

# Provide the Flask test client
@pytest.fixture
def client(app: Flask):
    return app.test_client()

# Create a test user to use in our tests
@pytest.fixture
def test_user(app: Flask):
    user = User(
        username='testuser',
        email='test@example.com',
        password='password',
        role='user',
        contact='1234567890',
        location='Test Location',
        dob=date(1990, 1, 1),  # Use a datetime.date object here
        gender='M'
    )
    db.session.add(user)
    db.session.commit()
    return user

# Test the Forgot Password form
def test_forgot_password(client: FlaskClient, test_user: User):
    # Test valid email input
    response = client.post('/password/forgot_password', data={'email': 'test@example.com'}, follow_redirects=True)
    assert b"Password changing link has been sent to your mail." in response.data

    # Test invalid email input
    response = client.post('/password/forgot_password', data={'email': 'nonexistent@example.com'}, follow_redirects=True)
    assert b"No such account exists, register yourself first." in response.data

# Test that the user can be created
def test_user_creation(app: Flask):
    user = User(
        username='newuser',
        email='newuser@example.com',
        password='password',
        role='user',
        contact='9876543210',
        location='New Location',
        dob=date(1995, 1, 1),  # Correctly using datetime.date
        gender='F'
    )
    db.session.add(user)
    db.session.commit()

    created_user = User.query.filter_by(email='newuser@example.com').first()
    assert created_user is not None
    assert created_user.username == 'newuser'

# Test the email sending function (mocked)
@patch('app.password.mail.send')
def test_send_reset_email(mock_send, test_user: User):
    # Call the function to send the email
    send_reset_email(test_user)
    
    # Verify that the email sending function was called
    mock_send.assert_called_once()
    
    # Check that the email has the correct recipient and body content
    msg = mock_send.call_args[0][0]
    assert msg.recipients == ['test@example.com']
    assert 'To reset your password' in msg.body
    assert 'If you did not make this request, simply ignore this email.' in msg.body


