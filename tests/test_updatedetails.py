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

def test_update_details_as_owner(client, init_data):
    """Test that a user can update their own details."""
    user = init_data["user"]

    # Log in as the normal user
    with client.session_transaction() as session:
        session['_user_id'] = user.id

    # Prepare new data for the update
    updated_data = {
        'username': 'updateduser',
        'email': 'updateduser@example.com',    
        'contact': '9876543210',
        'location': 'Updated City',
        'dob': '1995-05-15',
        'gender': 'Male'
    }

    # Send POST request to update the details  
    response = client.post(url_for('auth.update_details', id=user.id), data=updated_data)

    # Follow the redirect to the profile page
    response = client.get(response.headers['Location'])

    # Check for the success message
    assert b"User details updated successfully." in response.data  # Check if the success message appears
    assert b'updateduser' in response.data  # Verify updated username
    assert b'updateduser@example.com' in response.data  # Verify updated email

def test_update_details_as_admin(client, init_data):
    """Test that an admin can update user details."""
    admin = init_data["admin"]
    user = init_data["user"]

    # Log in as the admin user
    with client.session_transaction() as session:
        session['_user_id'] = admin.id

    # Prepare new data for the update
    updated_data = {
        'username': 'adminupdateduser',        
        'email': 'adminupdateduser@example.com',
        'contact': '1231231234',
        'location': 'Admin Updated City',      
        'dob': '1995-05-15',
        'gender': 'Female',
        'role': 'customer'  # Only admin can change the role
    }

    # Send POST request to update the details  
    response = client.post(url_for('auth.update_details', id=user.id), data=updated_data)

    # Follow the redirect to the profile page
    response = client.get(response.headers['Location'])

    # Check for the success message
    assert b"User details updated successfully." in response.data  # Check if the success message appears
    assert b'adminupdateduser' in response.data  # Verify updated username
    assert b'adminupdateduser@example.com' in response.data  # Verify updated email

def test_update_details_invalid_data(client, init_data):
    """Test that invalid form data returns an error."""
    user = init_data["user"]

    # Log in as the user
    with client.session_transaction() as session:
        session['_user_id'] = user.id

    # Prepare invalid data (missing required fields)
    invalid_data = {
        'username': '',
        'email': ''  # Both username and email are required
    }

    # Send POST request with invalid data      
    response = client.post(url_for('auth.update_details', id=user.id), data=invalid_data)

    # Follow the redirect back to the update page
    response = client.get(response.headers['Location'])

    # Check if the error message appears       
    assert b"Username and Email are required." in response.data



def test_update_details_denied_for_non_owner_and_non_admin(client, init_data):
    """Test that a non-owner and non-admin user cannot update details."""
    user = init_data["user"]
    another_user = User(
        username='anotheruser',
        email='anotheruser@example.com',
        password='password123',
        role='customer',
        contact='2223334444',
        location='Another City',
        dob=datetime(1990, 1, 1).date(),
        gender='other'
    )
    db.session.add(another_user)
    db.session.commit()