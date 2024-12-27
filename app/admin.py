from flask import Blueprint, render_template, flash, redirect, url_for, session
from .models import User
from flask_login import login_required
from . import db, bcrypt
from datetime import datetime

admin = Blueprint('admin', __name__)

def create_admin_user():
    admin = User.query.filter_by(email='admin@gmail.com').first()
    if not admin:
        hashed_password = bcrypt.generate_password_hash('admin123').decode('utf-8')
        new_admin = User(
            username='admin',
            email='admin@gmail.com',
            password=hashed_password,
            role='admin',
            contact='1234567890',
            location='Admin Location',
            dob=datetime(1990, 1, 1).date(),
            gender='male'
        )
        db.session.add(new_admin)
        db.session.commit()

@admin.route('/admin_dashboard')
def admin_dashboard():
    if session.get('role') != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('auth.login'))
    delivery_requests = User.query.filter_by(role='delivery_person', status='pending').all()
    return render_template('admin.html',delivery_requests=delivery_requests ,username=session.get('username'))
