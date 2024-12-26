from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required
from .forms import RegistrationForm, LoginForm
from flask_mail import Message
from .models import User
from . import db, bcrypt, mail


auth = Blueprint('auth', __name__)

@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    
    if form.validate_on_submit():
        # Hash the password
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        
        # Create a new user instance
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password=hashed_password,
            role=form.role.data,
            contact=form.contact.data,
            location=form.location.data,
            dob=form.dob.data,
            gender=form.gender.data
        )
        
        # Add the new user to the database
        db.session.add(new_user)
        db.session.commit()
        if form.role.data == 'delivery_person':
            flash('Registration successful! Your status is pending for admin approval.', 'info')
            return redirect(url_for('auth.login'))

        flash('Registration successful!', 'success')
        return redirect(url_for('auth.login'))
    print("Form errors:", form.errors)
    return render_template('register.html', form=form)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            if user.role == 'delivery_person' and user.status == 'pending':
                flash('Your request is pending approval. Please wait.', 'warning')
                return redirect(url_for('auth.login'))
            elif user.role == 'delivery_person' and user.status == 'rejected':
                flash('Your request was rejected. Please register again.', 'danger')
                return redirect(url_for('auth.register'))
            login_user(user)
             # Store username in the session
            session['username'] = user.username
            session['role'] = user.role
            if user.role == 'admin':
                return redirect(url_for('admin.admin_dashboard'))
            elif user.role == 'delivery_person':
                return redirect(url_for('main.delivery_dashboard'))
            return redirect(url_for('main.customer_dashboard'))
        flash('Invalid email or password.', 'danger')
    return render_template('login.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))
