from flask import Blueprint, render_template, redirect, url_for, flash, request, session, abort
from flask_login import login_user, logout_user, login_required, current_user
from .forms import RegistrationForm, LoginForm
from flask_mail import Message
from .models import User
import logging
from datetime import datetime
from . import db, bcrypt, mail, logger
from werkzeug.security import check_password_hash, generate_password_hash

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
            session['logged_in'] = True
            session['username'] = user.username
            session['user_id'] = user.id
            session['role'] = user.role
            if user.role == 'admin':
                return redirect(url_for('main.admin'))
            elif user.role == 'delivery_person':
                return redirect(url_for('main.home'))
            return redirect(url_for('main.home'))
        flash('Invalid email or password.', 'danger')
    return render_template('login.html', form=form)

@auth.route('/profile/<int:id>')
@login_required
def profile(id):
    # Fetch the user with the given ID from the database
    user = User.query.get(id)

    # If the user doesn't exist, return a 404 page
    if not user:
        abort(404)

    # Access control: Allow only the owner or admin
    from flask_login import current_user
    if current_user.id != id and current_user.role != 'admin':
        abort(403)

    # Render the profile.html template with the user's data
    return render_template('profile.html', user=user)


@auth.route('/update_details/<int:id>', methods=['GET', 'POST'])
@login_required
def update_details(id):
    # Fetch the user to update
    user = User.query.get(id)
    if not user:
        flash("User not found.", "error")
        return redirect(url_for('main.profile'))  # Redirect to an appropriate route
    
    # Access control: Only the user or an admin can update details
    if current_user.id != id and current_user.role != 'admin':
        abort(403)

    if request.method == 'POST':
        # Get form data
        username = request.form.get('username')
        email = request.form.get('email')
        contact = request.form.get('contact')
        location = request.form.get('location')
        dob = request.form.get('dob')
        gender = request.form.get('gender')
        role = request.form.get('role') if current_user.role == 'admin' else user.role  # Only admins can update roles

        # Validate required fields
        if not username or not email:
            flash("Username and Email are required.", "error")
            return redirect(url_for('auth.update_details', id=id))
        
        # Validate and process date of birth
        if dob:
            try:
                dob = datetime.strptime(dob, "%Y-%m-%d").date()
            except ValueError:
                flash("Invalid date format. Please use YYYY-MM-DD.", "error")
                return redirect(url_for('auth.update_details', id=id))
        
        # Validate gender
        valid_genders = ['Male', 'Female', 'Other', 'Prefer not to say']
        if gender and gender not in valid_genders:
            flash("Invalid gender selection.", "error")
            return redirect(url_for('auth.update_details', id=id))

        try:
            # Update user details
            user.username = username
            user.email = email
            user.contact = contact
            user.location = location
            user.dob = dob
            user.gender = gender
            user.role = role

            # Commit changes to the database
            db.session.commit()
            flash("User details updated successfully.", "success")
            return redirect(url_for('main.profile'))  # Redirect to an appropriate route
        except Exception as e:
            logger.error(f"Error updating user details for user {id}: {e}")
            db.session.rollback()
            flash("An error occurred while updating the details. Please try again.", "error")
            return redirect(url_for('auth.update_details', id=id))

    # Render the update details form
    return render_template('update_details.html', user=user)



@auth.route('/confirm_delete/<int:id>', methods=['GET', 'POST'])
@login_required
def confirm_delete(id):
    # Fetch the user to delete
    user = User.query.get(id)
    if not user:
        flash("User not found.", "error")
        return redirect(url_for('auth.profile', id=current_user.id))  # Redirect to profile
    
    # Access control: Only the user themselves can delete their account
    if current_user.id != id:
        abort(403)
    
    if request.method == 'POST':
        password = request.form.get('password')
        
        # Verify the password
        if not bcrypt.check_password_hash(user.password, password):
            flash("Incorrect password. Account deletion canceled.", "error")
            return redirect(url_for('auth.confirm_delete', id=id))
        
        try:
            # Delete the user from the database
            db.session.delete(user)
            db.session.commit()
            
            # Log out the user
            logout_user()
            session.clear()
            
            flash("Your account has been deleted successfully.", "success")
            return render_template('home.html')
        except Exception as e:
            logger.error(f"Error deleting user {id}: {e}")
            db.session.rollback()
            flash("An error occurred while deleting your account. Please try again.", "error")
            return redirect(url_for('auth.confirm_delete', id=id))
    
    # Render the confirmation page
    return render_template('confirm_delete.html', user=user)




@auth.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash('You have been logged out.', 'info')
    return render_template('home.html')
