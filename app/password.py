from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_mail import Message, Mail
from itsdangerous import URLSafeTimedSerializer
from flask import current_app
from .__init__ import create_app
from . import db, bcrypt, mail
from .forms import ForgotPasswordForm
from .models import User
 # Import the mail instance

password = Blueprint('password', __name__)


def get_serializer():
    """Create a URLSafeTimedSerializer instance within the app context."""
    return URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
def send_reset_email(user):
    s = get_serializer()  # Get the serializer within the app context
    token = s.dumps(user.email, salt='password-reset-salt')
    msg = Message('Password Reset Request',
                  sender='chamanyadav38113114@gmail.com',  # Use your email here
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('password.reset_token', token=token, _external=True)}

If you did not make this request, simply ignore this email.
    '''
    try:
        # Attempt to send the email
        mail.send(msg)
        print("Email sent successfully!")
    except Exception as e:
        print(f"Error sending email: {e}")
        flash(f"Failed to send email: {e}", 'danger')

@password.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()# Confirm the route is hit
    if form.validate_on_submit():
        print("Form submitted successfully")  # Debug statement
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        print(f"User found: {user}")  # Debug statement

        if user:
            print("User found, sending reset email")  # Confirm user is found
            # Send the password reset email
            send_reset_email(user)
            flash('Password changing link has been sent to your mail.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash('No such account exists, register yourself first.', 'danger')
    else:
        print("Form validation failed")
        print(form.errors)  # Debug statement
    return render_template('forgot_password.html',form=form)

@password.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    s = get_serializer()  # Get the serializer within the app context
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except Exception as e:
        flash('The token is either invalid or has expired.', 'danger')
        return redirect(url_for('home'))

    user = User.query.filter_by(email=email).first()

    if request.method == 'POST':
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated!', 'success')
        return redirect(url_for('auth.login'))

    return render_template('reset_password.html',token=token)


