import smtplib
import os
from flask import render_template, url_for, flash, redirect, request
from flask_login import login_required
from . import create_app, db
from .models import User
from flask import Blueprint
request = Blueprint('request', __name__)
@request.route('/admin/approve/<int:user_id>', methods=['POST'])
@login_required
def approve_user(user_id):
    user = User.query.get(user_id)
    if user:
        user.status = 'approved'
        db.session.commit()
        
        # Sending email with smtplib
        try:
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login('sameenamumtaz3@gmail.com', 'cjld vsca amph dqpm')  # Use your App Password
            message = f"Subject: Approval Notification\n\nDear {user.username},\n\nYour request has been approved. You can now log in."
            server.sendmail('sameenamumtaz3@gmail.com', user.email, message)
            server.quit()
            flash(f'{user.username} has been approved, and an email notification was sent.', 'success')
        except Exception as e:
            flash(f'{user.username} has been approved, but the email notification failed: {e}', 'warning')
    
    return redirect(url_for('admin.admin_dashboard'))




@request.route('/admin/reject/<int:user_id>', methods=['POST'])
@login_required
def reject_user(user_id):
    user = User.query.get(user_id)
    if user:
        try:
            # Sending email with smtplib
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login('sameenamumtaz3@gmail.com', 'cjld vsca amph dqpm')  # Use your App Password
            message = f"Subject: Rejection Notification\n\nDear {user.username},\n\nYour request has been rejected. Please register again."
            server.sendmail('sameenamumtaz3@gmail.com', user.email, message)
            server.quit()
            flash(f'{user.username} has been rejected, and an email notification was sent.', 'danger')
        except Exception as e:
            flash(f'{user.username} has been rejected, but the email notification failed: {e}', 'warning')
        
        # Deleting the user from the database
        try:
            db.session.delete(user)
            db.session.commit()
            flash(f'{user.username}\'s details have been removed from the database.', 'success')
        except Exception as e:
            flash(f'Failed to delete {user.username} from the database: {e}', 'danger')
    else:
        flash('User not found.', 'warning')
    
    return redirect(url_for('admin.admin_dashboard'))
