# routes.py

from flask import request, render_template, flash, redirect, url_for, session
from app import app, db
from models import User, Department, Campaign, Feedback
from functools import wraps
import datetime

# Role and login decorators (you can import these from app if defined globally)
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(role):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_role' not in session or session['user_role'] != role:
                flash("Access denied.", "danger")
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

# Routes
@app.route('/assign_role', methods=['GET', 'POST'])
@login_required
@role_required('super_admin')
def assign_role():
    # Code to assign roles to users
    return render_template('assign_role.html')

@app.route('/add_department', methods=['GET', 'POST'])
@login_required
@role_required('super_admin')
def add_department():
    # Code to add a new department
    return render_template('add_department.html')

@app.route('/submit_feedback', methods=['GET', 'POST'])
@login_required
def submit_feedback():
    # Code to submit feedback
    return render_template('submit_feedback.html')

@app.route('/create_campaign', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def create_campaign():
    # Code to create a campaign
    return render_template('create_campaign.html')

@app.route('/view_feedback/<int:campaign_id>', methods=['GET'])
@login_required
@role_required('admin', 'viewer')
def view_feedback(campaign_id):
    # Code to view feedback related to a specific campaign
    return render_template('view_feedback.html')