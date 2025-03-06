from flask import Flask, request, render_template, flash, redirect, url_for , session; from flask_cors import CORS;
from flask import Flask, jsonify, json
from flask import Flask
from sqlalchemy.orm.exc import NoResultFound
from flask_login import current_user, login_required,LoginManager,UserMixin, AnonymousUserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import sessionmaker
from flask_bcrypt import Bcrypt
from config import Config
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask import abort, current_app
import datetime
from sqlalchemy import desc
import logging, re
from sqlalchemy import text
import traceback
import io
import requests
from time import sleep
from werkzeug.exceptions import HTTPException
import uuid

from sqlalchemy.sql import func
import re
import secrets
from datetime import datetime, timedelta
import email_validator
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFProtect,generate_csrf
from sqlalchemy.exc import IntegrityError
import secrets
import base64
from sqlalchemy.exc import SQLAlchemyError

from flask import redirect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField, RadioField, HiddenField, DateTimeField, BooleanField, FileField, FieldList, FormField
from wtforms.validators import DataRequired, Email, EqualTo, Length, AnyOf, Optional , ValidationError
from flask_wtf.file import FileAllowed
from werkzeug.utils import secure_filename
import random


import os
import qrcode
from PIL import Image, ImageDraw
from flask import Flask, request, send_file
from io import BytesIO

import logging

# Set up your logger
logger = logging.getLogger(__name__)




# import routes  # Import routes (we’ll create this later)
from models import Campaign, Feedback, Department ,Users, Question, Dockets, Announcement, DepartmentActivity,FormFeedback, FormUrl, ViewerDepartment

from forms import QuestionForm,LoginForm, RegisterForm, AddDepartmentForm, AddDocketForm, AssignRoleForm, CreateCampaignForm, DepartmentActivityForm, AddAnnouncementForm ,DepartmentActivityViewForm , AnnouncementViewForm , FeedbackViewForm



# Initialize extensions first (before app creation)


app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://username:password@localhost/your_database'
app.config['SECRET_KEY'] = 'your_secret_key'
# Set up Redis storage for Flask-Limiter
app.config["RATELIMIT_STORAGE_URL"] = "redis://localhost:6380/0"

# Initialize extensions
bcrypt = Bcrypt(app)
mail = Mail(app)

# Initialize CSRF protection
csrf = CSRFProtect(app)


# Initialize Limiter with correct parameters
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["10000 per day"],
    storage_uri=app.config["RATELIMIT_STORAGE_URL"],
    app=app,  # Pass app as a keyword argument
    
)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User class
class User(UserMixin):
    # department_id = db.Column(db.Integer, db.ForeignKey('department.id'), nullable=True)
    def __init__(self, id):
        self.id = id

# User loader callback
@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

#Initialize Talisman with Content Security Policy
# talisman = Talisman(app,
#     content_security_policy={
#         'default-src': '\'self\'',
#         'script-src': ['\'self\'', 'https://cdnjs.cloudflare.com'],
#     }
# )

# Custom error handler for all exceptions
@app.errorhandler(Exception)
def handle_exception(e):
    # Log the error
    logger.error(f"Error occurred: {str(e)}")

    # If it's an HTTP exception, use its error code and description
    if isinstance(e, HTTPException):
        response = {
            'error': True,
            'message': e.description,
            'status_code': e.code
        }
        return jsonify(response), e.code

    # For other exceptions, return 500 Internal Server Error
    response = {
        'error': True,
        'message': 'An unexpected error occurred. Please try again later.',
        'status_code': 500
    }
    return jsonify(response), 500


    return app

if __name__== '__main__':
    app.run(debug=True, port=5000)

# Import models here (User, Department, Campaign, Feedback, etc.)
# from models import User, Department, Campaign, Feedback

# Helper function for role-based access control
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
            user_role = session.get("user_role")
            if user_role != role:
                flash("You do not have permission to access this page.", "danger")
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

# Utility function for role-based access control
def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'email' not in session:
                return redirect(url_for('login'))
            user = db.session.execute(
                db.select(Users).filter_by(email=session['email'])
            ).scalar_one()
            if not user or user.role != role:
                return jsonify({'error': 'Unauthorized'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Custom decorator for super_admin role
def super_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is logged in and has super_admin role
        if 'email' not in session:
            flash("Please log in first.", "error")
            return redirect(url_for('login'))
            
        user = db.session.execute(
            db.select(Users).filter_by(email=session['email'])
        ).scalar_one_or_none()
        
        if not user or user.role != 'super_admin':
            flash("You don't have permission to access this page.", "error")
            return redirect(url_for('dashboard'))
            
        return f(*args, **kwargs)
    return decorated_function

# class SearchForm:
#     def __init__(self):
#         self.csrf_token = generate_csrf()

#     def validate_csrf_token(self, field):
#         if not verify_csrf_token(field.data, current_app.config['SECRET_KEY']):
#             raise ValidationError('Invalid CSRF token.')

class AddQuestionForm(FlaskForm):
    # For docket-specific choices
    docket_choice = RadioField(
        'Docket Selection',
        choices=[
            ('specific', 'Specific Docket'),
            ('all', 'All Dockets')
        ]
    )
    
    specific_docket_name = StringField('Docket Name')
    
    # For questions
    questions = TextAreaField('Question', validators=[DataRequired()])
    
    # Dynamic question type based on feedback_type
    question_type = SelectField(
        'Question Type',
        choices=[
            ('general', 'General Feedback'),
            ('docket', 'Docket Selection'),
            ('feedback', 'Feedback/Idea/Complaint'),
            ('optional', 'Optional Feedback'),
            ('rating', 'Rating'),
            ('improvement', 'Improvement Suggestion'),
            ('info', 'Information')
        ],
        validators=[DataRequired()]
    )
    
    submit = SubmitField('Add Questions')

    def __init__(self, feedback_type=None, *args, **kwargs):
        super(AddQuestionForm, self).__init__(*args, **kwargs)
        
        # Customize choices based on feedback type
        if feedback_type:
            if feedback_type == 'general':
                self.question_type.choices = [('general', 'General Feedback')]
            
            elif feedback_type == 'docket':
                self.question_type.choices = [
                    ('docket', 'Docket Selection'),
                    ('feedback', 'Feedback/Idea/Complaint'),
                    ('optional', 'Optional Feedback')
                ]
            
            elif feedback_type == 'service':
                self.question_type.choices = [
                    ('rating', 'Rating'),
                    ('improvement', 'Improvement Suggestion'),
                    ('feedback', 'Feedback')
                ]
                
class GeneralFeedbackForm(FlaskForm):
    """
    Form for general feedback questions.
    """
    question = StringField(
        'Question',
        validators=[
            DataRequired(message="Question is required."),
            Length(max=200, message="Question must be less than 200 characters.")
        ],
        render_kw={"placeholder": "Enter your question"}
    )
    question_type = SelectField(
        'Question Type',
        choices=[
            ('general', 'General'),
            ('rating', 'Rating'),
            ('feedback', 'Feedback')
        ],
        validators=[DataRequired(message="Question type is required.")]
    )
    submit = SubmitField('Add Question')

    # Additional fields for file handling
    attachment = FileField('Attachment', validators=[
        Optional(),
        FileAllowed(['pdf', 'doc', 'docx', 'txt', 'jpg', 'jpeg', 'png'], 
                'Only pdf, doc, docx, txt, and image files are allowed!')
    ])

# File upload configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt', 'jpg', 'jpeg', 'png'}

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Route to handle file uploads
def handle_file_upload(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        unique_filename = f"{timestamp}_{filename}"
        
        # Create upload directory if it doesn't exist
        if not os.path.exists(current_app.config['UPLOAD_FOLDER']):
            os.makedirs(current_app.config['UPLOAD_FOLDER'])
            
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        return unique_filename
    return None


class QuestionEntryForm(FlaskForm):
    question_text = TextAreaField('Question', validators=[
        DataRequired(message="Question text is required"),
        Length(min=10, max=500, message="Question must be between 10 and 500 characters")
    ])
    question_type = HiddenField(default='general')

class GeneralQuestionsForm(FlaskForm):
    questions = FieldList(FormField(QuestionEntryForm), min_entries=1)

class DocketFeedbackForm(FlaskForm):
    """
    Form for docket-wise feedback questions.
    """
    docket_choice = SelectField(
        'Docket Choice',
        choices=[
            ('specific', 'Specific Docket'),
            ('all', 'All Dockets')
        ],
        validators=[DataRequired(message="Docket choice is required.")]
    )
    specific_docket_name = StringField(
        'Specific Docket Name',
        validators=[
            DataRequired(message="Docket name is required if 'Specific Docket' is selected."),
            Length(max=100, message="Docket name must be less than 100 characters.")
        ],
        render_kw={"placeholder": "Enter docket name"}
    )
    question = StringField(
        'Question',
        validators=[
            DataRequired(message="Question is required."),
            Length(max=200, message="Question must be less than 200 characters.")
        ],
        render_kw={"placeholder": "Enter your question"}
    )
    question_type = SelectField(
        'Question Type',
        choices=[
            ('docket', 'Docket'),
            ('feedback', 'Feedback'),
            ('optional', 'Optional')
        ],
        validators=[DataRequired(message="Question type is required.")]
    )
    submit = SubmitField('Add Question')

class ServiceFeedbackForm(FlaskForm):
    """
    Form for service-wise feedback questions.
    """
    service_name = StringField(
        'Service Name',
        validators=[
            DataRequired(message="Service name is required."),
            Length(max=100, message="Service name must be less than 100 characters.")
        ],
        render_kw={"placeholder": "Enter service name"}
    )
    question = StringField(
        'Question',
        validators=[
            DataRequired(message="Question is required."),
            Length(max=200, message="Question must be less than 200 characters.")
        ],
        render_kw={"placeholder": "Enter your question"}
    )
    question_type = SelectField(
        'Question Type',
        choices=[
            ('rating', 'Rating'),
            ('improvement', 'Improvement'),
            ('feedback', 'Feedback')
        ],
        validators=[DataRequired(message="Question type is required.")]
    )
    submit = SubmitField('Add Question')
    
class SearchForm(FlaskForm):
    search_query = StringField(
        'Search Form by Name',
        validators=[DataRequired(message="Search query is required.")]
    )
    submit = SubmitField('Search')
    
# class SuperAdminDashboardForm(FlaskForm):
#     # Add fields if needed (e.g., for actions like assigning roles or departments)
#     csrf_token = HiddenField()  # CSRF token is automatically included by Flask-WTF[==-\=
#     # Add A submit button for the form
#     submit = SubmitField('Submit')
    

@app.route('/assign_role', methods=['GET', 'POST'])
@login_required
@super_admin_required
@role_required('super_admin')
def assign_role():
    """
    This view handles assigning roles to users.
    """
    form = AssignRoleForm()
    
    
    if form.validate_on_submit():
        email = form.email.data
        role = form.role.data
        user = Users.query.filter_by(email=email).first()
        
        # Validate role assignment
        valid_roles = ['admin', 'viewer' , 'super_admin']  # List of assignable roles
        
        # if isinstance(current_user, AnonymousUserMixin):
        #     return "Please log in to access this page.", 401  # Unauthorized
        
        try:
            if user:
                if role not in valid_roles:
                    flash("Invalid role selection.", "danger")
                    return redirect(url_for('assign_role'))
                
                # Assign role to user
                user.role = role
                db.session.commit()
                flash(f"Role '{role}' assigned to {email}.", "success")
            else:
                flash("User not found", "danger")
        except Exception as e:
            db.session.rollback()
            flash("An error occurred while assigning role.", "danger")
            flash(str(e), "danger")
        return redirect(url_for('assign_role'))
    
    # Get all users for displayquestion
    users = Users.query.all()
    return render_template('super_admins/assign_role.html' , users=users, form=form)


@app.route('/add_department', methods=['GET', 'POST'])
@login_required
@role_required('super_admin')
def add_department():
    # Get a list of eligible admin users to assign
    eligible_admins = db.session.execute(db.select(Users).filter_by(role='admin')).scalars().all() #Users.query.filter_by(role='admin').all()
    form = AddDepartmentForm(admins=eligible_admins)
    
    
    # Populate the admin_id dropdown with eligible admins
    form.admin_id.choices = [(admin.user_id, admin.name) for admin in Users.query.filter_by(role='admin').all()]
    
    
    # if request.method == 'POST'
    #     name = request.form['name'].strip()
    #     admin_id = request.form.get('user_id')
    if form.validate_on_submit():
        name = form.name.data.strip()
        admin_id = form.admin_id.data
        max_admins = int(request.form.get('max_admins', 1))
        
        # Check if the department name already exists
        
        if db.session.query(Department).filter_by(name=name).first():
            flash("Department is already registered.", "danger")
            return redirect(url_for('add_department'))
        
        

        # Check if the specified admin exists and has an 'admin' role
        admin_user = db.session.execute(db.select(Users).filter_by( user_id=admin_id, role='admin')).scalar_one()
        
        if not admin_user:
            flash("Selected admin does not exist or is not eligible.", "danger")
            return redirect(url_for('add_department'))
        
        #Create the new department
        try:
            new_department = Department(name=name,max_admins=max_admins, created_at=datetime.now())
            db.session.add(new_department)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"Insertion error: {e}")
            flash("Failed to create new department")

        # #Assign the selected admin to the new department
        # try:
        #     admin_user.department_id = new_department.department_id
        #     db.session.commit()
        # except Exception as e:
        #     print(f"Update error: {e}")
        #     flash("Failed to assign admin user to a department")
        
        flash(f"Department '{name}' added and assigned to {admin_user.name}.", "success")
        return redirect(url_for('add_department'))
    
    # Get a list of eligible admin users to assign
    eligible_admins = Users.query.filter_by(role='admin').all()
    departments = db.session.execute(db.select(Department)).scalars()
    
    # Query all active departments (excluding soft-deleted ones)
    departments = Department.query.filter(Department.deleted_at.is_(None)).all()
    
    return render_template('super_admins/manage_departments.html', eligible_admins=eligible_admins, departments=departments , form=form)

# Route for Updating a Department
@app.route('/update_department/<int:department_id>', methods=['POST'])
@login_required
@super_admin_required
def update_department(department_id):
    department = db.session.execute(
        db.select(Department).filter_by(department_id=department_id)
    ).scalar_one_or_none()
    
    if not department:
        flash("Department not found", "error")
        return redirect(url_for('add_department'))
        
    department_name = request.form.get('department_name')
    max_admins = int(request.form.get('max_admins', 1))
    
    # Validate input
    if not department_name:
        flash("Department name is required", "error")
        return redirect(url_for('add_department'))
        
    if max_admins < 1:
        flash("Maximum admins must be at least 1", "error")
        return redirect(url_for('add_department'))
    
    # Check current admin count
    admin_count = db.session.execute(
        db.select(db.func.count()).select_from(Users).filter_by(
            department_id=department_id, role='admin')
    ).scalar_one()
    
    if admin_count > max_admins:
        flash(f"Cannot reduce max admins to {max_admins}, department currently has {admin_count} admins", "error")
        return redirect(url_for('add_department'))
    
    # Update department
    try:
        department.name = department_name
        department.max_admins = max_admins
        db.session.commit()
        flash(f"Department '{department_name}' updated successfully", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error updating department: {str(e)}", "error")
        
    return redirect(url_for('add_department'))




@app.route('/delete_department/<int:department_id>', methods=['POST'])
@login_required
@role_required('super_admin')
def delete_department(department_id):
    # department = Department.query.get_or_404(department_id)
    
    # Fetch the department by its ID
    department = db.session.execute(db.select(Department).filter_by(department_id=department_id)).scalar_one_or_none()  # Use scalar_one_or_none() to handle cases where the department might not exist

    
    if not department:
        flash("Department not found", "error")
        return redirect(url_for('add_department'))
    
    # Check if department has users
    user_count = db.session.execute(
        db.select(db.func.count()).select_from(Users).filter_by(department_id=department_id)
    ).scalar_one()
    
    if user_count > 0:
        flash(f"Cannot delete department '{department.name}' as it has {user_count} users assigned", "error")
        return redirect(url_for('add_department'))

    if department:
        print(f"Found department: {department.name}")  # Debugging
        try:
            # Soft delete: Set the deleted_at timestamp
            department.deleted_at = datetime.now()  # Implementing soft delete
            db.session.delete(department)
            db.session.commit()
            print(f"Department '{department.name}' soft deleted successfully.")  # Debugging
            flash(f"Department '{department.name}' deleted successfully.", "success")
        except Exception as e:
            db.session.rollback()
            print(f"Deletion error: {e}")  # Debugging
            flash("Failed to delete department")
    else:
        print(f"Department with ID {department_id} not found.")  # Debugging
        flash("Invalid docket ID.", "danger")
    # flash(f"Department '{department.name}' deleted.", "success")
    return redirect(url_for('add_department'))

# Route for Assigning Users to Departments
@app.route('/assign_department', methods=['POST'])
@login_required
@super_admin_required
def assign_department():
    user_id = request.form.get('user_id')
    department_id = request.form.get('department_id') or None
    
    if not user_id:
        flash("User ID is required", "error")
        return redirect(url_for('super_admin_dashboard'))
        
    # Get user
    user = db.session.execute(
        db.select(Users).filter_by(id=user_id)
    ).scalar_one_or_none()
    
    if not user:
        flash("User not found", "error")
        return redirect(url_for('super_admin_dashboard'))
    
    # If assigning to department and user is admin, check max_admins limit
    if department_id and user.role == 'admin':
        department = db.session.execute(
            db.select(Department).filter_by(department_id=department_id)
        ).scalar_one_or_none()
        
        if department:
            # Count current admins in this department
            admin_count = db.session.execute(
                db.select(db.func.count()).select_from(Users).filter_by(
                    department_id=department_id, role='admin')
            ).scalar_one()
            
            if admin_count >= department.max_admins:
                flash(f"Department '{department.name}' already has maximum number of admins ({department.max_admins})", "error")
                return redirect(url_for('super_admin_dashboard'))
    
    # Update user department
    try:
        user.department_id = department_id
        db.session.commit()
        
        if department_id:
            department_name = db.session.execute(
                db.select(Department).filter_by(department_id=department_id)
            ).scalar_one().name
            flash(f"User {user.username} assigned to department: {department_name}", "success")
        else:
            flash(f"User {user.username} removed from department", "success")
            
    except Exception as e:
        db.session.rollback()
        flash(f"Error assigning department: {str(e)}", "error")
        
    return redirect(url_for('super_admin_dashboard'))

# Route for Viewing All Campaigns
@app.route('/view_all_campaigns')
@login_required
@super_admin_required
def view_all_campaigns():
    # Get all campaigns with department information
    campaigns = db.session.execute(
        db.select(Campaign, Department)
        .join(Department, Campaign.department_id == Department.department_id)
    ).all()
    
    return render_template('view_all_campaigns.html', campaigns=campaigns)

# Route for Assigning Viewers to Departments
@app.route('/assign_viewers', methods=['GET', 'POST'])
@login_required
@super_admin_required
def assign_viewers():
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        department_ids = request.form.getlist('department_ids')
        
        if not user_id:
            flash("User ID is required", "error")
            return redirect(url_for('assign_viewers'))
            
        # Get user
        user = db.session.execute(
            db.select(Users).filter_by(user_id=user_id)
        ).scalar_one_or_none()
        
        if not user:
            flash("User not found", "error")
            return redirect(url_for('assign_viewers'))
            
        # Ensure user is a viewer
        if user.role != 'viewer':
            user.role = 'viewer'
        
        # Update user's viewable departments
        try:
            # First remove existing assignments
            db.session.execute(
                db.delete(ViewerDepartment).where(ViewerDepartment.user_id == user_id)
            )
            
            # Add new assignments
            for dept_id in department_ids:
                viewer_dept = ViewerDepartment(
                    user_id=user_id,
                    department_id=dept_id
                )
                db.session.add(viewer_dept)
                
            db.session.commit()
            flash(f"Viewer permissions updated for {user.username}", "success")
            
        except Exception as e:
            db.session.rollback()
            flash(f"Error updating viewer permissions: {str(e)}", "error")
            
        return redirect(url_for('assign_viewers'))
    
    # GET request - display all users and departments
    users = db.session.execute(
        db.select(Users).filter(Users.role == 'viewer')
    ).scalars().all()
    
    departments = db.session.execute(db.select(Department)).scalars().all()
    
    # Get current viewer assignments for each user
    viewer_assignments = {}
    for user in users:
        viewer_depts = db.session.execute(
            db.select(ViewerDepartment).filter_by(user_id=user.id)
        ).scalars().all()
        viewer_assignments[user.id] = [vd.department_id for vd in viewer_depts]
    
    return render_template('super_admins/assign_viewers.html',
                        users=users,
                        departments=departments,
                        viewer_assignments=viewer_assignments)



@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        confirm_password = form.confirm_password.data
        
        
        # Validate passwords match
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template('basics/register.html' , form=form)

        # Validate email domain
        if not email.endswith('@strathmore.edu'):
            flash("Please use a valid organization email address.", "danger")
            return redirect(url_for('register'))

        # Check if user already exists
        if db.session.query(Users.query.filter_by(email=email).exists()).scalar():
            flash("Email is already registered.", "danger")
            return redirect(url_for('register'))
                
        
        if not Users.validate_password_strength(password):
            flash("Password does not meet strength requirements. It must be at least 12 characters long and include uppercase, lowercase, number, and special character.", "danger")
            return render_template('basics/register.html', form = form)

        # Create new user
        try:
            new_user = Users(name=name, email=email, role='super_admin')  # Default role
            new_user.set_password(password)
            
            # # Generate and set verification token
            # new_user.set_verification_token()
            
            # Add user to database
            db.session.add(new_user)
            db.session.commit()
            
            # # Send verification email
            # send_verification_email(new_user.email, new_user.verification_token)
            
            # Redirect to login page with success message
            flash("Registration successful! You can now log in.", "success")
            return redirect(url_for('login'))
        
        except IntegrityError:
            db.session.rollback()
            flash("Email is already registered.", "danger")
            return redirect(url_for('register'))
        except Exception as e:
            db.session.rollback()
            print(f"Registration error: {str(e)}")  # Log the error for debugging
            flash("Registration failed. Please try again.", "danger")
            return redirect(url_for('register'))
        
    return render_template('basics/register.html' , form=form)

@app.route('/verify-email/<token>')
def verify_email(token):
    user = Users.query.filter_by(verification_token=token).first()
    if user and user.verify_email_token(token):
        flash('Email verified successfully! You can now log in.', 'success')
        return redirect(url_for('login'))
    else:
        flash('Invalid or expired verification link.', 'danger')
        return redirect(url_for('register'))



@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()  # Create an instance of the LoginForm class
    
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        session['email'] = email

        try:
            # Check if user exists
            user = db.session.execute(db.select(Users.user_id,  Users.password, Users.role).filter_by(email=email)).first()
            
            # Check if password matches and user is verified
            if user and bcrypt.check_password_hash(user.password ,password):
                # if user.email_verified:
                #     flash("Login successful", "success")
                                
                session['user_id'] = user.user_id
                session['user_role'] = user.role
                
                flash("Login successful", "success")
                
                
                # # Check if email is verified
                # if user and user.verify_email_token(user.verification_token):
                    # Redirect based on role
                if user.role == 'super_admin':
                    return redirect(url_for('super_admin_dashboard'))  # Super Admin dashboard
                elif user.role == 'admin':
                    return redirect(url_for('admin_dashboard'))  # Admin dashboard
                else:
                    return redirect(url_for('viewer_dashboard'))  # Viewer route
            else:
                flash("Invalid email or password", "danger")
        except Exception as e:
            db.session.rollback()
            print(f"Login error: {str(e)}")  # Log the error for debugging
            flash("Login failed. Please try again.", "danger")
            return redirect(url_for('login'))
        
    return render_template('basics/login.html' , form=form)

def send_verification_email(to_email, token):
    """
    Send email verification link
    """
    verification_link = url_for('verify_email', token=token, _external=True)
    msg = Message('Verify Your Strathmore Account',
                sender=app.config['MAIL_DEFAULT_SENDER'],
                recipients=[to_email])
    msg.body = f'''
    Dear Strathmore User,

    Please verify your email by clicking the link below:
    {verification_link}

    This link will expire in 24 hours.

    If you did not create an account, please ignore this email.

    Best regards,
    Strathmore University IT Team
    '''
    try:
        mail.send(msg)
        print(f"Verification email sent to {to_email} with link: {verification_link}")
    except Exception as e:
        print(f"Error sending verification email: {e}")
        
        
# @app.route('/super_admin_dashboard', methods=['GET', 'POST'])
# @login_required
# @role_required('super_admin')
# def super_admin_dashboard():
#     try:
#         # Ensure only super admins can access this route
#         if session.get('user_role') != 'super_admin':
#             return "Unauthorized", 403
        
#         # Create an instance of the CSRF-protected form
#         form = SuperAdminDashboardForm()
        
#         # Fetch all users and departments
#         users = Users.query.all()
#         departments = Department.query.all()

#         # Fetch all users in the super_admin role
#         # super_admins = Users.query.filter_by(role='super_admin').all()

#         # Fetch all departments with at least one user
#         departments_with_users = Department.query.join(Users, Department.department_id == Users.department_id).filter(Users.deleted_at == None).group_by(Department.department_id).having(db.func.count(Users.user_id) > 0).all()

#         # Fetch all departments with at least one admin
    
#         # Validate the form data
#         if form.validate_on_submit():
#             # Handle form submission logic here
#             return redirect(url_for('super_admin_dashboard'))
#     except:
#         return "Unauthorized", 403

#     # Render the template with the form, users, and departments
#     return render_template('super_admin_dashboard.html', form=form, users=users, departments=departments)



@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash("Logged out successfully", "success")
    return redirect(url_for('login'))

class Users(db.Model):
    _tablename_ = 'users'

    user_id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='viewer')
    department_id = db.Column(db.Integer, db.ForeignKey('department.department_id'),nullable =True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    deleted_at = db.Column(db.DateTime, nullable=True)
    verification_token = db.Column(db.String(255), nullable=True)  # New column for verification token
    verification_token_expires_at = db.Column(db.DateTime, nullable=True)
    account_locked_until = db.Column(db.DateTime, nullable=True)  # New column for account lock
    failed_login_attempts = db.Column(db.Integer, default=0)   # New column for failed login attempts
    last_login = db.Column(db.DateTime, nullable=True)
    updated_at = db.Column(db.DateTime, onupdate=db.func.current_timestamp())
    email_verified = db.Column(db.Boolean, nullable=False, default=False)
    
    
    @staticmethod
    def validate_password_strength(password):
        """Validate password strength."""
        if len(password) < 12:
            return False
        if not re.search(r"[A-Z]", password):  # At least one uppercase letter
            return False
        if not re.search(r"[a-z]", password):  # At least one lowercase letter
            return False
        if not re.search(r"[0-9]", password):  # At least one digit
            return False
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):  # At least one special character
            return False
        return True


    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return check_password_hash(self.password, password)
    
# Security-related fields
    
    # created_at = db.Column(db.DateTime, server_default=func.now())
    # updated_at = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now())
    # deleted_at = db.Column(db.DateTime, nullable=True)

    @staticmethod
    def validate_strathmore_email(email):
        """
        Validate Strathmore email with comprehensive checks
        """
        try:
            # Validate email format
            valid = email_validator.validate_email(email)
            
            # Check Strathmore domain
            if not email.lower().endswith('@strathmore.edu'):
                return False
            
            return True
        except email_validator.EmailNotValidError:
            return False

    @classmethod
    def generate_secure_token(cls, length=32):
        """
        Generate a cryptographically secure random token
        """
        return secrets.token_urlsafe(length)

    def set_verification_token(self):
        """
        Set email verification token with expiration
        """
        self.verification_token = self.generate_secure_token()
        self.verification_token_expires_at = datetime.now() + timedelta(hours=24)
        try:
            send_verification_email(self.email, self.verification_token)
            db.session.add(self)
            db.session.commit()
            return self.verification_token
        except Exception as e:
            print(f"Error sending email verification link: {e}")
            db.session.rollback()
        

    def verify_email_token(self, token):
        """
        Verify email verification token
        """
        if (self.verification_token == token and
            self.verification_token_expires_at and
            datetime.now() < self.verification_token_expires_at):
            self.email_verified = True
            self.verification_token = None
            self.verification_token_expires_at = None
            db.session.commit()
            return True
        return False

    # @staticmethod
    # def validate_password_strength(password):
    #     """
    #     Comprehensive password strength validation
        
    #     Requirements:
    #     - At least 12 characters long
    #     - Contains at least one uppercase letter
    #     - Contains at least one lowercase letter
    #     - Contains at least one number
    #     - Contains at least one special character
    #     """
    #     if len(password) < 12:
    #         return False
        
    #     # Checks for at least one uppercase, one lowercase, one digit, and one special character
    #     if not re.search(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$', password):
    #         return False
        
    #     return True

    def increment_failed_login(self):
        """
        Increment failed login attempts and potentially lock account
        """
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.account_locked_until = datetime.now() + timedelta(minutes=15)
        db.session.commit()

    def reset_failed_login_attempts(self):
        """
        Reset failed login attempts after successful login
        """
        self.failed_login_attempts = 0
        self.account_locked_until = None
        db.session.commit()

    def is_account_locked(self):
        """
        Check if account is currently locked
        """
        if self.account_locked_until:
            return datetime.now() < self.account_locked_until
        return False

def role_required(*roles):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_role' not in session or session['user_role'] not in roles:
                flash("You do not have permission to access this page.", "danger")
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

class Department(db.Model):
    _tablename_ = 'department'
    department_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    deleted_at = db.Column(db.DateTime, nullable=True)
    #Relationships with users
    #admins = db.relationship('Users', backref = 'department', lazy =True)


    def soft_delete(self):
        self.deleted_at = datetime.now()
        db.session.commit()
        
        
    def restore(self):
        self.deleted_at = None
        db.session.commit()
        
    def __repr__(self):
        return f"<Department {self.name}>"
    
@app.route('/create_campaign', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def create_campaign():
    # Create form instance
    form = CreateCampaignForm()
    
    try:
        # Explicitly query for the current user
        user = db.session.execute(
            db.select(Users).filter_by(email=session['email'])
        ).scalar_one_or_none()
        
        # Get user from database instead of using current_user
        if 'email' not in session:
            flash("Session expired. Please log in again.", "error")
            return redirect(url_for('login'))
        
        if not user:
            flash("User account not found. Please log in again.", "error")
            return redirect(url_for('login'))

        # Check if the user exists
        current_user_data = db.session.execute(
            db.select(Users).filter_by(email=session['email'])
        ).scalar_one()
        
        # Check if the user has department access
        if not current_user_data.department_id:
            flash("You don't have permission to create campaigns. You must be assigned to a department.", "error")
            return redirect(url_for('admin_dashboard'))
            
        # Get the user's department with a direct query
        department = db.session.execute(
            db.select(Department).filter_by(department_id=current_user_data.department_id)
        ).scalar_one_or_none()
        
        if not department:
            flash("Your assigned department was not found in the system.", "error")
            return redirect(url_for('admin_dashboard'))
        
        if request.method == 'POST' and form.validate_on_submit():
            # Get campaign details from form
            title = request.form.get('campaign_title')
            description = request.form.get('campaign_description')
            campaign_type = request.form.get('campaign_type')
            # Add date validation
            try:
                start_date = datetime.strptime(request.form.get('start_date'), '%Y-%m-%d')
                end_date = datetime.strptime(request.form.get('end_date'), '%Y-%m-%d')
            except (ValueError, TypeError) as e:
                flash("Invalid date format. Please use YYYY-MM-DD format", "error")
                return redirect(url_for('create_campaign'))
            
            # Create new campaign with the admin's department_id
            new_campaign = Campaign(
                department_id=current_user.department_id,
                title=title,
                description=description,
                campaign_type=campaign_type,
                start_date=start_date,
                end_date=end_date
            )
            
            try:
                db.session.add(new_campaign)
                db.session.commit()
                # Store campaign ID in session for use in next step
                session['current_campaign_id'] = new_campaign.campaign_id
                flash("Campaign created successfully! Add questions now", "success")
                
                # Redirect to add questions page
                return redirect(url_for('add_questions'))
            except Exception as e:
                db.session.rollback()
                flash(f"Error creating campaign: {str(e)}", "error")
                return redirect(url_for('create_campaign'))
        
    except Exception as e:
        db.session.rollback()
        flash(f"Error processing form: {str(e)}", "error")
        return redirect(url_for('create_campaign'))
    
    # GET request - show form to create campaign
    # Pass the department info to display in the template
    return render_template('create_campaign.html', department=department, form = form, min_date=datetime.now().strftime('%Y-%m-%d'))


# Route for adding questions
@app.route('/add_questions', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def add_questions():
    campaign_id = session.get('current_campaign_id')
    
    if not campaign_id:
        flash("Campaign not found. Please create a campaign first.", "error")
        return redirect(url_for('create_campaign'))
    
    campaign = Campaign.query.get(campaign_id)
    
    if request.method == 'POST':
        # Get question data from form
        question_texts = request.form.getlist('question_text')
        question_types = request.form.getlist('question_type')
        
        if not question_texts:
            flash("Please add at least one question.", "error")
            return render_template('add_questions.html', campaign=campaign)
        
        # Create a temporary form in the session (not yet saved to database)
        temp_form = {
            'campaign_id': campaign_id,
            'form_name': f"{campaign.campaign_title} - Draft",
            'form_version': 1,
            'questions': []
        }
        
        # Since we haven't saved the form yet, we can't add questions to the database
        # We'll store them in the session temporarily
        for i in range(len(question_texts)):
            if question_texts[i].strip():  # Check if question text is not empty
                temp_form['questions'].append({
                    'question_text': question_texts[i],
                    'question_type': question_types[i] if i < len(question_types) else 'general'
                })
        
        # Store the temporary form in the session
        session['temp_form'] = temp_form
        
        # Redirect to preview form
        return redirect(url_for('preview_form'))
    
    # GET request - show form to add questions
    return render_template('add_questions.html', campaign=campaign)

# Route for previewing the form
@app.route('/preview_form', methods=['GET'])
def preview_form():
    try:
        temp_form = session.get('temp_form')
        
        if not temp_form:
            flash("No form data found. Please add questions first.", "error")
            return redirect(url_for('add_questions'))
        
        campaign = Campaign.query.get(temp_form['campaign_id'])
    except Exception as e:
        db.session.rollback()
        flash(f"Error processing form: {str(e)}", "error")
        return redirect(url_for('add_questions'))
    
    return render_template('preview_form.html', form=temp_form, campaign=campaign)

# Route for reviewing the form (edit or publish)
@app.route('/review_form', methods=['POST'])
def review_form():
    action = request.form.get('action')
    
    try:
        if action == 'edit':
            # Redirect to edit form page
            return redirect(url_for('edit_form'))
        elif action == 'discard':
            # Clear the temporary form from session
            session.pop('temp_form', None)
            flash("Form has been discarded.", "info")
            return redirect(url_for('create_campaign'))
        elif action == 'publish':
            # Save the form and questions to the database
            return redirect(url_for('save_form'))
        
        flash("Invalid action.", "error")
    except Exception as e:
        db.session.rollback()
        flash(f"Error processing form: {str(e)}", "error")
    return redirect(url_for('preview_form'))

# Route for editing the form
@app.route('/edit_form', methods=['GET', 'POST'])
def edit_form():
    temp_form = session.get('temp_form')
    
    if not temp_form:
        flash("No form data found. Please add questions first.", "error")
        return redirect(url_for('add_questions'))
    
    if request.method == 'POST':
        # Get updated form details
        form_name = request.form.get('form_name')
        logo_path = request.form.get('logo_path')
        location_details = request.form.get('location_details')
        
        # Update temporary form in session
        temp_form['form_name'] = form_name
        temp_form['logo_path'] = logo_path
        temp_form['location_details'] = location_details
        
        # Get updated questions
        question_ids = request.form.getlist('question_id')
        question_texts = request.form.getlist('question_text')
        question_types = request.form.getlist('question_type')
        
        # Clear existing questions
        temp_form['questions'] = []
        
        # Add updated questions
        for i in range(len(question_texts)):
            if question_texts[i].strip():  # Check if question text is not empty
                temp_form['questions'].append({
                    'question_id': question_ids[i] if i < len(question_ids) else None,
                    'question_text': question_texts[i],
                    'question_type': question_types[i] if i < len(question_types) else 'general'
                })
        
        # Update session
        session['temp_form'] = temp_form
        
        # Redirect to preview page
        return redirect(url_for('preview_form'))
    
    # GET request - show form for editing
    campaign = Campaign.query.get(temp_form['campaign_id'])
    
    return render_template('edit_form.html', form=temp_form, campaign=campaign)


# Route for saving the form to the database
@app.route('/save_form', methods=['GET', 'POST'])
def save_form():
    temp_form = session.get('temp_form')
    
    if not temp_form:
        flash("No form data found. Please add questions first.", "error")
        return redirect(url_for('add_questions'))
    
    if request.method == 'POST':
        # Get final form details
        form_name = request.form.get('form_name')
        status = request.form.get('status', 'draft')
        logo_path = request.form.get('logo_path')
        location_details = request.form.get('location_details')
    else:
        # Use data from session
        form_name = temp_form.get('form_name')
        status = 'draft'
        logo_path = temp_form.get('logo_path')
        location_details = temp_form.get('location_details')
    
    # Get the latest version number for this campaign
    latest_form = FormFeedback.query.filter_by(
        campaign_id=temp_form['campaign_id']
    ).order_by(FormFeedback.form_version.desc()).first()
    
    form_version = 1
    if latest_form:
        form_version = latest_form.form_version + 1
    
    # If status is 'active', set all other forms for this campaign to 'archived'
    if status == 'active':
        active_forms = FormFeedback.query.filter_by(
            campaign_id=temp_form['campaign_id'], 
            status='active'
        ).all()
        
        for form in active_forms:
            form.status = 'archived'
        
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash(f"Error updating existing forms: {str(e)}", "error")
    
    # Create new form
    new_form = FormFeedback(
        campaign_id=temp_form['campaign_id'],
        form_name=form_name,
        form_version=form_version,
        status=status,
        created_by=session.get('user_id'),
        logo_path=logo_path,
        location_details=location_details
    )
    
    try:
        db.session.add(new_form)
        db.session.flush()  # Get the new form ID
        
        # Save questions
        for q in temp_form['questions']:
            new_question = Question(
                form_id=new_form.form_id,
                question_text=q['question_text'],
                question_type=q['question_type']
            )
            db.session.add(new_question)
        
        # Create a unique URL for the form
        url_code = str(uuid.uuid4())[:8]
        new_url = FormUrl(
            form_id=new_form.form_id,
            url_code=url_code,
            is_active=True
        )
        db.session.add(new_url)
        
        db.session.commit()
        
        # Clear the temporary form from session
        session.pop('temp_form', None)
        
        # Store form ID in session for QR code generation
        session['current_form_id'] = new_form.form_id
        session['form_url_code'] = url_code
        
        flash("Form saved successfully!", "success")
        return redirect(url_for('generate_qr_code'))
    
    except Exception as e:
        db.session.rollback()
        flash(f"Error saving form: {str(e)}", "error")
        return redirect(url_for('preview_form'))
    
# Route for generating QR code
@app.route('/generate_qr_code', methods=['GET'])
def generate_qr_code():
    form_id = session.get('current_form_id')
    url_code = session.get('form_url_code')
    
    if not form_id or not url_code:
        flash("Form information not found.", "error")
        return redirect(url_for('admin_dashboard'))
    
    form = FormFeedback.query.get(form_id)
    
    if not form:
        flash("Form not found.", "error")
        return redirect(url_for('admin_dashboard'))
    
    # Generate the feedback form URL
    feedback_url = url_for('feedback_form', url_code=url_code, _external=True)
    
    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(feedback_url)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Save QR code to BytesIO
    buffered = BytesIO()
    img.save(buffered)
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return render_template(
        'qr_code.html',
        form=form,
        feedback_url=feedback_url,
        qr_code=img_str
    )

# Route for the feedback form (what respondents will see)
@app.route('/feedback/<url_code>', methods=['GET', 'POST'])
def feedback_form(url_code):
    form_url = FormUrl.query.filter_by(url_code=url_code, is_active=True).first()
    
    if not form_url:
        return render_template('error.html', message="Form not found or inactive.")
    
    form = FormFeedback.query.get(form_url.form_id)
    questions = Question.query.filter_by(form_id=form.form_id).all()
    campaign = Campaign.query.get(form.campaign_id)
    
    if request.method == 'POST':
        # Process submitted feedback...
        # This is where you'd save the user's answers
        flash("Thank you for your feedback!", "success")
        return redirect(url_for('thank_you'))
    
    return render_template(
        'feedback_form.html',
        form=form,
        questions=questions,
        campaign=campaign
    )

# Route for viewing all campaigns
@app.route('/view_campaigns')
def view_campaigns():
    # Get department ID from logged-in user or request
    department_id = request.args.get('department_id')
    user_id = session.get('user_id')
    
    if department_id:
        campaigns = Campaign.query.filter_by(department_id=department_id).all()
    elif user_id:
        # Show campaigns for departments where user is admin
        user_departments = Department.query.filter_by(admin_id=user_id).all()
        department_ids = [dept.department_id for dept in user_departments]
        campaigns = Campaign.query.filter(Campaign.department_id.in_(department_ids)).all()
    else:
        campaigns = []
    
    return render_template('view_campaigns.html', campaigns=campaigns)

# Route for viewing forms for a campaign
@app.route('/view_forms/<int:campaign_id>')
def view_forms(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    forms = FormFeedback.query.filter_by(campaign_id=campaign_id).order_by(
        FormFeedback.status,
        FormFeedback.form_version.desc()
    ).all()
    
    return render_template('view_forms.html', campaign=campaign, forms=forms)




# # Now let's modify the add_questions route to handle automatic form creation
# @app.route('/add_general_questions/<int:campaign_id>', methods=['GET', 'POST'])
# @login_required
# @role_required('admin')
# def add_general_questions(campaign_id):
#     if request.method == 'POST':
#         try:
#             campaign = Campaign.query.get_or_404(campaign_id)
#             questions_data = request.json.get('questions', [])
            
#             # Create a new form automatically
#             # Get the latest version number for this campaign
#             latest_form = FormFeedback.query.filter_by(campaign_id=campaign_id)\
#                 .order_by(FormFeedback.version.desc()).first()
#             new_version = (latest_form.version + 1) if latest_form else 1
            
#             # Create new form using campaign title
#             new_form = FormFeedback(
#                 campaign_id=campaign_id,
#                 name=f"{campaign.title} - Version {new_version}",
#                 version=new_version,
#                 status='active'  # This will be the active version
#             )
#             db.session.add(new_form)
#             db.session.flush()  # Get the new form ID
            
#             # Archive any previously active forms for this campaign
#             FormFeedback.query.filter_by(
#                 campaign_id=campaign_id,
#                 status='active'
#             ).filter(FormFeedback.form_id != new_form.form_id)\
#             .update({'status': 'archived'})
            
#             # Save questions linked to both form and campaign
#             for question in questions_data:
#                 new_question = Question(
#                     form_id=new_form.form_id,
#                     campaign_id=campaign_id,
#                     question_text=question['text'],
#                     question_type='general'
#                 )
#                 db.session.add(new_question)
            
#             db.session.commit()
            
#             return jsonify({
#                 'success': True,
#                 'form_id': new_form.form_id
#             })
            
#         except Exception as e:
#             db.session.rollback()
#             return jsonify({
#                 'success': False,
#                 'message': str(e)
#             }), 500
            
#     # GET request - show the question addition form
#     return render_template('add_general_questions.html', campaign_id=campaign_id)


# # Routes for handling questions after campaign creation
# @app.route('/add_questions/<campaign_id>/<feedback_type>', methods=['GET', 'POST'])
# @login_required
# @role_required('admin')
# def add_questions(campaign_id, feedback_type):
#     if feedback_type not in ['general', 'docket', 'service']:
#         return redirect(url_for('create_campaign'))
    
#     form = QuestionForm()
    
#     try:
#         campaign = db.session.execute(
#             db.select(Campaign).filter_by(campaign_id=campaign_id)
#         ).scalar_one()
        
#         if request.method == 'POST':
#             if form.validate_on_submit():
#                 new_question = Question(
#                     form_id=campaign_id,
#                     question_text=form.question_text.data,
#                     question_type=feedback_type
#                 )
                
#                 db.session.add(new_question)
#                 db.session.commit()
                
#                 # Get all questions for this campaign to check if we should create temporary form
#                 questions = db.session.execute(
#                     db.select(Question).filter_by(form_id=campaign_id)
#                 ).scalars().all()
                
#                 temp_form_name = f"Temporary_{feedback_type}_Form_{campaign_id}"
                
#                 return jsonify({
#                     'success': True,
#                     'question_id': new_question.question_id,
#                     'temp_form_name': temp_form_name,
#                     'questions_count': len(questions)
#                 })
        
#         # GET request - show appropriate template based on feedback type
#         questions = db.session.execute(
#             db.select(Question).filter_by(form_id=campaign_id)
#         ).scalars().all()
        
#         template_name = f'add_{feedback_type}_questions.html'
#         return render_template(
#             template_name,
#             form=form,
#             questions=questions,
#             campaign=campaign
#         )
        
#     except Exception as e:
#         db.session.rollback()
#         return jsonify({
#             'success': False,
#             'error': str(e)
#         }), 500

# @app.route('/campaign/<int:campaign_id>/forms')
# @login_required
# @role_required('admin')
# def list_campaign_forms(campaign_id):
#     """Display all forms associated with a campaign, showing their versions and status."""
#     try:
#         campaign = Campaign.query.get_or_404(campaign_id)
#         # Get forms ordered by creation date, newest first
#         forms = FormFeedback.query.filter_by(campaign_id=campaign_id)\
#             .order_by(desc(FormFeedback.created_at)).all()
        
#         return render_template('campaign_forms.html',
#                             campaign=campaign,
#                             forms=forms)
#     except Exception as e:
#         return jsonify({'error': str(e)}), 500

# @app.route('/campaign/<int:campaign_id>/create_form', methods=['GET', 'POST'])
# @login_required
# @role_required('admin')
# def create_campaign_form(campaign_id):
#     """Create a new form for an existing campaign."""
#     try:
#         campaign = Campaign.query.get_or_404(campaign_id)
        
#         if request.method == 'POST':
#             # Get the highest version number for this campaign's forms
#             latest_form = FormFeedback.query.filter_by(campaign_id=campaign_id)\
#                 .order_by(desc(FormFeedback.version)).first()
#             new_version = (latest_form.version + 1) if latest_form else 1
            
#             # Create new form
#             new_form = FormFeedback(
#                 campaign_id=campaign_id,
#                 name=request.form.get('name', f"{campaign.title} - Version {new_version}"),
#                 version=new_version,
#                 status='draft',
#                 language=request.form.get('language', 'en'),
#                 format=request.form.get('format', 'web')
#             )
#             db.session.add(new_form)
#             db.session.commit()
            
#             # If this is a new version of an existing form, copy questions from the previous version
#             if request.form.get('copy_from_form'):
#                 source_form_id = int(request.form.get('copy_from_form'))
#                 source_questions = Question.query.filter_by(form_id=source_form_id).all()
                
#                 for question in source_questions:
#                     new_question = Question(
#                         form_id=new_form.form_id,
#                         question_text=question.question_text,
#                         question_type=question.question_type
#                     )
#                     db.session.add(new_question)
                
#                 db.session.commit()
            
#             return redirect(url_for('edit_form', form_id=new_form.form_id))
        
#         # Get existing forms for this campaign (for copying questions)
#         existing_forms = FormFeedback.query.filter_by(campaign_id=campaign_id).all()
        
#         return render_template('create_form.html',
#                             campaign=campaign,
#                             existing_forms=existing_forms)
        
#     except Exception as e:
#         db.session.rollback()
#         return jsonify({'error': str(e)}), 500

# @app.route('/form/<int:form_id>/edit', methods=['GET', 'POST'])
# @login_required
# @role_required('admin')
# def edit_form(form_id):
#     """Edit an existing form, including its questions."""
#     try:
#         form = FormFeedback.query.get_or_404(form_id)
        
#         if request.method == 'POST':
#             form.name = request.form.get('name', form.name)
#             form.language = request.form.get('language', form.language)
#             form.format = request.form.get('format', form.format)
            
#             # Handle question updates
#             questions_data = request.json.get('questions', [])
            
#             # Remove existing questions
#             Question.query.filter_by(form_id=form_id).delete()
            
#             # Add updated questions
#             for question in questions_data:
#                 new_question = Question(
#                     form_id=form_id,
#                     question_text=question['text'],
#                     question_type=question['type']
#                 )
#                 db.session.add(new_question)
            
#             db.session.commit()
#             return jsonify({'success': True})
        
#         questions = Question.query.filter_by(form_id=form_id).all()
#         return render_template('edit_form.html', form=form, questions=questions)
        
#     except Exception as e:
#         db.session.rollback()
#         return jsonify({'error': str(e)}), 500

# @app.route('/form/<int:form_id>/status', methods=['POST'])
# @login_required
# @role_required('admin')
# def update_form_status(form_id):
#     """Update the status of a form (draft, active, archived)."""
#     try:
#         form = FormFeedback.query.get_or_404(form_id)
#         new_status = request.json.get('status')
        
#         if new_status not in ['draft', 'active', 'archived']:
#             return jsonify({'error': 'Invalid status'}), 400
        
#         # If activating this form, archive other active forms for this campaign
#         if new_status == 'active':
#             active_forms = FormFeedback.query.filter_by(
#                 campaign_id=form.campaign_id,
#                 status='active'
#             ).all()
#             for active_form in active_forms:
#                 active_form.status = 'archived'
        
#         form.status = new_status
#         db.session.commit()
        
#         return jsonify({'success': True})
        
#     except Exception as e:
#         db.session.rollback()
#         return jsonify({'error': str(e)}), 500
    
    # # GET request - show edit form
    # campaign = db.session.execute(
    #     db.select(Campaign).filter_by(campaign_id=campaign_id)
    # ).scalar_one()
    
    # questions = db.session.execute(
    #     db.select(Question).filter_by(form_id=campaign_id)
    # ).scalars().all()
    
    # return render_template(
    #     'edit_form.html',
    #     campaign=campaign,
    #     questions=questions
    # )


# @app.route('/add_general_questions/<int:campaign_id>', methods=['GET', 'POST'])
# @login_required
# @role_required('admin')
# def add_general_questions(campaign_id):
#     form = GeneralQuestionsForm()
#     campaign = db.session.execute(db.select(Campaign).filter_by(campaign_id=campaign_id)).scalar_one()
    
#     default_questions = [
#         'What is your overall satisfaction with our services?',
#         'What do you like most about our services?',
#         'Any additional comments?'
#     ]
#     question_types = ['general'] * len(default_questions)

#     if request.method == 'POST':
#         return save_questions(campaign_id, campaign)

#     return render_template('add_questions.html',
#                         campaign=campaign,
#                         default_questions=default_questions,
#                         question_types=question_types)

# @app.route('/add_docket_questions/<int:campaign_id>', methods=['GET', 'POST'])
# @login_required
# @role_required('admin')
# def add_docket_questions(campaign_id):
#     campaign = db.session.execute(db.select(Campaign).filter_by(campaign_id=campaign_id)).scalar_one()
#     department_id = campaign.department_id

#     if request.method == 'GET':
#         return render_template('choose_docket.html', campaign=campaign)

#     docket_choice = request.form.get('docket_choice')
    
#     if docket_choice == 'specific':
#         return handle_specific_docket(campaign_id, department_id, campaign)
#     elif docket_choice == 'all':
#         return handle_all_dockets(campaign_id, department_id, campaign)

#     flash('Invalid docket choice.', 'error')
#     return redirect(url_for('add_docket_questions', campaign_id=campaign_id))

# @app.route('/add_service_questions/<int:campaign_id>', methods=['GET', 'POST'])
# @login_required
# @role_required('admin')
# def add_service_questions(campaign_id):
#     campaign = db.session.execute(db.select(Campaign).filter_by(campaign_id=campaign_id)).scalar_one()
    
#     default_questions = [
#         'How would you rate our services?',
#         'What improvements can be made?',
#         'Please provide any additional feedback regarding our services.'
#     ]
#     question_types = ['rating', 'improvement', 'feedback']

#     if request.method == 'POST':
#         return save_questions(campaign_id, campaign)

#     return render_template('add_questions.html',
#                         campaign=campaign,
#                         default_questions=default_questions,
#                         question_types=question_types)

# # Helper functions
# def save_questions(campaign_id, campaign):
#     questions = request.form.getlist('questions')
#     questions_type = request.form.getlist('questions_type')

#     for question_text, question_type in zip(questions, questions_type):
#         new_question = FeedbackQuestion (campaign_id=campaign_id,
#             question=question_text,
#             question_type=question_type,
#             feedback_type='general',
#             created_at=datetime.now(),
#             updated_at=datetime.now()
#         )
#         db.session.add(new_question)

#     db.session.commit()
#     flash(f"Questions added successfully to the campaign '{campaign.title}'.", "success")
#     return redirect(url_for('create_feedback_form', campaign_id=campaign.campaign_id))

# def handle_specific_docket(campaign_id, department_id, campaign):
#     specific_docket_name = request.form.get('specific_docket_name')
#     specific_docket = db.session.execute(
#         db.select(Dockets).filter_by(
#             name=specific_docket_name,
#             department_id=department_id,
#             deleted_at=None
#         )
#     ).scalar_one_or_none()

#     if not specific_docket:
#         flash('The specified docket does not exist or is not available.', 'error')
#         return redirect(url_for('add_docket_questions', campaign_id=campaign_id))

#     default_questions = [
#         f'Feedback for {specific_docket.name}:',
#         'What is your feedback/idea/complaint?',
#         'What should be brought back and why? (optional)'
#     ]
#     question_types = ['docket', 'feedback', 'optional']

#     return render_template('add_questions.html',
#                         campaign=campaign,
#                         default_questions=default_questions,
#                         question_types=question_types)

# def handle_all_dockets(campaign_id, department_id, campaign):
#     dockets = db.session.execute(
#         db.select(Dockets).filter_by(department_id=department_id, deleted_at=None)
#     ).scalars()

#     docket_names = [docket.name for docket in dockets]

#     if not docket_names:
#         default_questions = [
#             'No available dockets for feedback at this time.',
#             'Please provide your feedback/idea/complaint:'
#         ]
#         question_types = ['info', 'feedback']
#     else:
#         default_questions = [
#             f'Please select a docket from the following: {", ".join(docket_names)}',
#             'What is your feedback/idea/complaint?',
#             'What should be brought back and why? (optional)'
#         ]
#         question_types = ['docket', 'feedback', 'optional']

#     return render_template('add_questions.html',
#                         campaign=campaign,
#                         default_questions=default_questions,
#                         question_types=question_types)


# @app.route('/create_feedback_form/<int:campaign_id>', methods=['GET', 'POST'])
# @login_required
# @role_required('admin')
# def create_feedback_form(campaign_id):
#     campaign = db.session.execute(db.select(Campaign).filter_by(campaign_id=campaign_id)).scalar_one()

#     # Fetch all questions related to this campaign
#     questions = db.session.execute(db.select(Question).filter_by(campaign_id=campaign_id)).scalars().all()

#     if request.method == 'POST':
#         # Logic to generate URL or save changes can be added here
#         # For now, just redirect to a confirmation page or show URL
#         feedback_url = f"/feedback/{campaign.title.replace(' ', '_')}"

#         flash(f"Feedback form created! Access it at: {feedback_url}", "success")

#         # Redirect to view feedback form where admin can confirm satisfaction
#         return redirect(url_for('view_feedback_form', campaign_id=campaign_id, feedback_url=feedback_url))

#         # return redirect(url_for('view_feedback_form', campaign_id=campaign_id))  # Pass campaign_id and Redirect where appropriate

#     return render_template('create_feedback_form.html', campaign=campaign, questions=questions)

# @app.route('/view_feedback_form/<int:campaign_id>', methods=['GET', 'POST'])
# @login_required
# @role_required('admin')
# def view_feedback_form(campaign_id):
#     campaign = db.session.execute(db.select(Campaign).filter_by(campaign_id=campaign_id)).scalar_one()

#     # Fetch all questions related to this campaign
#     questions = db.session.execute(db.select(Question).filter_by(campaign_id=campaign_id)).scalars().all()

#     feedback_url = f"/feedback/{campaign.title.replace(' ', '_')}"  # Generate a test URL

#     if request.method == 'POST':
#         # Here you could handle any additional logic if needed

#         return redirect(url_for('generate_qr', url=request.form['feedback_url']))
#         # flash("QR Code generated!", "success")
#         # return redirect(url_for('view_feedback_form', campaign_id=campaign.campaign_id))

#     return render_template('view_feedback_form.html', campaign=campaign, questions=questions, feedback_url=feedback_url)

@app.route('/search_forms')
def search_forms():
    search_term = request.args.get('term', '')
    # Example form data - replace with your database query
    forms = [
        {'id': 1, 'name': f'Form matching {search_term} 1'},
        {'id': 2, 'name': f'Form matching {search_term} 2'},
        # Add more forms based on search
    ]
    return jsonify(forms)

# @app.route('/form_selection', methods=['GET', 'POST'])
# @login_required
# def form_selection():
#     user_role = get_user_role()
#     if user_role != 'admin':
#         flash('Access denied. Only admins can access this page.', 'error')
#         return redirect(url_for('dashboard'))

#     # Create an instance of the SearchForm
#     form = SearchForm()

#     # Handle form submission
#     if form.validate_on_submit():
#         search_query = form.search_query.data
#         # Perform search logic (e.g., query the database)
#         forms = Form.query.filter(Form.form_name.ilike(f'%{search_query}%')).all()
#         return render_template('form_selection.html', user_role=user_role, form=form, forms=forms)

#     # Render the template with the form
#     return render_template('form_selection.html', user_role=user_role, form=form, forms=None)

@app.route('/get_form_preview/<form_id>')
def get_form_preview(form_id):
    # Example preview data - replace with your form template retrieval logic
    form = {
        'id': form_id,
        'content': f'<div class="preview">Form template content for ID: {form_id}</div>',
        'name': f'Form Template {form_id}'
    }
    return jsonify(form)

@app.route('/download_template/<form_id>')
def download_template(form_id):
    # Example template retrieval - replace with your actual template file handling
    template_content = f"Template content for form {form_id}"
    mem_file = BytesIO()
    mem_file.write(template_content.encode())
    mem_file.seek(0)
    
    return send_file(
        mem_file,
        mimetype='application/octet-stream',
        as_attachment=True,
        download_name=f'template_{form_id}.txt'
    )

@app.route('/generate_qrcode/<form_id>', methods=['POST'])
@csrf.exempt  # If you want to exempt this route from CSRF protection
def generate_qrcode(form_id):
    # Get the form URL for QR generation
    form_url = request.host_url + f'forms/view/{form_id}'
    
    # QR code configuration
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4
    )
    
    # Add the URL data
    qr.add_data(form_url)
    qr.make(fit=True)
    
    # Create QR code image
    qr_image = qr.make_image(fill_color="black", back_color="white").convert('RGB')
    
    # Convert to base64 for sending to frontend
    img_io = BytesIO()
    qr_image.save(img_io, format='PNG')
    img_io.seek(0)
    
    # Convert to base64
    import base64
    qr_base64 = base64.b64encode(img_io.getvalue()).decode()
    
    return jsonify({'qr_code': qr_base64})


@app.route('/manage_dockets', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manage_dockets():
    form = AddDocketForm()  # Instantiate the form
    
    current_user = db.session.execute(db.select(Users).filter_by(email=session['email'])).scalar_one()
    department_id = current_user.department_id
    department = Department.query.get_or_404(department_id)
    

    if request.method == 'POST' and form.validate_on_submit():
        action = request.form.get('action')
        docket_name = form.docket_name.data.strip()
        # docket_name = request.form.get('docket_name')

        # Check if the docket name already exists
        if db.session.query(Dockets).filter_by(name=docket_name).first():
            flash("Docket is already registered.", "danger")
            return redirect(url_for('manage_dockets'))

        #Create the new docket
        if action == 'add':
            try:
                new_docket = Dockets(name=docket_name, department_id=department_id, created_at=datetime.now())
                db.session.add(new_docket)
                db.session.commit()
                flash(f"Docket '{docket_name}' added successfully.", "success")
                
            except Exception as e:
                db.session.rollback()
                print(f"Insertion error: {e}")
                flash("Failed to create new docket")
            

        #Delete the docket
        elif action == 'delete':

            docket_id = request.form.get('docket_id')

            docket = db.session.execute(db.select(Dockets).filter_by(docket_id=docket_id)).scalar_one()
            if docket:
                try:
                    docket.deleted_at = datetime.datetime.now()  # Implementing soft delete
                    db.session.commit()
                    flash(f"Docket {docket.name} deleted successfully","success")
                except Exception as e:
                    db.session.rollback()
                    print(f"Deletion error: {e}")
                    flash("Failed to delete the docket")
            else:
                flash("Invalid docket ID.", "danger")

        return redirect(url_for('manage_dockets'))

    # Query all active dockets (excluding soft-deleted ones)
    dockets = db.session.execute(db.select(Dockets).filter_by(department_id=department_id, deleted_at = None)).scalars()
    return render_template('admins/manage_dockets.html', department=department, dockets=dockets , form=form)


#super admin dashboard
@app.route('/super_admin_dashboard')
@login_required
def super_admin_dashboard():
    # Code for displaying the dashboard
    # users = db.session.execute(db.select(Users)).scalars().all()
    # departments = db.session.execute(db.select(Department)).scalars().all()
    # Show different data based on the role (admin or viewer)
    
    user_role = session.get('user_role')
    return render_template('dashboard/super_admin_dashboard.html', user_role=user_role)


#admin dashboard
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    # Code for displaying the dashboard
    # Show different data based on the role (admin or viewer)
    
    user_role = session.get('user_role')
    return render_template('dashboard/admin_dashboard.html', user_role=user_role)


#viewer dashboard
@app.route('/viewer_dashboard')
@login_required
def viewer_dashboard():
    # Code for displaying the dashboard
    # Show different data based on the role (admin or viewer)
    
    user_role = session.get('user_role')
    return render_template('dashboard/viewer_dashboard.html', user_role=user_role)


def viewer_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_role') != 'viewer':
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/view_feedback', methods=['GET', 'POST'])
@viewer_required
def view_feedback():
    try:
        form = FeedbackViewForm()
        
        if form.validate_on_submit():
            feedback_type = form.feedback_type.data
        else:
            feedback_type = request.args.get('feedback_type', 'general')
        
        feedback = db.session.query(Feedback).filter(
            Feedback.type == feedback_type,
            Feedback.status == 'answered'
        ).order_by(Feedback.date_answered.desc()).all()
        
        return render_template(
            'view_feedback.html',
            form=form,
            feedback=feedback,
            feedback_type=feedback_type
        )
    except Exception as e:
        db.session.rollback()
        print(f"Deletion error: {e}")
        flash("Failed to delete the feedback")
        return redirect(url_for('view_feedback'))


@app.route('/view_department_activity', methods=['GET', 'POST'])
@viewer_required
def view_department_activity():
    try:
        form = DepartmentActivityViewForm()
        activities = db.session.query(DepartmentActivity)\
            .order_by(DepartmentActivity.date.desc()).all()
        
        return render_template(
            'view_department_activity.html',
            form=form,
            activities=activities
        )
    except Exception as e:
        db.session.rollback()
        print(f"Deletion error: {e}")
        flash("Failed to delete the activity")
        return redirect(url_for('view_department_activity'))
    

# @app.route('/view_announcements', methods=['GET', 'POST'])
# @viewer_required
# def view_announcements():
#     try:
#         form = AnnouncementViewForm()
#         announcements = db.session.query(Announcement)\
#             .order_by(Announcement.date.desc()).all()
        
#         return render_template(
#             'view_announcements.html',
#             form=form,
#             announcements=announcements
#         )
#     except Exception as e:
#         db.session.rollback()
#         print(f"Deletion error: {e}")
#         flash("Failed to delete the announcement")
#         return redirect(url_for('view_announcements'))
    
    
# @app.route('/view_performance_metrics', methods=['GET', 'POST'])
# @viewer_required
# def view_performance_metrics():
#     form = PerformanceMetricsViewForm()
#     metrics = db.session.query(PerformanceMetrics)\
#         .order_by(PerformanceMetrics.date.desc()).all()
    
#     return render_template(
#         'view_performance_metrics.html',
#         form=form,
#         metrics=metrics
#     )

# @app.route('/view_department_performance', methods=['GET', 'POST'])
# @viewer_required
# def view_department_performance():
#     form = DepartmentPerformanceViewForm()
#     departments = Department.query.all()
    
#     return render_template(
#         'view_department_performance.html',
#         form=form,
#         departments=departments
#     )

@app.route('/view_announcements', methods=['GET', 'POST'])
@viewer_required
def view_announcements():
    form = AnnouncementViewForm()
    announcements = db.session.query(Announcement)\
        .order_by(Announcement.date.desc()).all()
    
    return render_template(
        'view_announcements.html',
        form=form,
        announcements=announcements
    )

@app.route('/manage_announcements')
@login_required
@role_required('admin')
def manage_announcements():
    form = AddAnnouncementForm()  # Instantiate the form to add_announcement()
    
    try:
        if request.method == 'POST' and form.validate_on_submit():
            action = request.form.get('action')
            title = form.title.data.strip()
            content = form.content.data.strip()

            if action == 'add':
                try:
                    new_announcement = Announcement(title=title, content=content)
                    db.session.add(new_announcement)
                    db.session.commit()
                    flash('Announcement added successfully!', 'success')
                    return redirect(url_for('manage_announcements'))
                except Exception as e:
                    db.session.rollback()
                    print(f"Insertion error: {e}")
                    flash("Failed to create new announcement")
                    return redirect(url_for('manage_announcements'))
                
            elif action == 'delete':
                
                announcement_id = request.form.get('announcement_id')
                announcement = db.session.execute(db.select(Announcement).filter_by(announcement_id=announcement_id)).scalar_one()
                try:
                    announcement.deleted_at = datetime.datetime.now()  # Implementing soft delete
                    db.session.commit()
                    flash('Announcement deleted successfully!', 'success')
                    return redirect(url_for('manage_announcements'))
                except Exception as e:
                    db.session.rollback()
                    print(f"Deletion error: {e}")
                    flash("Failed to delete the announcement")
                    return redirect(url_for('manage_announcements'))
                
            return redirect(url_for('manage_announcements'))
    except Exception as e:
        db.session.rollback()
        print(f"Deletion error: {e}")
        flash("Failed to delete the announcement")
        return redirect(url_for('manage_announcements'))
    
    # Query all announcements (excluding soft-deleted ones)
    announcements = db.session.execute(db.select(Announcement).filter_by(deleted_at = None)).scalars()  # Fetch non-deleted announcements
    
    
    return render_template('admins/manage_announcements.html', announcements=announcements, form=form)


@app.route('/department_activity', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def department_activity():
        
    form = DepartmentActivityForm()
    
    # Add new department activity
    # form.activity.choices = [(activity.activity_id, activity.activity_description) for activity in DepartmentActivity.query.all()]
    try:
        if request.method == 'POST' and form.validate_on_submit():
            activity_description = form.activity_description.data.strip()
            new_form_id = db.session.query(db.func.coalesce(db.func.max(DepartmentActivity.form_id), 0) + 1).scalar()
            try:
                activity_description = request.form['activity_description'].strip()
                new_activity_description = DepartmentActivity(activity_description=activity_description , created_at=datetime.now(),form_id=new_form_id)
                db.session.add(new_activity_description)
                db.session.commit()
                flash('Department activity successfully recorded!', 'success')
                return redirect(url_for('department_activity'))
            except Exception as e:
                db.session.rollback()
                print(f"Insertion error: {e}")
                flash("Failed to record department activity")
            return redirect(url_for('department_activity'))
    except Exception as e:
        db.session.rollback()
        print(f"Deletion error: {e}")
        flash("Failed to delete the announcement")
        return redirect(url_for('department_activity'))

    # Fetch all department activities (excluding soft-deleted ones)
    activities = db.session.execute(db.select(DepartmentActivity).filter_by(is_deleted = None)).scalars()  # Fetch non-deleted announcements
    return render_template('department_activity.html', activities=activities, form=form)


# Allowed templates that can be accessed
#ALLOWED_TEMPLATES = {'login.html', '.html', 'assign_role.html' , 'add_questions.html', 'dashboard.html' , 'create_campaign.html' , 'general_feedback.html' , 'docket_feedback.html' , 'service_feedback.html', 'manage_dockets.html' , 'manage_announcements.html' , 'department_activity.html'}

# @app.route('/view/<path:filename>')
# def secure_serve_template(filename):
#     """
#     Securely serves only allowed HTML templates, preventing directory traversal attacks.
#     """
#     # Allow only letters, numbers, dashes, and underscores in filenames
#     if not re.match(r'^[a-zA-Z0-9_-]+\.html$', filename):
#         abort(403)  # Forbidden access

#     # Check if the requested file is in the allowed list
#     if filename not in ALLOWED_TEMPLATES:
#         abort(403)  # Forbidden

#     return render_template(filename)



logging.basicConfig(filename='security.log', level=logging.WARNING)
@app.errorhandler(403)
def forbidden_access(error):
    logging.warning(f"403 Forbidden: Attempted access by {request.remote_addr} to {request.path}")
    return "Access Forbidden", 403