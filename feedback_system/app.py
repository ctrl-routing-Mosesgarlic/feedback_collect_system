from flask import Flask, request, render_template, flash, redirect, url_for , session; from flask_cors import CORS;
from flask import Flask, jsonify, json
from flask import Flask
from sqlalchemy.orm.exc import NoResultFound
from flask_login import current_user, login_required,LoginManager,UserMixin, AnonymousUserMixin
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from config import Config
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask import abort, current_app
import datetime
import logging, re

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
from sqlalchemy.exc import SQLAlchemyError

from flask import redirect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField, RadioField, HiddenField, DateTimeField, BooleanField, FileField
from wtforms.validators import DataRequired, Email, EqualTo, Length, AnyOf, Optional , ValidationError
from flask_wtf.file import FileAllowed
from werkzeug.utils import secure_filename
import random


import os
import qrcode
from PIL import Image, ImageDraw
from flask import Flask, request, send_file
from io import BytesIO




# import routes  # Import routes (we’ll create this later)
from models import Campaign, Feedback, Department ,Users, Question, Dockets, Announcement, DepartmentActivity, FeedbackQuestion
# from models import *
# with app.app_context():            #import app and db from your app package
#     db.create_all()                #create the tables based on models




app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
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
    default_limits=["1000 per day"],
    storage_uri=app.config["RATELIMIT_STORAGE_URL"],
    app=app,  # Pass app as a keyword argument
    
)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# User class
class User(UserMixin):
    def __init__(self, id):
        self.id = id

# User loader callback
@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

# Initialize Talisman with Content Security Policy
# talisman = Talisman(app,
#     content_security_policy={
#         'default-src': '\'self\'',
#         'script-src': ['\'self\'', 'https://cdnjs.cloudflare.com'],
#     }
# )

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

class SearchForm:
    def __init__(self):
        self.csrf_token = generate_csrf()

class RegisterForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired()])
    email = StringField('Strathmore Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=12, message="Password must be at least 12 characters long"),
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message="Passwords must match"),
    ])
    submit = SubmitField('Register')

    def validate_email(self, email):
        if not Users.validate_strathmore_email(email.data):
            raise ValidationError("Please use a valid Strathmore email address.")

class LoginForm(FlaskForm):
    email = StringField(
        'Strathmore Email', validators=[DataRequired(message="Strathmore Email is required."),
            Email(message="Please enter a valid Strathmore email address."),
            Length(max=120, message="Email must be less than 120 characters.")
        ],
        # render_kw={"placeholder": "Enter your email"}  # Optional: Adds a placeholder to the email input field
    )
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message="Password is required."),
            Length(min=12, message="Password must be at least 12 characters long.")
        ],
        # render_kw={"placeholder": "Enter your password"}  # Optional: Adds a placeholder to the password input field
    )
    submit = SubmitField('Login')
    
class AssignRoleForm(FlaskForm):
    email = StringField(
        'Email',
        validators=[
            DataRequired(message="Email is required."),
            Email(message="Please enter a valid email address."),
            Length(max=120, message="Email must be less than 120 characters.")
        ]
    )
    role = SelectField(
        'Role',
        choices=[
        ('viewer', 'Viewer'), ('admin', 'Admin'), ('super_admin', 'Super Admin')],  # Add other roles as needed
        validators=[DataRequired(message="Role is required.")]
    )
    submit = SubmitField('Assign Role')
    
class AddDepartmentForm(FlaskForm):
    name = StringField(
        'Department Name',
        validators=[
            DataRequired(message="Department name is required."),
            Length(max=100, message="Department name must be less than 100 characters.")
        ],
        render_kw={"placeholder": "Enter department name"}
    )
    admin_id = SelectField(
        'Assign Admin',
        coerce=int,  # Ensure the selected value is treated as an integer
        validators=[DataRequired(message="Please select an admin.")]
    )
    submit = SubmitField('Add Department')
    
class AddDocketForm(FlaskForm):
    docket_name = StringField(
        'Docket Name',
        validators=[
            DataRequired(message="Docket name is required."),
            Length(max=100, message="Docket name must be less than 100 characters.")
        ],
        render_kw={"placeholder": "Enter docket name"}
    )
    submit = SubmitField('Add Docket')
    
class AddAnnouncementForm(FlaskForm):
    title = StringField(
        'Title',
        validators=[
            DataRequired(message="Title is required."),
            Length(max=100, message="Title must be less than 100 characters.")
        ],
        render_kw={"placeholder": "Enter announcement title"}
    )
    content = TextAreaField(
        'Content',
        validators=[
            DataRequired(message="Content is required."),
            Length(max=500, message="Content must be less than 500 characters.")
        ],
        render_kw={"placeholder": "Enter announcement content", "rows": 5}
    )
    submit = SubmitField('Add Announcement')
    
    
class CreateCampaignForm(FlaskForm):
    title = StringField(
        'Campaign Title',
        validators=[
            DataRequired(message="Campaign title is required."),
            Length(max=100, message="Campaign title must be less than 100 characters.")
        ],
        render_kw={"placeholder": "Enter campaign title"}
    )
    description = TextAreaField(
        'Description',
        validators=[
            DataRequired(message="Description is required."),
            Length(max=500, message="Description must be less than 500 characters.")
        ],
        render_kw={"placeholder": "Enter campaign description", "rows": 5}
    )
    feedback_type = SelectField(
        'Feedback Type',
        choices=[
            ('general', 'General'),
            ('docket-wise', 'Docket-wise'),
            ('service-wise', 'Service-wise')
        ],
        validators=[DataRequired(message="Feedback type is required.")]
    )
    submit = SubmitField('Create Campaign')
    

class DepartmentActivityForm(FlaskForm):
    activity_description = TextAreaField(
        'Activity Description',
        validators=[
            DataRequired(message="Activity description is required."),
            Length(max=500, message="Description must be less than 500 characters.")
        ]
    )
    submit = SubmitField('Add Activity')
    
class CreateCampaignForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=1, max=100)])
    description = TextAreaField('Description', validators=[DataRequired(), Length(min=1, max=500)])
    feedback_type = HiddenField('Feedback Type', validators=[
        DataRequired(),
        AnyOf(['general', 'docket-wise', 'service-wise'], message='Invalid feedback type')
    ])
    
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
@role_required('super_admin')
def assign_role():
    # # Check if the user is authenticated and has the 'role' attribute
    # if not current_user.is_authenticated:
    #     flash("Please log in to access this page.", "danger")
    #     return redirect(url_for('login'))  # Redirect to the login page
    
    # # Check if current user is super_admin
    # if current_user.role != 'super_admin':
    #     flash("Only super administrators can assign roles.", "danger")
    #     return redirect(url_for('index'))
    
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
    
    # Get all users for display
    users = Users.query.all()
    return render_template('assign_role.html' , users=users, form=form)


@app.route('/add_department', methods=['GET', 'POST'])
@login_required
@role_required('super_admin')
def add_department():
    form = AddDepartmentForm()
    
    # Populate the admin_id dropdown with eligible admins
    form.admin_id.choices = [(admin.user_id, admin.name) for admin in Users.query.filter_by(role='admin').all()]
    
    
    # if request.method == 'POST'
    #     name = request.form['name'].strip()
    #     admin_id = request.form.get('user_id')
    if form.validate_on_submit():
        name = form.name.data.strip()
        admin_id = form.admin_id.data
        
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
            new_department = Department(name=name, created_at=datetime.now())
            db.session.add(new_department)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"Insertion error: {e}")
            flash("Failed to create new department")

        #Assign the selected admin to the new department
        try:
            admin_user.department_id = new_department.department_id
            db.session.commit()
        except Exception as e:
            print(f"Update error: {e}")
            flash("Failed to assign admin user to a department")
        
        flash(f"Department '{name}' added and assigned to {admin_user.name}.", "success")
        return redirect(url_for('add_department'))
    
    # Get a list of eligible admin users to assign
    eligible_admins = Users.query.filter_by(role='admin').all()
    departments = db.session.execute(db.select(Department)).scalars()
    
    # Query all active departments (excluding soft-deleted ones)
    departments = Department.query.filter(Department.deleted_at.is_(None)).all()
    
    return render_template('manage_departments.html', eligible_admins=eligible_admins, departments=departments , form=form)




@app.route('/delete_department/<int:department_id>', methods=['POST'])
@login_required
@role_required('super_admin')
def delete_department(department_id):
    # department = Department.query.get_or_404(department_id)
    
    # Fetch the department by its ID
    department = db.session.execute(db.select(Department).filter_by(department_id=department_id)).scalar_one_or_none()  # Use scalar_one_or_none() to handle cases where the department might not exist


    # name = request.form['name'].strip()
    # department = db.session.execute(db.select(Department)).scalar_one()

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
            return render_template('register.html' , form=form)

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
            return render_template('register.html', form = form)

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
        
    return render_template('register.html' , form=form)

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
                    return redirect(url_for('dashboard'))  # Viewer route
            else:
                flash("Invalid email or password", "danger")
        except Exception as e:
            db.session.rollback()
            print(f"Login error: {str(e)}")  # Log the error for debugging
            flash("Login failed. Please try again.", "danger")
            return redirect(url_for('login'))
        
    return render_template('login.html' , form=form)

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
    email_verified = db.Column(db.Boolean, default=False)
    
    # created_at = db.Column(db.DateTime, server_default=func.now())
    # updated_at = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now())
    # deleted_at = db.Column(db.DateTime, nullable=True)

    @classmethod
    def validate_strathmore_email(cls, email):
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
        self.deleted_at = datetime.datetime.now()
        db.session.commit()

@app.route('/create_campaign', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def create_campaign():
    form = CreateCampaignForm()
    
    # Handle GET request with feedback_type parameter
    if request.method == 'GET':
        feedback_type = request.args.get('feedback_type')
        if feedback_type in ['general', 'docket-wise', 'service-wise']:
            form.feedback_type.data = feedback_type
    
    # Handle POST request
    if request.method == 'POST' and form.validate_on_submit():
        try:
            # Get current user and verify department
            current_user = db.session.execute(
                db.select(Users).filter_by(email=session['email'])
            ).scalar_one()
            
            if not hasattr(current_user, 'department_id') or current_user.department_id is None:
                return jsonify({
                    'success': False,
                    'message': "Your account is not associated with any department."
                })

            # Create new campaign
            try:
                new_campaign = Campaign(
                    title=form.title.data.strip(),
                    description=form.description.data.strip(),
                    department_id=current_user.department_id,
                    feedback_type=form.feedback_type.data
                )
                db.session.add(new_campaign)
                db.session.commit()
                return jsonify({
                'success': True,
                'campaign_id': new_campaign.campaign_id
                })
            except Exception as e:
                db.session.rollback()
                print(f"Insertion error: {e}")
                return jsonify({
                    'success': False,
                    'message': "An error occurred while creating the campaign."
                })

        except NoResultFound:
            return jsonify({
                'success': False,
                'message': "An error occurred while creating the campaign."
            })
    # If form validation failed on POST
    if request.method == 'POST':
        return jsonify({
            'success': False,
            'message': "Please check the form for errors."
        })

    return render_template('create_campaign.html', form=form)

@app.route('/general_feedback/<int:campaign_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def general_feedback(campaign_id):
    try:
        campaign = db.session.execute(
            db.select(Campaign).filter_by(campaign_id=campaign_id)
        ).scalar_one()
        
        # Create form instance for CSRF token
        form = GeneralFeedbackForm()
        
        if campaign.feedback_type != 'general':
            if request.is_xhr:  # Check if it's an AJAX request
                return jsonify({'error': 'Invalid feedback type'}), 400
            flash("Invalid feedback type for this campaign.", "error")
            return redirect(url_for('dashboard'))
            
        if request.method == 'POST':
            if not form.validate():  # Validate CSRF token
                if request.is_xhr:
                    return jsonify({'error': 'Invalid CSRF token'}), 400
                flash("Invalid CSRF token.", "error")
                return redirect(url_for('dashboard'))
                
            if request.is_xhr:
                data = request.get_json()
                # Process your data
                return jsonify({'success': True, 'message': 'Feedback submitted'})
            
            # Handle regular form submission
            try:
                # Get form data
                question_text = request.form.get('question')
                question_type = request.form.get('question_type')
                
                # Validate form data
                if not question_text or not question_type:
                    flash("Question and question type are required.", "error")
                    return redirect(url_for('general_feedback', campaign_id=campaign_id))
                
                # Create new feedback question
                new_question = FeedbackQuestion(
                    campaign_id=campaign_id,
                    question=question_text,
                    question_type=question_type,
                    created_at=datetime.now(),
                    created_by=current_user.id
                )
                
                # Add to database
                db.session.add(new_question)
                db.session.commit()
                
                flash("Question added successfully!", "success")
            except Exception as e:
                db.session.rollback()
                flash("Error adding question. Please try again.", "error")
                # Log the error
                current_app.logger.error(f"Error adding feedback question: {str(e)}")
            
            return redirect(url_for('general_feedback', campaign_id=campaign_id))
            
        # Get questions for the template
        questions = db.session.execute(
            db.select(FeedbackQuestion).filter_by(campaign_id=campaign_id)
        ).scalars().all()
        
        return render_template('general_feedback.html',
                            campaign=campaign,
                            form=form,  # Pass form to template
                            questions=questions)
                            
    except NoResultFound:
        if request.is_xhr:
            return jsonify({'error': 'Campaign not found'}), 404
        flash("Campaign not found.", "error")
        return redirect(url_for('dashboard'))
    
    except Exception as e:
        current_app.logger.error(f"Error retrieving campaign: {str(e)}")
        if request.is_xhr:
            return jsonify({'error': 'An error occurred'}), 500
        flash("An error occurred.", "error")
        return redirect(url_for('dashboard'))
    
    return render_template('general_feedback.html', campaign=campaign, form=form)

@app.route('/get_category_questions/<category>')
@login_required
def get_category_questions(category):
    # Define questions for each category
    questions = {
        'student-council': [
            {'question': 'Are you satisfied with the Student Council representation?', 'type': 'general'},
            {'question': 'How can the Student Council improve its services?', 'type': 'feedback'}
        ],
        'academic': [
            {'question': 'Are you satisfied with the quality of your courses?', 'type': 'rating'},
            {'question': 'How could we improve the academic workload?', 'type': 'feedback'}
        ],
        # Add other categories as needed
    }
    
    if category not in questions:
        return jsonify({'error': 'Invalid category'}), 400
        
    # Generate HTML for the questions
    html = render_template('_category_questions.html',
                        questions=questions[category],
                        category=category)
    
    return jsonify({'html': html})

@app.route('/docket_feedback/<int:campaign_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def docket_feedback(campaign_id):
    try:
        campaign = db.session.execute(
            db.select(Campaign).filter_by(campaign_id=campaign_id)
        ).scalar_one()
        
        # Create form instance for CSRF token
        form = DocketFeedbackForm()
        
        # Check if it's an AJAX request
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        
        # Validate campaign type
        if campaign.feedback_type != 'docket':
            if is_ajax:
                return jsonify({'error': 'Invalid feedback type'}), 400
            flash("Invalid feedback type.", "error")
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            # Validate CSRF token
            if not form.validate():
                if is_ajax:
                    return jsonify({'error': 'Invalid CSRF token'}), 400
                flash("Invalid CSRF token.", "error")
                return redirect(url_for('dashboard'))

            # Handle AJAX submission
            if is_ajax:
                data = request.get_json()
                # Process your data
                return jsonify({'success': True, 'message': 'Feedback submitted'})

            # Handle regular form submission
            try:
                # Get form data
                question_text = request.form.get('question')
                question_type = request.form.get('question_type')
                
                # Validate form data
                if not question_text or not question_type:
                    flash("Question and question type are required.", "error")
                    return redirect(url_for('docket_feedback', campaign_id=campaign_id))
                
                # Create new feedback question
                new_question = FeedbackQuestion(
                    campaign_id=campaign_id,
                    question=question_text,
                    question_type=question_type,
                    created_at=datetime.now(),
                    created_by=current_user.id
                )
                
                # Add to database
                db.session.add(new_question)
                db.session.commit()
                flash("Question added successfully!", "success")

            except Exception as e:
                db.session.rollback()
                flash("Error adding question. Please try again.", "error")
                # Log the error
                current_app.logger.error(f"Error adding feedback question: {str(e)}")

            return redirect(url_for('docket_feedback', campaign_id=campaign_id))

        # GET request - render template
        questions = db.session.execute(
            db.select(FeedbackQuestion).filter_by(campaign_id=campaign_id)
        ).scalars().all()
        
        return render_template('general_feedback.html',
                            campaign=campaign,
                            form=form,
                            questions=questions)

    except NoResultFound:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'error': 'Campaign not found'}), 404
        flash("Campaign not found.", "error")
        return redirect(url_for('dashboard'))

@app.route('/service_feedback/<int:campaign_id>')
@login_required
@role_required('admin')
def service_feedback(campaign_id):
    try:
        campaign = db.session.execute(
            db.select(Campaign).filter_by(campaign_id=campaign_id)
        ).scalar_one()
        
        if campaign.feedback_type != 'service':
            flash("Invalid feedback type for this campaign.", "error")
            return redirect(url_for('dashboard'))
            
        return render_template('service_feedback.html', campaign=campaign)
        
    except NoResultFound:
        flash("Campaign not found.", "error")
        return redirect(url_for('dashboard'))

from flask import jsonify, request, flash, redirect, url_for
from sqlalchemy.orm.exc import NoResultFound

@app.route('/save_general_feedback/<int:campaign_id>', methods=['POST'])
@login_required
@role_required('admin')
def save_general_feedback(campaign_id):
    try:
        form = GeneralFeedbackForm()
        
        # Verify campaign exists and is of correct type
        campaign = db.session.execute(
            db.select(Campaign).filter_by(
                campaign_id=campaign_id,
                feedback_type='general'
                )
            ).scalar_one()
        
        if not form.validate_on_submit():
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'success': False,
                    'errors': form.errors
                }), 400
            flash("Please correct the form errors.", "error")
            return redirect(url_for('general_feedback', campaign_id=campaign_id))

        try:
            # Handle file upload if present
            file_path = None
            if 'attachment' in request.files:
                file = request.files['attachment']
                file_path = handle_file_upload(file)

            # Create new feedback question
            new_question = FeedbackQuestion(
                campaign_id=campaign_id,
                question=form.question.data,
                question_type=form.question_type.data,
                attachment_path=file_path,
                created_at=datetime.now(),
                created_by=current_user.id
            )

            db.session.add(new_question)
            db.session.commit()

            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'success': True,
                    'message': 'Question added successfully!'
                })

            flash("Question added successfully!", "success")
            return redirect(url_for('general_feedback', campaign_id=campaign_id))

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error saving feedback question: {str(e)}")
            
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'success': False,
                    'error': 'An error occurred while saving the question.'
                }), 500

            flash("An error occurred while saving the question.", "error")
            return redirect(url_for('general_feedback', campaign_id=campaign_id))

    except NoResultFound:
        flash("Campaign not found or invalid feedback type.", "error")
        return redirect(url_for('dashboard'))

    except Exception as e:
        db.session.rollback()
        print(f"Error saving general feedback: {str(e)}")
        flash("An error occurred while saving the question.", "error")

    return redirect(url_for('general_feedback', campaign_id=campaign_id))

@app.route('/save_docket_feedback/<int:campaign_id>', methods=['POST'])
@login_required
@role_required('admin')
def save_docket_feedback(campaign_id):
    try:
        # Verify campaign exists and is of correct type
        campaign = db.session.execute(
            db.select(Campaign).filter_by(
                campaign_id=campaign_id,
                feedback_type='docket'
            )
        ).scalar_one()
        
        # Validate required fields
        docket_number = request.form.get('docket_number', '').strip()
        question = request.form.get('question', '').strip()
        
        if not docket_number or not question:
            flash("Docket number and question are required.", "error")
            return redirect(url_for('docket_feedback', campaign_id=campaign_id))
            
        # Create new feedback question
        new_question = FeedbackQuestion(
            campaign_id=campaign_id,
            question=question,
            docket_number=docket_number,
            feedback_type='docket'
        )
        
        db.session.add(new_question)
        db.session.commit()
        
        flash("Question added successfully.", "success")
        
    except NoResultFound:
        flash("Campaign not found or invalid feedback type.", "error")
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        db.session.rollback()
        print(f"Error saving docket feedback: {str(e)}")
        flash("An error occurred while saving the question.", "error")
        
    return redirect(url_for('docket_feedback', campaign_id=campaign_id))

@app.route('/save_service_feedback/<int:campaign_id>', methods=['POST'])
@login_required
@role_required('admin')
def save_service_feedback(campaign_id):
    try:
        # Verify campaign exists and is of correct type
        campaign = db.session.execute(
            db.select(Campaign).filter_by(
                campaign_id=campaign_id,
                feedback_type='service'
            )
        ).scalar_one()
        
        # Validate required fields
        service_name = request.form.get('service_name', '').strip()
        question = request.form.get('question', '').strip()
        
        if not service_name or not question:
            flash("Service name and question are required.", "error")
            return redirect(url_for('service_feedback', campaign_id=campaign_id))
            
        # Create new feedback question
        new_question = FeedbackQuestion(
            campaign_id=campaign_id,
            question=question,
            service_name=service_name,
            feedback_type='service'
        )
        
        db.session.add(new_question)
        db.session.commit()
        
        flash("Question added successfully.", "success")
        
    except NoResultFound:
        flash("Campaign not found or invalid feedback type.", "error")
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        db.session.rollback()
        print(f"Error saving service feedback: {str(e)}")
        flash("An error occurred while saving the question.", "error")
        
    return redirect(url_for('service_feedback', campaign_id=campaign_id))

@app.route('/add_questions/<int:campaign_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def add_questions(campaign_id):
    campaign = db.session.execute(db.select(Campaign).filter_by(campaign_id=campaign_id)).scalar_one()
    feedback_type = campaign.feedback_type

    # Define default questions based on feedback type
    if feedback_type == 'general':
        default_questions = [
            'What is your overall satisfaction with our services?',
            'What areas do you think we can improve?',
            'Any additional comments?'
        ]
        question_types = ['general'] * len(default_questions)

    elif feedback_type == 'docket':
        # Get the department ID from the campaign
        department_id = campaign.department_id

        # Check if the form has been submitted
        if request.method == 'POST':
            docket_choice = request.form.get('docket_choice')  # This should be set from the form input

            if docket_choice == 'specific':
                specific_docket_name = request.form.get('specific_docket_name')
                specific_docket = db.session.execute(
                    db.select(Dockets).filter_by(name=specific_docket_name, department_id=department_id, deleted_at=None)
                ).scalar_one_or_none()

                if specific_docket:
                    default_questions = [
                        f'Feedback for {specific_docket.name}:',
                        'What is your feedback/idea/complaint?',
                        'What should be brought back and why? (optional)'
                    ]
                    question_types = ['docket', 'feedback', 'optional']
                else:
                    # Flash message when the specified docket does not exist
                    flash('The specified docket does not exist or is not available.', 'error')
                    return redirect(url_for('add_questions', campaign_id=campaign_id))  # Redirect to try again

            elif docket_choice == 'all':
                # Fetch all dockets related to the department
                dockets = db.session.execute(
                    db.select(Dockets).filter_by(department_id=department_id, deleted_at=None)
                ).scalars()

                docket_names = [docket.name for docket in dockets]

                if not docket_names:
                    default_questions = [
                        'No available dockets for feedback at this time.',
                        'Please provide your feedback/idea/complaint:'
                    ]
                    question_types = ['info', 'feedback']
                else:
                    default_questions = [
                        f'Please select a docket from the following: {", ".join(docket_names)}',
                        'What is your feedback/idea/complaint?',
                        'What should be brought back and why? (optional)'
                    ]
                    question_types = ['docket', 'feedback', 'optional']

        else:
            # If it's a GET request, show options for choosing a docket
            return render_template('choose_docket.html', campaign=campaign)

    elif feedback_type == 'service':
        default_questions = [
            'How would you rate our services?',
            'What improvements can be made?',
            'Please provide any additional feedback regarding our services.'
        ]
        question_types = ['rating', 'improvement', 'feedback']

    else:
        default_questions = []
        question_types = []

    if request.method == 'POST':
        questions = request.form.getlist('questions')
        questions_type = request.form.getlist('questions_type')

        for question_text, question_type in zip(questions, questions_type):
            new_question = Question(
                campaign_id=campaign_id,
                question_text=question_text,
                question_type=question_type,
                created_at=datetime.datetime.now()
            )
            db.session.add(new_question)

        db.session.commit()
        flash(f"Questions added successfully to the campaign '{campaign.title}'.", "success")
        return redirect(url_for('create_feedback_form', campaign_id=campaign.campaign_id))

    return render_template('add_questions.html', campaign=campaign, default_questions=default_questions, question_types=question_types)


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

# Your existing generate_qr route with CSRF protection
@app.route('/generate', methods=['POST'])
@csrf.exempt  # If you want to exempt this route from CSRF protection
def generate_qr():
    # Get form data
    url = request.form.get('url')
    fg_color_type = request.form.get('fg_color_type', 'single')
    single_color = request.form.get('single_color', 'black')
    gradient_start = request.form.get('gradient_start', '#000000')
    gradient_end = request.form.get('gradient_end', '#FFFFFF')
    eye_color = request.form.get('eye_color', '#FF0000')
    bg_color = request.form.get('bg_color', 'white')
    size = int(request.form.get('size', 10))
    img_format = request.form.get('format', 'PNG')

    # Handle logo
    logo_file = request.files.get('logo')
    logo_path = None
    if logo_file:
        logo_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(logo_file.filename))
        logo_file.save(logo_path)

    # Generate QR code
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=size,
        border=4
    )
    
    qr.add_data(url)
    qr.make(fit=True)
    qr_image = qr.make_image(fill_color="black", back_color=bg_color).convert('RGB')

    # Apply foreground styles
    if fg_color_type == 'single':
        qr_image = qr.make_image(fill_color=single_color, back_color=bg_color).convert('RGB')
    elif fg_color_type == 'gradient':
        qr_image = apply_gradient(qr_image, gradient_start, gradient_end)
    elif fg_color_type == 'custom_eyes':
        qr_image = apply_custom_eye_color(qr_image, qr, eye_color, bg_color)

    # Add logo if uploaded
    if logo_path:
        logo = Image.open(logo_path).convert("RGBA")
        logo = logo.resize((qr_image.size[0] // 4, qr_image.size[1] // 4))
        pos = ((qr_image.size[0] - logo.size[0]) // 2, (qr_image.size[1] - logo.size[1]) // 2)
        qr_image.paste(logo, pos, mask=logo)
        
        # Clean up the logo file
        os.remove(logo_path)

    # Save QR code to in-memory file
    img_io = BytesIO()
    qr_image.save(img_io, format=img_format)
    img_io.seek(0)
    
    mime_type = f"image/{img_format.lower()}" if img_format != "JPG" else "image/jpeg"
    return send_file(
        img_io,
        mimetype=mime_type,
        as_attachment=True,
        download_name=f'qr_code.{img_format.lower()}'
    )

# Keep your existing helper functions
def apply_gradient(image, start_color, end_color):
    """Apply gradient to the QR code."""
    gradient = Image.new('RGB', image.size, color=0)
    draw = ImageDraw.Draw(gradient)
    
    for y in range(gradient.height):
        r = int(start_color[1:3], 16) + (int(end_color[1:3], 16) - int(start_color[1:3], 16)) * y // gradient.height
        g = int(start_color[3:5], 16) + (int(end_color[3:5], 16) - int(start_color[3:5], 16)) * y // gradient.height
        b = int(start_color[5:7], 16) + (int(end_color[5:7], 16) - int(start_color[5:7], 16)) * y // gradient.height
        draw.line([(0, y), (gradient.width, y)], fill=(r, g, b))
    
    return Image.blend(image, gradient, alpha=0.5)

def apply_custom_eye_color(image, qr, eye_color, bg_color):
    """Apply custom color to QR code eyes."""
    qr_matrix = qr.modules
    eye_positions = [(6, 6), (len(qr_matrix) - 7, 6), (6, len(qr_matrix) - 7)]
    draw = ImageDraw.Draw(image)
    
    for ex, ey in eye_positions:
        box_size = image.size[0] // len(qr_matrix)
        x0, y0 = ex * box_size, ey * box_size
        x1, y1 = (ex + 7) * box_size, (ey + 7) * box_size
        draw.rectangle([x0, y0, x1, y1], fill=eye_color)
    
    return image


# @app.route('/submit_feedback/<int:campaign_id>', methods=['POST'])
# @login_required
# def submit_feedback(campaign_id):
#     campaign = db.session.execute(db.select(Campaign).filter_by(campaign_id=campaign_id)).scalar_one()
#     feedback_type = campaign.feedback_type

#     if feedback_type == 'general':
#         satisfaction_rating = request.form.get('satisfaction_rating')
#         improvement_areas = request.form.get('improvement_areas')
#         additional_comments = request.form.get('additional_comments')

#         # Save feedback to the database
#         new_feedback = Feedback(
#             campaign_id=campaign_id,
#             satisfaction_rating=satisfaction_rating,
#             improvement_areas=improvement_areas,
#             additional_comments=additional_comments,
#             created_at=datetime.now()
#         )
#         db.session.add(new_feedback)

#     elif feedback_type == 'docket':
#         docket_name = request.form.get('docket_name')
#         feedback = request.form.get('feedback')
#         bring_back = request.form.get('bring_back')

#         # Save feedback to the database
#         new_feedback = Feedback(
#             campaign_id=campaign_id,
#             docket_name=docket_name,
#             feedback=feedback,
#             bring_back=bring_back,
#             created_at=datetime.utcnow()
#         )
#         db.session.add(new_feedback)

#     elif feedback_type == 'service':
#         service_rating = request.form.get('service_rating')
#         improvements = request.form.get('improvements')
#         additional_feedback = request.form.get('additional_feedback')

#         # Save feedback to the database
#         new_feedback = Feedback(
#             campaign_id=campaign_id,
#             service_rating=service_rating,
#             improvements=improvements,
#             additional_feedback=additional_feedback,
#             created_at=datetime.now()
#         )
#         db.session.add(new_feedback)

#     db.session.commit()
#     flash("Thank you for your feedback!", "success")
#     return redirect(url_for('dashboard'))


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
    return render_template('manage_dockets.html', department=department, dockets=dockets , form=form)

@app.route('/super_admin_dashboard')
@login_required
def super_admin_dashboard():
    # Code for displaying the dashboard
    # Show different data based on the role (admin or viewer)
    
    user_role = session.get('user_role')
    return render_template('super_admin_dashboard.html', user_role=user_role)

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    # Code for displaying the dashboard
    # Show different data based on the role (admin or viewer)
    
    user_role = session.get('user_role')
    return render_template('admin_dashboard.html', user_role=user_role)

@app.route('/viewer_dashboard')
@login_required
def viewer_dashboard():
    # Code for displaying the dashboard
    # Show different data based on the role (admin or viewer)
    
    user_role = session.get('user_role')
    return render_template('viewer_dashboard.html', user_role=user_role)


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
    
    
    return render_template('manage_announcements.html', announcements=announcements, form=form)


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
            try:
                activity_description = request.form['activity_description'].strip()
                new_activity_description = DepartmentActivity(activity_description=activity_description , created_at=datetime.now())
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

    
# @app.route('/view_feedback/<int:campaign_id>', methods=['GET'])
# @login_required
# @role_required('admin', 'viewer')
# def view_feedback(campaign_id):
#     campaign = Campaign.query.get_or_404(campaign_id)
#     feedbacks = Feedback.query.filter_by(campaign_id=campaign_id).all()  # Customize this query as needed
#     return render_template('view_feedback.html', campaign=campaign, feedbacks=feedbacks)



# Allowed templates that can be accessed
ALLOWED_TEMPLATES = {'login.html', '.html', 'assign_role.html' , 'add_questions.html', 'dashboard.html' , 'create_campaign.html' , 'general_feedback.html' , 'docket_feedback.html' , 'service_feedback.html', 'manage_dockets.html' , 'manage_announcements.html' , 'department_activity.html'}

@app.route('/view/<path:filename>')
def secure_serve_template(filename):
    """
    Securely serves only allowed HTML templates, preventing directory traversal attacks.
    """
    # Allow only letters, numbers, dashes, and underscores in filenames
    if not re.match(r'^[a-zA-Z0-9_-]+\.html$', filename):
        abort(403)  # Forbidden access

    # Check if the requested file is in the allowed list
    if filename not in ALLOWED_TEMPLATES:
        abort(403)  # Forbidden

    return render_template(filename)



logging.basicConfig(filename='security.log', level=logging.WARNING)
@app.errorhandler(403)
def forbidden_access(error):
    logging.warning(f"403 Forbidden: Attempted access by {request.remote_addr} to {request.path}")
    return "Access Forbidden", 403

