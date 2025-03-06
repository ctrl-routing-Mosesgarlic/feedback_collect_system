from flask import redirect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField, RadioField, HiddenField, DateTimeField, BooleanField, FileField, FieldList, FormField, DateField
from wtforms.validators import DataRequired, Email, EqualTo, Length, AnyOf, Optional , ValidationError
from flask_wtf.file import FileAllowed
from werkzeug.utils import secure_filename
import random
from sqlalchemy import desc
from sqlalchemy.exc import SQLAlchemyError

from models import Users, Department, Base, Dockets, Campaign, Announcement, DepartmentActivity, Question, db


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

    # def validate_email(self, email):
    #     if not Users.validate_strathmore_email(email.data):
    #         raise ValidationError("Please use a valid Strathmore email address.")
        
    #     user = Users.query.filter_by(email=email.data).first()
    #     if user is not None:
    #         raise ValidationError("Email is already registered.")
        
    #     return email
    # def validate_password(self, password):
    #     if not Users.validate_password_strength(password.data):
    #         raise ValidationError("Password does not meet strength requirements. It must be at least 12 characters long and include uppercase, lowercase, number, and special character.")or password
        

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
    
    # def validate_email(self, email):
    #     if not Users.validate_strathmore_email(email.data):
    #         raise ValidationError("Please use a valid Strathmore email address.")
        
    #     user = Users.query.filter_by(email=email.data).first()
    #     if user is None:
    #         raise ValidationError("Email is not registered.")
    #     elif not user.email_verified:
    #         raise ValidationError("Email is not verified. Please verify your email before logging in.")
    #     elif not user.is_active:
    #         raise ValidationError("Account is not active. Please contact admin for further details.")
    #     else:
    #         return user


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
    
    def __init__(self, admins):
        super().__init__()
        self.admin_id.choices = [(admin.user_id, admin.name) for admin in admins]
        self.admin_id.choices.insert(0, ('', 'Select Admin'))
        self.admin_id.default = ''
        self.process()
        
    def validate_name(self, name):
        if db.session.query(Department).filter_by(name=name).first():
            raise ValidationError("Department is already registered.")
        
        return name
        
    def validate_admin_id(self, admin_id):
        admin_user = db.session.execute(db.select(Users).filter_by( user_id=admin_id, role='admin')).scalar_one()
        if not admin_user:
            raise ValidationError("Selected admin does not exist or is not eligible.")
        return admin_id


class CreateCampaignForm(FlaskForm):
    title = StringField(
        'Campaign Title',
        validators=[
            DataRequired(message="Campaign title is required."),
            Length(min=1, max=100, message="Campaign title must be less than 100 characters.")
        ],
        render_kw={"placeholder": "Enter campaign title"}
    )
    description = TextAreaField(
        'Campaign Description',
        validators=[
            DataRequired(message="Description is required."),
            Length(max=500, message="Description must be less than 500 characters.")
        ],
        render_kw={"placeholder": "Describe the purpose of this campaign", "rows": 5}
    )
    campaign_type = SelectField(
        'Campaign Type',
        validators=[DataRequired(message="Campaign type is required.")],
        choices=[('valid', 'valid'), ('invalid', 'invalid')],
        render_kw={"placeholder": "Select Type"}
    )
    start_date = DateField(
        'Start Date',
        validators=[DataRequired(message="Start date is required.")],
        format='%Y-%m-%d'
    )
    end_date = DateField(
        'End Date',
        validators=[DataRequired(message="End date is required.")],
        format='%Y-%m-%d'
    )
    submit = SubmitField('Create Campaign')
    
    def validate_title(self, title):
        """
        Custom validation for the title field.
        Ensures the title is unique or appends a number if a similar title exists.
        """
        base_title = title.data.strip()
        similar_campaigns = db.session.query(Campaign)\
            .filter(Campaign.title.like(f"{base_title}%"))\
            .order_by(Campaign.title.desc())\
            .all()
            
        if similar_campaigns:
            max_number = 0
            for campaign in similar_campaigns:
                campaign_title = campaign.title
                if campaign_title == base_title:
                    max_number = max(max_number, 1)
                    continue
                    
                # Extract number from title (if exists)
                if campaign_title.startswith(base_title + " (") and campaign_title.endswith(")"):
                    try:
                        num = int(campaign_title[len(base_title)+2:-1])
                        max_number = max(max_number, num)
                    except ValueError:
                        continue
                        
            if max_number > 0:
                new_title = f"{base_title} ({max_number + 1})"
                if len(new_title) > 100:
                    raise ValidationError("Campaign title would exceed maximum length with added suffix.")
                # Instead of modifying the data, raise an error and let the user decide
                raise ValidationError(f"A similar title already exists. Suggested title: {new_title}")
        
        return True
        
    def validate_end_date(self, end_date):
        """
        Custom validation for the end_date field.
        Ensures the end date is after the start date.
        """
        if self.start_date.data and end_date.data and end_date.data < self.start_date.data:
            raise ValidationError("End date must be after start date.")
        return True
    
class QuestionForm(FlaskForm):
    """Form for adding questions to a feedback campaign."""
    question_text = TextAreaField(
        'Question',
        validators=[
            DataRequired(message="Question text is required"),
            Length(min=10, max=500, message="Question must be between 10 and 500 characters")
        ]
    )

    def validate_question_text(self, field):
        # Check for duplicate questions in the same campaign
        if db.session.query(Question).filter_by(question_text=field.data, form_id=self.form_id.data).first():
            raise ValidationError("Question already exists in this campaign.")
        
        # Check for invalid question format
        if not field.data.strip():
            raise ValidationError("Question must not be empty.")
        
        return field

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.question_text.validators.append(self.validate_question_text)
        self.process()
    
# class CreateCampaignForm(FlaskForm):
#     title = StringField('Title', validators=[DataRequired(), Length(min=1, max=100)])
#     description = TextAreaField('Description', validators=[DataRequired(), Length(min=1, max=500)])
#     feedback_type = HiddenField('Feedback Type', validators=[
#         DataRequired(),
#         AnyOf(['general', 'docket-wise', 'service-wise'], message='Invalid feedback type')
#     ])
#     submit = SubmitField('Create Campaign')
    

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
    
    
class DepartmentActivityForm(FlaskForm):
    activity_description = TextAreaField(
        'Activity Description',
        validators=[
            DataRequired(message="Activity description is required."),
            Length(max=500, message="Description must be less than 500 characters.")
        ]
    )
    submit = SubmitField('Add Activity')
    
    
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
    
    
    
#----------------------------------------------------------------
#viewer classes for forms
#for feedback view form
class FeedbackViewForm(FlaskForm):
    feedback_type = SelectField(
        'Feedback Type',
        choices=[
            ('general', 'General Feedback'),
            ('docket', 'Docket Feedback'),
            ('service', 'Service Feedback')
        ],
        validators=[DataRequired()]
    )
    submit = SubmitField('View Feedback')



#for department_activity
class DepartmentActivityViewForm(FlaskForm):
    submit = SubmitField('Refresh Activities')
    
    
class AnnouncementViewForm(FlaskForm):
    submit = SubmitField('Refresh Announcements')
    
#----------------------------------------------------------------
    
    


# class CreateCampaignForm(FlaskForm):
#     title = StringField('Title', validators=[DataRequired(), Length(min=1, max=255)])
#     description = TextAreaField('Description', validators=[DataRequired()])
#     feedback_type = HiddenField('Feedback Type', validators=[
#         DataRequired(),
#         AnyOf(['general', 'docket', 'service'])
#     ])