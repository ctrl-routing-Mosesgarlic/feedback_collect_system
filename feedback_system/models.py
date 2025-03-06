from flask import Flask
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass

db=SQLAlchemy(model_class=Base)

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

class Users(db.Model):
    _tablename_ = 'users'  # Fix here: _tablename_ instead of tablename
    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum('super_admin', 'admin', 'viewer'), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey('department.department_id'),nullable =True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    deleted_at = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        from app import bcrypt
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        from app import bcrypt
        return bcrypt.check_password_hash(self.password_hash, password)

class Dockets(db.Model):
    _tablename_ = 'dockets'
    docket_id = db.Column(db.Integer, primary_key=True)
    department_id = db.Column(db.Integer, db.ForeignKey('department.department_id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    deleted_at = db.Column(db.DateTime, nullable=True, default = None)

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

class Users(db.Model):
    _tablename_ = 'users'  # Fix here: _tablename_ instead of tablename
    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum('super_admin', 'admin', 'viewer'), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey('department.department_id'),nullable =True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    deleted_at = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        from app import bcrypt
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        from app import bcrypt
        return bcrypt.check_password_hash(self.password_hash, password), db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    start_date = db.Column(db.DateTime)
    end_date = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.now)
    deleted_at = db.Column(db.DateTime, nullable=True)
    campaign_type = db.Column(db.String(50), nullable=False)  # valid or invalid
    # Add relationship
    forms = db.relationship('FormFeedback', backref='campaign', lazy=True)
    def __repr__(self):
        return f"<Campaign {self.title}>"

class Question(db.Model):
    _tablename_ = 'questions'
    question_id = db.Column(db.Integer, primary_key=True)
    form_id = db.Column(db.Integer, db.ForeignKey('form_feedback.form_id'), nullable=False)
    question_text = db.Column(db.Text, nullable=False)
    question_type = db.Column(db.Text, nullable=False)# general, docket, or service
    created_at = db.Column(db.DateTime, default=datetime.now)
    
# class FeedbackQuestion(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.campaign_id'), nullable=False)
#     question = db.Column(db.String(500), nullable=False)
#     question_type = db.Column(db.String(50))  # For general feedback
#     service_name = db.Column(db.String(100))  # For service feedback
#     feedback_type = db.Column(db.String(50), nullable=False)  # general, docket, or service
    
class FormFeedback(db.Model):
    _tablename_ = 'form_feedback'
    form_id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.campaign_id'), nullable=False)
    name = db.Column(db.String(500), nullable=False)
    version = db.Column(db.Integer, default=1)  # Track form versions
    status = db.Column(db.String(50), default='draft')  # draft, active, archived
    language = db.Column(db.String(50), default='en')  # Support multiple languages
    format = db.Column(db.String(50), default='web')  # web, mobile, print, kiosk
    logo_path = db.Column(db.String(255))
    location_details = db.Column(db.Text)
    is_template = db.Column(db.Boolean, default=False)
    modified_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    # Add relationship to questions
    questions = db.relationship('Question', backref='form', lazy=True)
    
    def __repr__(self):
        return f"<Form {self.name}>"
    
class FormUrl(db.Model):
    _tablename_ = 'form_urls'
    url_id = db.Column(db.Integer, primary_key=True)
    form_id = db.Column(db.Integer, db.ForeignKey('form_feedback.form_id'), nullable=False)
    url_code = db.Column(db.String(50), unique=True, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.now)

class Feedback(db.Model):
    _tablename_ = 'feedback'
    id = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.Integer, db.ForeignKey('question.question_id'), nullable=False)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.campaign_id'), nullable=False)
    response = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)

class Permission(db.Model):
    _tablename_ = 'permissions'
    permission_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    can_manage_dockets = db.Column(db.Boolean, default=False)
    can_manage_campaigns = db.Column(db.Boolean, default=True)
    department_id = db.Column(db.Integer, db.ForeignKey('department.department_id'))
    created_at = db.Column(db.DateTime, default=datetime.now)
    deleted_at = db.Column(db.DateTime, nullable=True)
    
class Announcement(db.Model):
    __tablename__ = 'announcements'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now, nullable=False)
    deleted_at = db.Column(db.DateTime, nullable=True)  # For soft deletion
    form_id = db.Column(db.Integer, db.ForeignKey('form_feedback.form_id'), nullable=False)

    def soft_delete(self):
        self.deleted_at = datetime.now()
        db.session.commit()

    def __repr__(self):
        return f"<Announcement(id={self.id}, title={self.title}, deleted_at={self.deleted_at})>"


class DepartmentActivity(db.Model):
    __tablename__ = 'department_activity'
    
    id = db.Column(db.Integer, primary_key=True)
    activity_description = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    is_deleted = db.Column(db.Boolean, nullable=False, default=False)  #for soft deletes
    form_id = db.Column(db.Integer, db.ForeignKey('form_feedback.form_id'), nullable=False)
    
    def __repr__(self):
        return f"<DepartmentActivity(id={self.id}, description='{self.activity_description}', created_at={self.created_at})>"

    @staticmethod
    def get_active_activities():
        """Fetch all non-deleted activities."""
        return DepartmentActivity.query.filter_by(is_deleted=False).all()

    def soft_delete(self):
        """Mark the activity as deleted without removing it from the database."""
        self.is_deleted = True
        db.session.commit()
        
        
        
class ViewerDepartment(db.Model):
    __tablename__ = 'viewer_departments'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey('department.department_id'), nullable=False)
    
    # Create a unique constraint to prevent duplicate assignments
    __table_args__ = (
        db.UniqueConstraint('user_id', 'department_id', name='unique_viewer_department'),
    )
    
    # Relationship to Users
    user = db.relationship('Users', backref=db.backref('viewable_departments', lazy=True))
    
    # Relationship to Department
    department = db.relationship('Department', backref=db.backref('viewers', lazy=True))
