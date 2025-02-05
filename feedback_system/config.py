import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your_secret_key'
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:@localhost/feedback_collection_system'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Email Settings
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')    # SMTP server
    MAIL_PORT = int(os.getenv('MAIL_PORT', 587))    # SMTP port (587 for TLS)
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'true').lower() == 'true'  # Use TLS
    MAIL_USERNAME = os.getenv('MAIL_USERNAME' , 'noreply@strathmore.edu')      # Email username (e.g., noreply@strathmore.edu)
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')      # Email password
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', 'noreply@strathmore.edu')
    # Security Flags
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'None'