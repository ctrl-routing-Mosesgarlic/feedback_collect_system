import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your_secret_key'
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:@localhost/feedback_collection_system'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Redis configuration
    REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6380/0')
    
    # Email Settings
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')    # SMTP server
    MAIL_PORT = int(os.getenv('MAIL_PORT', 587))    # SMTP port (587 for TLS)
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'true').lower() == 'true'  # Use TLS
    MAIL_USERNAME = os.getenv('MAIL_USERNAME' , 'noreply@strathmore.edu')      # Email username (e.g., noreply@strathmore.edu)
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')      # Email password
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', 'noreply@strathmore.edu')
    
    # Rate limiting
    RATELIMIT_DEFAULT = [10000, 86400]  # 10000 requests per day
    RATELIMIT_HEADERS_ENABLED = True
    RATELIMIT_STORAGE_URL ='redis://localhost:6380/1'
    
    # CSRF Protection
    CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # Set token expiration to 1 hour
    
    # CSRF_SESSION_KEY = os.environ.get('CSRF_SESSION_KEY') or 'your_secret_key'
    # WTF_CSRF_SECRET_KEY = os.environ.get('WTF_CSRF_SECRET_KEY') or 'your_secret_key'
    
    
    # Security Flags
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'None'