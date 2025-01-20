# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session
import boto3
from botocore.exceptions import ClientError
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import os
from functools import wraps

app = Flask(__name__)
app.secret_key = '1234567890'  # Change this to a secure secret key

# AWS SES Configuration
AWS_REGION = ""  # Change to your region
AWS_ACCESS_KEY = ""
AWS_SECRET_KEY = ""

# MongoDB Configuration
mongo_client = MongoClient('mongodb://localhost:27017/')
db = mongo_client['user_management']
users_collection = db['users']

# AWS SES Client
ses_client = boto3.client('ses',
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name=AWS_REGION
)

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'email' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def send_confirmation_email(recipient_email):
    SENDER = "kaparevanthkumarreddy@gmail.com"  # Must be verified in SES
    SUBJECT = "Welcome to Our Website!"
    BODY_TEXT = "Thank you for registering with our website!"
    BODY_HTML = """
    <html>
    <head></head>
    <body>
        <h1>Welcome to Our Website!</h1>
        <p>Thank you for registering. Your account has been created successfully.</p>
    </body>
    </html>
    """
    
    try:
        response = ses_client.send_email(
            Destination={'ToAddresses': [recipient_email]},
            Message={
                'Body': {
                    'Html': {'Data': BODY_HTML},
                    'Text': {'Data': BODY_TEXT}
                },
                'Subject': {'Data': SUBJECT}
            },
            Source=SENDER
        )
    except ClientError as e:
        print(e.response['Error']['Message'])
        return False
    return True

@app.route('/')
def home():
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # Check if user already exists
        if users_collection.find_one({'email': email}):
            flash('Email already registered')
            return redirect(url_for('register'))
        
        # Create new user
        hashed_password = generate_password_hash(password)
        users_collection.insert_one({
            'email': email,
            'password': hashed_password
        })
        
        # Send confirmation email
        send_confirmation_email(email)
        
        flash('Registration successful! Please check your email.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = users_collection.find_one({'email': email})
        
        if user and check_password_hash(user['password'], password):
            session['email'] = email
            return redirect(url_for('dashboard'))
        
        flash('Invalid email or password')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', email=session['email'])

@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)