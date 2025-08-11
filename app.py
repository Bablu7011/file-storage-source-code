import os
from datetime import datetime
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash
from pymongo import MongoClient
import boto3
from bson.objectid import ObjectId
from flask_bcrypt import Bcrypt

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24) # A secret key is required for sessions
bcrypt = Bcrypt(app)

# Database & S3 Initialization
try:
    client = MongoClient(os.getenv("MONGO_URI"))
    db = client.cert_storage_db
    print("Connected to MongoDB successfully!")
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")

try:
    s3 = boto3.client(
        's3',
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        region_name=os.getenv("AWS_REGION")
    )
    S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME")
    print("Connected to AWS S3 successfully!")
except Exception as e:
    print(f"Error connecting to AWS S3: {e}")

def _create_default_categories():
    """Ensures that predefined categories exist in the database."""
    default_categories = ["Education", "Job", "Training", "Certification", "License", "Workshop"]
    for cat_name in default_categories:
        if db.categories.find_one({"name": cat_name}) is None:
            db.categories.insert_one({"name": cat_name})
            print(f"Created default category: {cat_name}")

with app.app_context():
    _create_default_categories()

# --- Routes ---
@app.route('/')
def home():
    # Render the new landing page
    return render_template('landing.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = db.users.find_one({"email": email})
        
        if user and 'password' in user:
            try:
                if bcrypt.check_password_hash(user['password'], password):
                    session['user_email'] = user['email']
                    flash('Login successful!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Login failed. Please check your email and password.', 'danger')
                    return redirect(url_for('login'))
            except ValueError:
                flash('Your account needs to be re-registered. Please sign up again.', 'warning')
                return redirect(url_for('signup'))
        else:
            flash('Login failed. Please check your email and password.', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        existing_user = db.users.find_one({"email": email})
        
        if existing_user:
            flash('User with this email already exists.', 'warning')
            return redirect(url_for('signup'))
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            db.users.insert_one({"email": email, "password": hashed_password})
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard():
    if 'user_email' not in session:
        flash('Please log in to view this page.', 'info')
        return redirect(url_for('login'))
    
    user_email = session['user_email']
    categories = list(db.categories.find())
    
    # Fetch only the files uploaded by the current user
    user_files = list(db.files.find({"user_email": user_email}))
    
    return render_template('dashboard.html', categories=categories, user_files=user_files)

@app.route('/logout')
def logout():
    session.pop('user_email', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/upload_file', methods=['POST'])
def upload_file():
    if 'user_email' not in session:
        flash('Please log in to upload files.', 'info')
        return redirect(url_for('login'))

    if 'file' not in request.files:
        flash("No file part", 'danger')
        return redirect(url_for('dashboard'))

    file = request.files['file']
    category_value = request.form.get('category_id')
    other_category_name = request.form.get('other_category')

    if file.filename == '':
        flash("No selected file", 'danger')
        return redirect(url_for('dashboard'))

    final_category_id = None
    final_category_name = None

    if category_value == 'other' and other_category_name:
        existing_category = db.categories.find_one({"name": other_category_name})
        if existing_category:
            final_category_id = existing_category['_id']
            final_category_name = existing_category['name']
        else:
            new_category = {"name": other_category_name}
            result = db.categories.insert_one(new_category)
            final_category_id = result.inserted_id
            final_category_name = other_category_name
    elif category_value:
        try:
            category = db.categories.find_one({"_id": ObjectId(category_value)})
            if category:
                final_category_id = category['_id']
                final_category_name = category['name']
        except Exception:
            category = db.categories.find_one({"name": category_value})
            if category:
                final_category_id = category['_id']
                final_category_name = category['name']
            else:
                flash("Invalid category selected", 'danger')
                return redirect(url_for('dashboard'))

    if not final_category_id:
        flash("Category not selected or invalid", 'danger')
        return redirect(url_for('dashboard'))

    try:
        s3.upload_fileobj(file, S3_BUCKET_NAME, file.filename)
    except Exception as e:
        print(f"S3 upload error: {e}")
        flash("File upload failed", 'danger')
        return redirect(url_for('dashboard'))

    db.files.insert_one({
        "filename": file.filename,
        "category_id": final_category_id,
        "category_name": final_category_name,
        "uploaded_at": datetime.utcnow(),
        "user_email": session['user_email']
    })

    flash("File uploaded successfully!", 'success')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)