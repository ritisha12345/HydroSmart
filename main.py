from flask import Flask, render_template, request, redirect, url_for, session, flash
import os
import random
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your_secret_key'

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'csv', 'txt'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Dummy in-memory user database
users = {}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username in users and users[username] == password:
            session['username'] = username
            return redirect(url_for('profile'))
        else:
            flash('Invalid credentials, try again.')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username in users:
            flash('Username already exists.')
            return redirect(url_for('signup'))
        
        users[username] = password
        flash('Signup successful! Please login.')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))

    prediction = None
    confidence = None
    groundwater_info = None
    lat, lon = 20.5937, 78.9629  # Default center India

    if request.method == 'POST':
        if 'location' in request.form and request.form.get('location'):
            # Predict based on location
            location = request.form.get('location')

            if location.lower() == 'pune':
                lat, lon = 18.5204, 73.8567
                groundwater_info = {
                    "quality": "Good",
                    "depth": "50-120 meters",
                    "discharge": "Moderate (15-25 liters/sec)",
                    "techniques": "Rotary drilling preferred"
                }
            elif location.lower() == 'mumbai':
                lat, lon = 19.0760, 72.8777
                groundwater_info = {
                    "quality": "Moderate",
                    "depth": "40-100 meters",
                    "discharge": "Moderate (10-20 liters/sec)",
                    "techniques": "Percussion drilling recommended"
                }
            else:
                lat, lon = 20.5937, 78.9629
                groundwater_info = {
                    "quality": "Unknown",
                    "depth": "50-150 meters",
                    "discharge": "Unknown",
                    "techniques": "Rotary or Cable-tool drilling"
                }

            prediction = random.choice(['Suitable for Well Digging', 'Not Suitable'])
            confidence = round(random.uniform(70, 95), 2)

        elif 'file' in request.files and request.files['file'].filename != '':
            # Handle file upload
            file = request.files['file']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                flash('File uploaded successfully!')
            else:
                flash('Invalid file type. Only CSV and TXT are allowed.')

        elif 'feedback' in request.form:
            # Handle feedback
            feedback = request.form.get('feedback')
            if feedback:
                flash('Thank you for your feedback!')

    return render_template('profile.html',
                           username=session['username'],
                           prediction=prediction,
                           confidence=confidence,
                           groundwater_info=groundwater_info,
                           lat=lat,
                           lon=lon)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(debug=True)
