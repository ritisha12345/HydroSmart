from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import folium
from datetime import datetime
import csv
from io import StringIO
from geopy.geocoders import Nominatim

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a secure secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///groundwater.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'csv', 'txt'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    analyses = db.relationship('Analysis', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Analysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    location = db.Column(db.String(100), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    groundwater_info = db.Column(db.JSON)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    # Create a map of India
    m = folium.Map(location=[20.5937, 78.9629], zoom_start=5)
    map_html = m._repr_html_()
    return render_template('index.html', map_html=map_html)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('profile'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('signup'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('signup'))
        
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/profile')
@login_required
def profile():
    analyses = Analysis.query.filter_by(user_id=current_user.id).order_by(Analysis.timestamp.desc()).all()
    return render_template('profile.html', user=current_user, analyses=analyses)

@app.route('/input', methods=['GET', 'POST'])
@login_required
def input():
    if request.method == 'POST':
        location = request.form.get('location')
        lat_str = request.form.get('latitude', '').strip()
        lon_str = request.form.get('longitude', '').strip()
        lat, lon = None, None
        try:
            lat = float(lat_str) if lat_str else None
        except ValueError:
            lat = None
        try:
            lon = float(lon_str) if lon_str else None
        except ValueError:
            lon = None
        # If coordinates are missing, geocode the location name
        if (lat is None or lon is None) and location:
            geolocator = Nominatim(user_agent="groundwater_app")
            geo = geolocator.geocode(location)
            if geo:
                lat = geo.latitude
                lon = geo.longitude
        # If still missing, use default India center
        if lat is None:
            lat = 20.5937
        if lon is None:
            lon = 78.9629
        
        # Here you would typically call your AI model
        groundwater_info = {
            "quality": "Good",
            "depth": "50-120 meters",
            "discharge": "Moderate (15-25 liters/sec)",
            "techniques": "Rotary drilling preferred",
            "suitability": "Suitable for Well Digging",
            "confidence": 85.5
        }
        
        # Save analysis to database
        analysis = Analysis(
            location=location,
            latitude=lat,
            longitude=lon,
            groundwater_info=groundwater_info,
            user_id=current_user.id
        )
        db.session.add(analysis)
        db.session.commit()
        
        # Create a map
        m = folium.Map(location=[lat, lon], zoom_start=13)
        folium.Marker([lat, lon], popup=location).add_to(m)
        map_html = m._repr_html_()
        
        return render_template('results.html', 
                             location=location,
                             groundwater_info=groundwater_info,
                             map_html=map_html)
    
    return render_template('input.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/download')
@login_required
def download():
    # Get the latest analysis for the user
    analysis = Analysis.query.filter_by(user_id=current_user.id).order_by(Analysis.timestamp.desc()).first()
    if not analysis:
        flash('No analysis found to download.')
        return redirect(url_for('profile'))
    # Prepare CSV content
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['Location', 'Latitude', 'Longitude', 'Timestamp', 'Suitability', 'Depth', 'Discharge', 'Technique', 'Quality', 'Confidence'])
    info = analysis.groundwater_info
    writer.writerow([
        analysis.location,
        analysis.latitude,
        analysis.longitude,
        analysis.timestamp.strftime('%Y-%m-%d %H:%M'),
        info.get('suitability', ''),
        info.get('depth', ''),
        info.get('discharge', ''),
        info.get('techniques', ''),
        info.get('quality', ''),
        info.get('confidence', '')
    ])
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = f"attachment; filename=groundwater_analysis_{analysis.id}.csv"
    output.headers["Content-type"] = "text/csv"
    return output

# Create database tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(debug=True)
