#!/usr/bin/python3
"""
MAIN APP
"""

from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_sqlalchemy import SQLAlchemy
import bcrypt
from flask_mail import Mail, Message
import os
import secrets

# Flask app initialization
app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DBURL")
app.config['MAIL_SERVER'] = 'smtp.mailtrap.io'
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.secret_key = 'secret_key'

db = SQLAlchemy(app)
mail = Mail(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    reset_token = db.Column(db.String(100), nullable=True)

    def __init__(self, email, password, name):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

# Create the database tables
with app.app_context():
    db.create_all()

# Home page route
@app.route('/')
def index():
    return render_template('index.html')

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already registered', 'danger')
            return redirect('/register')

        new_user = User(email=email, password=password, name=name)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect('/login')
    return render_template('register.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session['email'] = user.email
            flash('Logged in successfully!', 'success')
            return redirect('/dashboard')
        else:
            flash('Invalid credentials, please try again', 'danger')
    return render_template('login.html')

# Dashboard route
@app.route('/dashboard')
def dashboard():
    if 'email' not in session:
        return redirect('/login')
    user = User.query.filter_by(email=session['email']).first()
    return render_template('dashboard.html', user=user)

# Logout route
@app.route('/logout')
def logout():
    session.pop('email', None)
    flash('Logged out successfully', 'success')
    return redirect('/login')

# Password reset request route
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if user:
            token = secrets.token_hex(16)
            user.reset_token = token
            db.session.commit()

            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message('Password Reset Request', sender='noreply@example.com', recipients=[email])
            msg.body = f"To reset your password, visit the following link: {reset_url}"
            mail.send(msg)
            flash('Check your email for password reset instructions.', 'info')
        else:
            flash('Email not found', 'danger')
        return redirect('/login')
    return render_template('reset_password_request.html')

# Password reset route
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()

    if not user:
        flash('Invalid or expired token', 'danger')
        return redirect('/login')

    if request.method == 'POST':
        password = request.form['password']
        user.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        user.reset_token = None
        db.session.commit()
        flash('Your password has been reset. You can now log in.', 'success')
        return redirect('/login')

    return render_template('reset_password.html')

if __name__ == '__main__':
    app.run(debug=True)
