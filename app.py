from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort, Response, make_response, send_file, current_app, after_this_request, g
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mysqldb import MySQL
import MySQLdb.cursors
from datetime import datetime, timedelta
import re
import logging
from logging.handlers import RotatingFileHandler
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, HiddenField
from wtforms.validators import DataRequired, Email, Length
from email_validator import validate_email, EmailNotValidError
from decimal import Decimal
from wtforms import StringField, SelectField, SubmitField
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask_mail import Mail, Message
import secrets
from threading import Thread
import pdfkit
from flask import send_file
import tempfile
import pandas as pd
import io
import xlsxwriter
import json
import csv
from flask import jsonify
import csv
from flask import Response
import pdfkit
from flask import send_file
import tempfile
import os
import time

#app
app = Flask(__name__)

# Configure logging
if not os.path.exists('logs'):
    os.makedirs('logs')

file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Application startup')

# Security Configuration
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  

app.config.from_object(Config)

# CSRF Protection
csrf = CSRFProtect(app)
app.config['SECRET_KEY'] = 'your-secret-key-here'

# Configure upload folder
UPLOAD_FOLDER = os.path.join('static', 'uploads', 'hotels')
ROOM_UPLOAD_FOLDER = 'static/uploads/rooms'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

#upload folder
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

#create upload folder
os.makedirs(os.path.join(app.root_path, UPLOAD_FOLDER), exist_ok=True)
os.makedirs(ROOM_UPLOAD_FOLDER, exist_ok=True)


# Configuration
app.secret_key = 'ehebdhdbhddyuenbedff'  
app.config['MYSQL_HOST'] = '127.0.0.1'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'diamond143#'
app.config['MYSQL_DB'] = 'web'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=60)

#mysql
mysql = MySQL(app)


# Common database functions
def get_db():
    return mysql.connection.cursor(MySQLdb.cursors.DictCursor)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    


# Search and filter functions
def calculate_room_price(base_price_peak, room_type, check_in_date, num_guests):
    """
    Calculate final room price including all multipliers and seasonal rates
    """
    # Convert to Decimal for precise calculations
    base_price_peak = Decimal(str(base_price_peak))
    
    # 1. Check if peak season first
    if isinstance(check_in_date, str):
        check_in = datetime.strptime(check_in_date, '%Y-%m-%d')
    else:
        check_in = check_in_date
        
    month = check_in.month
    is_peak = month in [4, 5, 6, 7, 8, 11, 12]  # April-August, November-December
    
    # 2. seasonal rates
    if not is_peak:
        base_price = base_price_peak * Decimal('0.5')  # 50% of peak price for off-peak
    else:
        base_price = base_price_peak  # Use peak price
    
    # 3.room type multiplier
    room_multiplier = ROOM_TYPE_MULTIPLIERS.get(room_type, Decimal('1.00'))
    price = base_price * room_multiplier
    
    # 4. guest surcharges 
    if room_type == 'Double' and num_guests == 2:
        surcharge = base_price * GUEST_SURCHARGES['Double']  # 10% of base price
        price += surcharge
    
    return price.quantize(Decimal('0.01'))

#calculate advance booking discount
def calculate_advance_booking_discount(check_in_date, total_price):
    """Calculate discount based on how far in advance the booking is made"""
    if isinstance(check_in_date, str):
        check_in_date = datetime.strptime(check_in_date, '%Y-%m-%d')
    
    # Convert total_price to Decimal if it isn't already
    total_price = Decimal(str(total_price))
    
    days_until = (check_in_date.date() - datetime.now().date()).days
    
    if days_until > 90:
        return (total_price * Decimal('0.15')).quantize(Decimal('0.01'))  # 15% discount
    elif days_until > 60:
        return (total_price * Decimal('0.10')).quantize(Decimal('0.01'))  # 10% discount
    elif days_until > 30:
        return (total_price * Decimal('0.05')).quantize(Decimal('0.01'))  # 5% discount
    return Decimal('0.00')

#room type multipliers
ROOM_TYPE_MULTIPLIERS = {
    'Standard': Decimal('1.00'),  # Base price
    'Double': Decimal('1.20'),    # 20% more than Standard
    'Family': Decimal('1.50')     # 50% more than Standard
}

GUEST_SURCHARGES = {
    'Double': Decimal('0.10'),    # 10% extra for second guest
    'Family': Decimal('0.00')     # No extra charge for family rooms
}


# Exchange rates
EXCHANGE_RATES = {
    'GBP': 1.0,
    'USD': 1.27,  
    'EUR': 1.17,  
    'INR': 105.42, 
    'NPR': 160.00 
}

CURRENCY_SYMBOLS = {
    'GBP': '£',
    'USD': '$',
    'EUR': '€',
    'INR': '₹',
    'NPR': 'रू'
}

#icons mapping
FEATURE_ICONS = {
    'WiFi': 'wifi',
    'TV': 'tv',
    'Air Conditioning': 'snowflake',
    'Mini Bar': 'glass-martini',
    'Room Service': 'concierge-bell',
    'Swimming Pool': 'swimming-pool',
    'Gym': 'dumbbell',
    'Parking': 'parking',
    'Restaurant': 'utensils',
    'Bar': 'glass-cheers',
    'Spa': 'spa',
    'Business Center': 'briefcase'
}

#set currency
@app.route('/set-currency/<currency>')
def set_currency(currency):
    if currency in CURRENCY_SYMBOLS:
        session['currency'] = currency
    return redirect(request.referrer or url_for('search'))

# login form
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me') 
    next_url = HiddenField()
    submit = SubmitField('Login')

# registration form
class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(min=2, max=50)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Register')

# search form
class SearchForm(FlaskForm):
    city = StringField('City')
    check_in = StringField('Check In', validators=[DataRequired()])
    check_out = StringField('Check Out', validators=[DataRequired()])
    guests = StringField('Guests', validators=[DataRequired()])
    submit = SubmitField('Search')
    
# booking form
class BookingForm(FlaskForm):
    check_in = StringField('Check In Date', validators=[DataRequired()])
    check_out = StringField('Check Out Date', validators=[DataRequired()])
    num_guests = SelectField('Number of Guests', 
                           choices=[(str(i), f'{i} Guest{"s" if i > 1 else ""}') for i in range(1, 5)],
                           validators=[DataRequired()])
    submit = SubmitField('Confirm Booking')
 
# forgot password form
class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Reset Link')

# cancellation form
class CancellationForm(FlaskForm):
    submit = SubmitField('Cancel Booking')
    
# payment form
class PaymentForm(FlaskForm):
    # Guest Details
    full_name = StringField('Full Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone Number', validators=[DataRequired()])
    special_requests = TextAreaField('Special Requests')
    
    # Payment Details
    card_number = StringField('Card Number', validators=[
        DataRequired(),
        Length(min=16, max=16, message='Please enter a valid 16-digit card number')
    ])
    expiry_month = SelectField('Expiry Month', choices=[
        (str(i).zfill(2), str(i).zfill(2)) for i in range(1, 13)
    ], validators=[DataRequired()])
    expiry_year = SelectField('Expiry Year', choices=[
        (str(i), str(i)) for i in range(datetime.now().year, datetime.now().year + 11)
    ], validators=[DataRequired()])
    cvv = StringField('CVV', validators=[
        DataRequired(),
        Length(min=3, max=4, message='Please enter a valid CVV')
    ])
    
    submit = SubmitField('Confirm Payment')
    
#special request form
class SpecialRequestForm(FlaskForm):
    status = SelectField('Status', choices=[
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled')
    ])
    notes = TextAreaField('Notes')
    submit = SubmitField('Update')

#mail
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USE_SSL=False,
    MAIL_USERNAME='khadkaridesha@gmail.com',
    MAIL_PASSWORD='bknk ktea asac pkyz',
    MAIL_DEFAULT_SENDER=('World Hotels', 'khadkaridesha@gmail.com')
)

# Initialize Flask-Mail
mail = Mail(app)

# async email
def send_async_email(app, msg):
    with app.app_context():
        try:
            mail.send(msg)
            app.logger.info(f"Email sent successfully to: {msg.recipients}")
            return True
        except Exception as e:
            app.logger.error(f"Failed to send email: {str(e)}")
            return False

# async email with thread
def send_email_with_thread(msg):
    try:
        thread = Thread(target=send_async_email, args=(app, msg))
        thread.start()
        return True
    except Exception as e:
        app.logger.error(f"Failed to start email thread: {str(e)}")
        return False
    
#send special request email
def send_special_request_email(booking_data, special_request):
    """
    Send email notification for new special requests
    """
    try:
        msg = Message(
            subject='New Special Request Received',
            recipients=['khadkaridesha@gmail.com'] 
        )
        
        msg.html = render_template(
            'special_request_notification.html', 
            booking=booking_data,
            special_request=special_request
        )
        
        # Use the send_email_with_thread function
        return send_email_with_thread(msg)
    except Exception as e:
        app.logger.error(f"Error preparing special request email: {str(e)}")
        return False

# subscribe newsletter route
@app.route('/subscribe-newsletter', methods=['POST'])
def subscribe_newsletter():
    try:
        # Handle both form data and JSON data
        if request.is_json:
            data = request.get_json()
            email = sanitize_input(data.get('email'))
        else:
            email = sanitize_input(request.form.get('email'))
        
        # Validate email
        try:
            validate_email(email)
        except EmailNotValidError:
            return jsonify({
                'status': 'error',
                'message': 'Please enter a valid email address.'
            })
        
        cursor = get_db()
        
        # Check if already subscribed
        cursor.execute('SELECT * FROM newsletter_subscribers WHERE email = %s', (email,))
        existing = cursor.fetchone()
        
        if existing:
            if existing['is_active']:
                return jsonify({
                    'status': 'info',
                    'message': 'This email is already subscribed to our newsletter.'
                })
            else:
                # Reactivate subscription
                cursor.execute("""
                    UPDATE newsletter_subscribers 
                    SET is_active = TRUE 
                    WHERE email = %s
                """, (email,))
                mysql.connection.commit()

                # Send reactivation email
                try:
                    msg = Message(
                        subject='Welcome Back to WorldHotels Newsletter!',
                        recipients=[email],
                        sender=app.config['MAIL_DEFAULT_SENDER']
                    )
                    
                    msg.html = f'''
                    <html>
                        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                                <h2 style="color: #007bff;">Welcome Back to WorldHotels Newsletter!</h2>
                                <p>Dear Subscriber,</p>
                                <p>We're delighted to have you back! Your newsletter subscription has been successfully reactivated.</p>
                                <p>You'll continue to receive updates about:</p>
                                <ul>
                                    <li>Latest hotel offers and deals</li>
                                    <li>New hotel openings</li>
                                    <li>Travel tips and guides</li>
                                    <li>Exclusive member promotions</li>
                                </ul>
                                <p>If you wish to unsubscribe again, please <a href="{url_for('unsubscribe_newsletter', token=generate_token(email), _external=True)}" style="color: #007bff;">click here</a>.</p>
                                <hr style="border: 1px solid #eee; margin: 20px 0;">
                                <p style="font-size: 12px; color: #666;">This email was sent to {email} because you reactivated your WorldHotels newsletter subscription.</p>
                            </div>
                        </body>
                    </html>
                    '''
                    
                    if send_email_with_thread(msg):
                        app.logger.info(f'Reactivation email sent successfully to {email}')
                    else:
                        app.logger.error(f'Failed to send reactivation email to {email}')
                        raise Exception("Failed to send email")
                        
                except Exception as e:
                    app.logger.error(f'Error sending reactivation email to {email}: {str(e)}')
                
                return jsonify({
                    'status': 'success',
                    'message': 'Your newsletter subscription has been reactivated! Please check your email for confirmation.'
                })
        else:
            
            cursor.execute("""
                INSERT INTO newsletter_subscribers (email) 
                VALUES (%s)
            """, (email,))
            mysql.connection.commit()
            
            # Send welcome email with better error handling
            try:
                # Create the message
                msg = Message(
                    subject='Welcome to WorldHotels Newsletter!',
                    recipients=[email],
                    sender=app.config['MAIL_DEFAULT_SENDER']
                )
                
                # Set the email content
                msg.html = f'''
                <html>
                    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                        <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                            <h2 style="color: #007bff;">Welcome to WorldHotels Newsletter!</h2>
                            <p>Dear Subscriber,</p>
                            <p>Thank you for subscribing to our newsletter! We're excited to have you join our community.</p>
                            <p>You'll now receive updates about:</p>
                            <ul>
                                <li>Latest hotel offers and deals</li>
                                <li>New hotel openings</li>
                                <li>Travel tips and guides</li>
                                <li>Exclusive member promotions</li>
                            </ul>
                            <p>If you wish to unsubscribe, please <a href="{url_for('unsubscribe_newsletter', token=generate_token(email), _external=True)}" style="color: #007bff;">click here</a>.</p>
                            <hr style="border: 1px solid #eee; margin: 20px 0;">
                            <p style="font-size: 12px; color: #666;">This email was sent to {email} because you subscribed to WorldHotels newsletter.</p>
                        </div>
                    </body>
                </html>
                '''
                
                
                msg.body = f'''
                Welcome to WorldHotels Newsletter!
                
                Thank you for subscribing to our newsletter! You'll now receive updates about our latest offers, new hotels, and travel tips.
                
                If you wish to unsubscribe, please visit: {url_for('unsubscribe_newsletter', token=generate_token(email), _external=True)}
                
                This email was sent to {email} because you subscribed to WorldHotels newsletter.
                '''
                
                # Send the email
                if send_email_with_thread(msg):
                    app.logger.info(f'Welcome email sent successfully to {email}')
                    app.logger.info(f'Attempting to send welcome email to {email}')
                else:
                    app.logger.error(f'Failed to send welcome email to {email}')
                    raise Exception("Failed to send email")
                    
            except Exception as e:
                app.logger.error(f'Error sending welcome email to {email}: {str(e)}')
                # Continue with subscription process even if email fails
            
            return jsonify({
                'status': 'success',
                'message': 'Thank you for subscribing to our newsletter! Please check your email for confirmation.'
            })
            
    except Exception as e:
        app.logger.error(f'Newsletter subscription error: {str(e)}')
        return jsonify({
            'status': 'error',
            'message': 'An error occurred. Please try again later.'
        })

# unsubscribe newsletter route
@app.route('/unsubscribe-newsletter/<token>')
def unsubscribe_newsletter(token):
    try:
        app.logger.info(f'Attempting to verify token: {token[:10]}...')  # Log only first 10 chars for security
        email = verify_token(token)
        
        if not email:
            app.logger.warning('Token verification failed')
            return render_template('unsubscribe.html', 
                                status='error',
                                message='Invalid or expired unsubscribe link.')
        
        app.logger.info(f'Token verified successfully for email: {email}')
        
        cursor = get_db()
        # Check if subscriber exists and is active
        cursor.execute("""
            SELECT * FROM newsletter_subscribers 
            WHERE email = %s
        """, (email,))
        subscriber = cursor.fetchone()
        
        if not subscriber:
            return render_template('unsubscribe.html',
                                 status='error',
                                 message='Email not found in our subscription list.')
        
        if not subscriber['is_active']:
            return render_template('unsubscribe.html',
                                 status='info',
                                 message='You are already unsubscribed from our newsletter.')
        
        # Update subscriber status
        cursor.execute("""
            UPDATE newsletter_subscribers 
            SET is_active = FALSE 
            WHERE email = %s
        """, (email,))
        mysql.connection.commit()
        
        # Send confirmation email
        try:
            msg = Message(
                'Newsletter Unsubscription Confirmation',
                recipients=[email],
                sender=app.config['MAIL_DEFAULT_SENDER']
            )
            msg.html = f'''
            <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                        <h2 style="color: #007bff;">Unsubscription Confirmed</h2>
                        <p>Dear Subscriber,</p>
                        <p>We're sorry to see you go. Your unsubscription from the WorldHotels newsletter has been confirmed.</p>
                        <p>If you change your mind, you can always subscribe again on our website.</p>
                        <hr style="border: 1px solid #eee; margin: 20px 0;">
                        <p style="font-size: 12px; color: #666;">This email was sent to {email} to confirm your unsubscription.</p>
                    </div>
                </body>
            </html>
            '''
            send_email_with_thread(msg)
        except Exception as e:
            app.logger.error(f'Error sending unsubscribe confirmation email: {str(e)}')
        
        return render_template('unsubscribe.html',
                             status='success',
                             message='You have been successfully unsubscribed from our newsletter.')
        
    except Exception as e:
        app.logger.error(f'Newsletter unsubscribe error: {str(e)}')
        return render_template('unsubscribe.html',
                             status='error',
                             message='An error occurred. Please try again later.')

# reviews route
@app.route('/reviews')
def reviews():
    page = request.args.get('page', 1, type=int)
    hotel_id = request.args.get('hotel', type=int)
    rating = request.args.get('rating', type=int)
    per_page = 12  # Number of reviews per page
    
    cursor = get_db()
    
    # Base query
    query = """
        SELECT r.*, h.hotel_name, u.first_name, u.last_name
        FROM reviews r
        JOIN hotels h ON r.hotel_id = h.hotel_id
        JOIN users u ON r.user_id = u.user_id
        WHERE r.is_verified = TRUE
    """
    count_query = """
        SELECT COUNT(*) as count 
        FROM reviews r
        WHERE r.is_verified = TRUE
    """
    params = []
    
    # Add filters if they exist
    if hotel_id:
        query += " AND r.hotel_id = %s"
        count_query += " AND r.hotel_id = %s"
        params.append(hotel_id)
    
    if rating:
        query += " AND r.rating = %s"
        count_query += " AND r.rating = %s"
        params.append(rating)
    
    # Add ordering
    query += " ORDER BY r.review_date DESC"
    
    # Get total count for pagination
    cursor.execute(count_query, params)
    total_reviews = cursor.fetchone()['count']
    
    # Calculate pagination
    pages = (total_reviews + per_page - 1) // per_page
    offset = (page - 1) * per_page
    
    # Add pagination to main query
    query += " LIMIT %s OFFSET %s"
    params.extend([per_page, offset])
    
    # Execute main query
    cursor.execute(query, params)
    reviews = cursor.fetchall()
    
    # Get all hotels for filter
    cursor.execute('SELECT hotel_id, hotel_name FROM hotels ORDER BY hotel_name')
    hotels = cursor.fetchall()
    
    return render_template('reviews.html',
                         reviews=reviews,
                         hotels=hotels,
                         pages=pages,
                         current_page=page,
                         selected_hotel=hotel_id,
                         selected_rating=rating)
    
    
# Custom Error Pages
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

# internal error
@app.errorhandler(500)
def internal_error(error):
    mysql.connection.rollback()  # Roll back db session in case of error
    app.logger.error(f'Server Error: {error}')
    return render_template('errors/500.html'), 500

# forbidden error
@app.errorhandler(403)
def forbidden_error(error):
    return render_template('errors/403.html'), 403

# login required
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'info')
            # Store the current URL in the session for redirect after login
            session['next_url'] = request.url
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# admin required
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            next_url = request.url
            return redirect(url_for('login', next=next_url))
        
        try:
            cursor = get_db()
            cursor.execute('SELECT user_type FROM users WHERE user_id = %s', 
                         (session['user_id'],))
            user = cursor.fetchone()
            cursor.close()
            
            if not user or user['user_type'] != 'admin':
                flash('Admin access required', 'error')
                return abort(403)  # Return 403 Forbidden instead of redirecting
                
            return f(*args, **kwargs)
            
        except Exception as e:
            app.logger.error(f'Admin verification error: {str(e)}')
            return abort(500)
            
    return decorated_function

# Input Validation
def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number"
    return True, "Password is valid"

#sanitize input
def sanitize_input(text):
    """Basic input sanitization"""
    if text is None:
        return None
    return text.strip()

# Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "100 per hour"]
)

# Database Connection Security
def get_db():
    """Safe database connection handling"""
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        return cursor
    except Exception as e:
        app.logger.error(f'Database connection error: {str(e)}')
        abort(500)

# Secure File Handling
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# upload image route
@app.route('/upload_image', methods=['POST'])
@login_required
def upload_image():
    if 'image' not in request.files:
        flash('No file uploaded', 'error')
        return redirect(request.referrer)
    
    file = request.files['image']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(request.referrer)
    
    if file and allowed_file(file.filename):
        try:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return redirect(request.referrer)
        except Exception as e:
            app.logger.error(f'File upload error: {str(e)}')
            flash('Error uploading file', 'error')
            return redirect(request.referrer)
    
    flash('Invalid file type', 'error')
    return redirect(request.referrer)

# login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))
        
    form = LoginForm()
    
    if request.method == 'GET':
        next_url = session.pop('next_url', None)
        if next_url:
            form.next_url.data = next_url
        else:
            form.next_url.data = request.args.get('next')
        return render_template('login.html', form=form)
    
    if form.validate_on_submit():
        email = sanitize_input(form.email.data)
        password = form.password.data
        next_url = form.next_url.data
        remember_me = form.remember_me.data  # Get remember_me value
        
        try:
            cursor = get_db()
            cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
            user = cursor.fetchone()
            
            if user and check_password_hash(user['password_hash'], password):
                # Preserve the currency and other parameters
                stored_params = session.get('url_params', {})
                
                session.clear()
                session['user_id'] = user['user_id']
                session['user_type'] = user['user_type']
                session['first_name'] = user['first_name']
                
                # Set session permanency based on remember_me
                if remember_me:
                    session.permanent = True  # Add this line
                    app.permanent_session_lifetime = timedelta(days=30)  # Add this line
                
                if 'currency' in stored_params:
                    session['currency'] = stored_params['currency']
                
                response = redirect(next_url if next_url else url_for('index'))
                return response
            
            flash('Invalid email or password', 'error')
            return render_template('login.html', form=form)
            
        except Exception as e:
            app.logger.error(f'Login error: {str(e)}')
            flash('An error occurred during login', 'error')
            return render_template('login.html', form=form)
    
    return render_template('login.html', form=form)

# register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if request.method == 'GET':
        return render_template('register.html', form=form)
    
    if form.validate_on_submit():
        first_name = sanitize_input(form.first_name.data)
        last_name = sanitize_input(form.last_name.data)
        email = sanitize_input(form.email.data)
        password = form.password.data
        phone = sanitize_input(request.form.get('phone'))  # Add this line
        
        # Check if user already exists
        cursor = get_db()
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        user = cursor.fetchone()
        
        if user:
            flash('Email already registered', 'error')
            return render_template('register.html', form=form)
        
        # Validate password strength
        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message, 'error')
            return render_template('register.html', form=form)
        
        # Create new user
        password_hash = generate_password_hash(password)
        try:
            cursor.execute('''
                INSERT INTO users (first_name, last_name, email, password_hash, phone, user_type)
                VALUES (%s, %s, %s, %s, %s, 'customer')
            ''', (first_name, last_name, email, password_hash, phone))  # Add phone to the query
            mysql.connection.commit()
            
            # Log the successful registration
            app.logger.info(f'New user registered: {email}')
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            mysql.connection.rollback()
            app.logger.error(f'Registration error: {str(e)}')
            flash('An error occurred during registration', 'error')
            return render_template('register.html', form=form)
            
    return render_template('register.html', form=form)

# logout route
@app.route('/logout')
def logout():
    try:
        # Get user_id before clearing session
        user_id = session.get('user_id')
        
        # Clear the session
        session.clear()
        
        # If there was a logged-in user, update their token (if the column exists)
        if user_id:
            cursor = get_db()
            try:
                # Check if token column exists first
                cursor.execute("""
                    SELECT COUNT(*) as count 
                    FROM information_schema.columns 
                    WHERE table_name = 'users' 
                    AND column_name = 'remember_token'
                """)
                has_token_column = cursor.fetchone()['count'] > 0
                
                if has_token_column:
                    cursor.execute("""
                        UPDATE users 
                        SET remember_token = NULL, 
                            remember_token_expires_at = NULL 
                        WHERE user_id = %s
                    """, (user_id,))
                    mysql.connection.commit()
            except Exception as e:
                app.logger.error(f'Error clearing remember token: {str(e)}')
                mysql.connection.rollback()
            finally:
                cursor.close()
        
        # Create response and delete the remember token cookie
        response = redirect(url_for('login'))
        response.delete_cookie('remember_token')
        
        flash('You have been logged out successfully', 'success')
        return redirect(url_for('login'))
        
    except Exception as e:
        app.logger.error(f'Logout error: {str(e)}')
        flash('An error occurred during logout', 'error')
        return redirect(url_for('index'))

# Main routes
@app.route('/')
def index():
    try:
        cursor = get_db()
        cursor.execute('SELECT h.*, c.city_name FROM hotels h JOIN cities c ON h.city_id = c.city_id')
        hotels = cursor.fetchall()
        
        return render_template('index.html', hotels=hotels)
        
    except Exception as e:
        app.logger.error(f'Error in index route: {str(e)}')
        return render_template('errors/500.html'), 500
        
    finally:
        if cursor:
            cursor.close()

# search route
@app.route('/search', methods=['GET', 'POST'])
def search():
    cursor = get_db()
    
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = 6  # Number of rooms per page
    
    # Get currency from session
    currency = session.get('currency', 'GBP')
    exchange_rate = Decimal(str(EXCHANGE_RATES.get(currency, 1.0)))
    currency_symbol = CURRENCY_SYMBOLS.get(currency, '£')
    
    # Get all cities for the dropdown
    cursor.execute("SELECT * FROM cities ORDER BY city_name")
    cities = cursor.fetchall()
    
    # Initialize variables
    rooms = []
    check_in = request.args.get('check_in', '')
    check_out = request.args.get('check_out', '')
    guests = request.args.get('guests', '1')
    selected_city = request.args.get('city', '')
    total_rooms = 0
    total_pages = 1
    current_rooms = []
    
    # Define feature icons mapping
    feature_icons = {
        'WiFi': 'wifi',
        'TV': 'tv',
        'Air Conditioning': 'snowflake',
        'Mini Bar': 'glass-martini',
        'Room Service': 'concierge-bell',
        'Swimming Pool': 'swimming-pool',
        'Gym': 'dumbbell',
        'Parking': 'parking',
        'Restaurant': 'utensils',
        'Bar': 'glass-cheers',
        'Spa': 'spa',
        'Business Center': 'briefcase'
    }
    
    if check_in and check_out:  # Only search if dates are provided
        try:
            guests = int(guests)
            # Base query with room type distribution check
            query = """
                SELECT r.*, rt.type_name, rt.max_guests, 
                       h.hotel_name, h.star_rating, c.city_name,
                       h.total_rooms, r.main_image,
                       (SELECT COUNT(*) FROM rooms r2 
                        WHERE r2.hotel_id = h.hotel_id 
                        AND r2.room_type_id = r.room_type_id) as type_count
                FROM rooms r
                JOIN hotels h ON r.hotel_id = h.hotel_id
                JOIN room_types rt ON r.room_type_id = rt.room_type_id
                JOIN cities c ON h.city_id = c.city_id
                WHERE r.room_id NOT IN (
                    SELECT room_id FROM bookings
                    WHERE status = 'confirmed'
                    AND (check_in_date <= %s AND check_out_date >= %s)
                )
            """
            params = [check_out, check_in]
            
            if selected_city:
                query += " AND h.city_id = %s"
                params.append(selected_city)
            
            if guests:
                query += " AND rt.max_guests >= %s"
                params.append(guests)
            
            cursor.execute(query, params)
            rooms = cursor.fetchall()
            
            # Process each room
            for room in rooms:
                # Calculate base price with room type multiplier
                base_price = calculate_room_price(
                    room['base_price_peak'],
                    room['type_name'],
                    check_in,
                    guests
                )
                
                # Calculate advance booking discount
                check_in_date = datetime.strptime(check_in, '%Y-%m-%d')
                days_ahead = (check_in_date.date() - datetime.now().date()).days
                
                if 80 <= days_ahead <= 90:
                    discount_rate = Decimal('0.30')
                elif 60 <= days_ahead <= 79:
                    discount_rate = Decimal('0.20')
                elif 45 <= days_ahead <= 59:
                    discount_rate = Decimal('0.10')
                else:
                    discount_rate = Decimal('0')
                    
                discount_amount = base_price * discount_rate
                
                # Convert to selected currency
                room['original_price'] = (base_price * exchange_rate).quantize(Decimal('0.01'))
                room['discount_amount'] = (discount_amount * exchange_rate).quantize(Decimal('0.01'))
                room['final_price'] = ((base_price - discount_amount) * exchange_rate).quantize(Decimal('0.01'))
                
                # Check room type distribution
                total_rooms = Decimal(str(room['total_rooms']))
                type_count = Decimal(str(room['type_count']))
                
                distribution = {
                    'Standard': Decimal('0.30'),  # 30%
                    'Double': Decimal('0.50'),    # 50%
                    'Family': Decimal('0.20')     # 20%
                }
                
                expected_count = total_rooms * distribution[room['type_name']]
                room['availability_status'] = 'Limited' if type_count < expected_count else 'Available'
                
                # Peak season
                room['is_peak'] = check_in_date.month in [4, 5, 6, 7, 8, 11, 12]
            
            # Calculate total number of rooms for pagination
            total_rooms = len(rooms)
            total_pages = (total_rooms + per_page - 1) // per_page
            
            # Slice the rooms list for current page
            start_idx = (page - 1) * per_page
            end_idx = start_idx + per_page
            current_rooms = rooms[start_idx:end_idx]
            
        except Exception as e:
            app.logger.error(f'Search error: {str(e)}')
            flash('An error occurred while searching for rooms', 'error')
            
    # Get city name for the selected city
    city_name = "Our Destinations"  # Default value
    if selected_city:
        try:
            cursor.execute("SELECT city_name FROM cities WHERE city_id = %s", (selected_city,))
            city_result = cursor.fetchone()
            if city_result:
                city_name = city_result['city_name']
        except Exception as e:
            app.logger.error(f'Error fetching city name: {str(e)}')
    
    
    # recommended hotels query
    recommended_hotels = []
    try:
        if selected_city and check_in and check_out:
            # Get hotels from the same city with similar or higher star rating
            # and available rooms for the selected dates
            recommend_query = """
                SELECT DISTINCT 
                    h.hotel_id,
                    h.hotel_name,
                    h.description,
                    h.star_rating,
                    h.main_image,
                    c.city_name,
                    MIN(r.base_price_peak) as min_price,
                    COUNT(DISTINCT r.room_id) as available_rooms
                FROM hotels h
                JOIN cities c ON h.city_id = c.city_id
                JOIN rooms r ON h.hotel_id = r.hotel_id
                LEFT JOIN bookings b ON r.room_id = b.room_id 
                    AND b.status = 'confirmed'
                    AND (b.check_in_date <= %s AND b.check_out_date >= %s)
                WHERE h.city_id = %s
                    AND r.is_active = TRUE
                    AND b.booking_id IS NULL
                GROUP BY h.hotel_id, h.hotel_name, h.description, h.star_rating, 
                         h.main_image, c.city_name
                HAVING available_rooms > 0
                ORDER BY ABS(h.star_rating - (
                    SELECT star_rating 
                    FROM hotels 
                    WHERE city_id = %s 
                    LIMIT 1
                )), h.star_rating DESC
                LIMIT 15
            """
            cursor.execute(recommend_query, (check_out, check_in, selected_city, selected_city))
        else:
            # Get top-rated hotels with available rooms
            recommend_query = """
                SELECT DISTINCT 
                    h.hotel_id,
                    h.hotel_name,
                    h.description,
                    h.star_rating,
                    h.main_image,
                    c.city_name,
                    MIN(r.base_price_peak) as min_price,
                    COUNT(DISTINCT r.room_id) as available_rooms,
                    COALESCE(AVG(rev.rating), 0) as avg_rating
                FROM hotels h
                JOIN cities c ON h.city_id = c.city_id
                JOIN rooms r ON h.hotel_id = r.hotel_id
                LEFT JOIN reviews rev ON h.hotel_id = rev.hotel_id
                WHERE r.is_active = TRUE
                GROUP BY h.hotel_id, h.hotel_name, h.description, h.star_rating, 
                         h.main_image, c.city_name
                HAVING available_rooms > 0
                ORDER BY h.star_rating DESC, avg_rating DESC
                LIMIT 5
            """
            cursor.execute(recommend_query)

        recommended_hotels = cursor.fetchall()

        # Convert prices to selected currency
        for hotel in recommended_hotels:
            if hotel['min_price']:
                hotel['min_price'] = (Decimal(str(hotel['min_price'])) * exchange_rate).quantize(Decimal('0.01'))
                
                # Add a short description (first 100 characters)
                if hotel['description']:
                    hotel['short_description'] = hotel['description'][:100] + '...'
                else:
                    hotel['short_description'] = 'Discover this amazing property...'

    except Exception as e:
        app.logger.error(f'Error fetching recommended hotels: {str(e)}')
        recommended_hotels = []  # Reset to empty list on error
    
    cursor.close()
    
    return render_template('search.html',                         
                        rooms=current_rooms if check_in and check_out else rooms,
                         cities=cities,
                         currency=currency,
                         currency_symbol=currency_symbol,
                         currencies=CURRENCY_SYMBOLS,
                         check_in=check_in,
                         check_out=check_out,
                         guests=guests,
                         selected_city=selected_city,
                         city_name=city_name,  # Add this line
                         today=datetime.now().strftime('%Y-%m-%d'),
                         feature_icons=feature_icons,
                         page=page,
                         per_page=per_page,
                         total_pages=total_pages,
                         total_rooms=total_rooms,
                         min=min,
                         recommended_hotels=recommended_hotels)


# book room route
@app.route('/book/<int:room_id>', methods=['GET', 'POST'])
@login_required
def book_room(room_id):
    
    stored_params = session.get('booking_params')
    if stored_params:
        # Clear the stored parameters
        session.pop('booking_params', None)
        # Redirect to the same route with the stored parameters
        return redirect(url_for('book_room', room_id=room_id, **stored_params))
    
    
    form = BookingForm()
    cursor = get_db()
    
    # Get currency preferences
    currency = session.get('currency', 'GBP')
    exchange_rate = Decimal(str(EXCHANGE_RATES.get(currency, 1.0)))
    currency_symbol = CURRENCY_SYMBOLS.get(currency, '£')
    
    # Get room details
    cursor.execute("""
        SELECT r.*, rt.type_name, rt.max_guests, h.hotel_name,
               r.main_image, r.features, r.description,
               r.base_price_peak, r.base_price_offpeak
        FROM rooms r
        JOIN room_types rt ON r.room_type_id = rt.room_type_id
        JOIN hotels h ON r.hotel_id = h.hotel_id
        WHERE r.room_id = %s
    """, (room_id,))
    room = cursor.fetchone()
    
    if not room:
        flash('Room not found', 'error')
        return redirect(url_for('search'))

    # Calculate prices based on dates if provided
    check_in_str = request.args.get('check_in', '') or form.check_in.data
    check_out_str = request.args.get('check_out', '') or form.check_out.data
    num_guests = int(request.args.get('guests', '1') or form.num_guests.data or 1)
    
    # Calculate base price and converted price
    base_price = Decimal(str(room['base_price_peak']))
    room['converted_price'] = (base_price * exchange_rate).quantize(Decimal('0.01'))

    # Add price calculation for display
    if check_in_str and check_out_str:
        try:
            check_in = datetime.strptime(check_in_str, '%Y-%m-%d')
            check_out = datetime.strptime(check_out_str, '%Y-%m-%d')
            stay_duration = (check_out - check_in).days
            
            # Calculate base price
            base_price = calculate_room_price(
                room['base_price_peak'],
                room['type_name'],
                check_in,
                num_guests
            )
            
            # Calculate total price for entire stay
            total_base_price = base_price * Decimal(str(stay_duration))
            
            # Calculate advance booking discount
            days_ahead = (check_in.date() - datetime.now().date()).days
            if days_ahead >= 80:
                room['discount_rate'] = 30
            elif days_ahead >= 60:
                room['discount_rate'] = 20
            elif days_ahead >= 45:
                room['discount_rate'] = 10
            else:
                room['discount_rate'] = 0
                
            # Calculate final prices
            room['base_price_per_night'] = (base_price * exchange_rate).quantize(Decimal('0.01'))
            room['total_base_price'] = (total_base_price * exchange_rate).quantize(Decimal('0.01'))
            
            if room['discount_rate'] > 0:
                discount_amount = total_base_price * (Decimal(str(room['discount_rate'])) / Decimal('100'))
                room['discount_amount'] = (discount_amount * exchange_rate).quantize(Decimal('0.01'))
                room['final_price'] = ((total_base_price - discount_amount) * exchange_rate).quantize(Decimal('0.01'))
            else:
                room['discount_amount'] = Decimal('0')
                room['final_price'] = room['total_base_price']
            
            room['num_nights'] = stay_duration
            room['is_peak_season'] = check_in.month in [4, 5, 6, 7, 8, 11, 12]
        except Exception as e:
            app.logger.error(f'Price calculation error: {str(e)}')

    # Define feature icons mapping
    feature_icons = {
        'WiFi': 'wifi',
        'TV': 'tv',
        'Air Conditioning': 'snowflake',
        'Mini Bar': 'glass-martini',
        'Room Service': 'concierge-bell',
        'Swimming Pool': 'swimming-pool',
        'Gym': 'dumbbell',
        'Parking': 'parking',
        'Restaurant': 'utensils',
        'Bar': 'glass-cheers',
        'Spa': 'spa',
        'Business Center': 'briefcase'
    }
    
    if request.method == 'POST' and form.validate():
        try:
            check_in = datetime.strptime(form.check_in.data, '%Y-%m-%d')
            check_out = datetime.strptime(form.check_out.data, '%Y-%m-%d')
            num_guests = int(form.num_guests.data)
            
            # Validation checks
            today = datetime.now().date()
            
            # 1. Check if dates are valid
            if check_in.date() < today:
                flash('Check-in date cannot be in the past', 'error')
                return redirect(request.url)
            
            if check_out <= check_in:
                flash('Check-out date must be after check-in date', 'error')
                return redirect(request.url)
            
            # 2. Check maximum stay duration (30 days)
            stay_duration = (check_out - check_in).days
            if stay_duration > 30:
                flash('Maximum stay duration is 30 days', 'error')
                return redirect(request.url)
            
            # 3. Check if booking is within 3 months
            max_future_date = today + timedelta(days=90)
            if check_in.date() > max_future_date:
                flash('Bookings can only be made up to 3 months in advance', 'error')
                return redirect(request.url)
            
            # 4. Validate guest count for room type
            if num_guests > room['max_guests']:
                flash(f'Maximum {room["max_guests"]} guests allowed for this room type', 'error')
                return redirect(request.url)
            
            # 5. Check room availability
            cursor.execute("""
                SELECT COUNT(*) as count 
                FROM bookings 
                WHERE room_id = %s 
                AND status = 'confirmed'
                AND (
                    (check_in_date <= %s AND check_out_date >= %s)
                    OR (check_in_date <= %s AND check_out_date >= %s)
                    OR (check_in_date >= %s AND check_out_date <= %s)
                )
            """, (room_id, check_out.date(), check_in.date(), 
                  check_out.date(), check_in.date(),
                  check_in.date(), check_out.date()))
            
            if cursor.fetchone()['count'] > 0:
                flash('Room is not available for selected dates', 'error')
                return redirect(request.url)
            
            # Calculate prices
            base_price = calculate_room_price(
                room['base_price_peak'],
                room['type_name'],
                check_in,
                num_guests
            )
            
            # Calculate total price for entire stay
            total_base_price = base_price * Decimal(str(stay_duration))
            
            # Calculate advance booking discount
            days_ahead = (check_in.date() - today).days
            if 80 <= days_ahead <= 90:
                discount_rate = Decimal('0.30')
            elif 60 <= days_ahead <= 79:
                discount_rate = Decimal('0.20')
            elif 45 <= days_ahead <= 59:
                discount_rate = Decimal('0.10')
            else:
                discount_rate = Decimal('0')
            
            discount_amount = total_base_price * discount_rate
            final_price = total_base_price - discount_amount
            
            # Convert to selected currency
            converted_price = final_price * exchange_rate
            
            # Store booking details in session for confirmation page
            session['pending_booking'] = {
                'room_id': room_id,
                'hotel_name': room['hotel_name'],
                'room_type': room['type_name'],
                'check_in': check_in.strftime('%Y-%m-%d'),
                'check_out': check_out.strftime('%Y-%m-%d'),
                'num_guests': num_guests,
                'total_price': float(converted_price),
                'currency': currency,
                'currency_symbol': currency_symbol,
                'discount_amount': float(discount_amount * exchange_rate),
                'stay_duration': stay_duration
            }
            
            return redirect(url_for('booking_payment'))
            
        except Exception as e:
            app.logger.error(f'Booking error: {str(e)}')
            flash('An error occurred while processing your booking', 'error')
            return redirect(request.url)
    
    # For GET request, pre-fill form with query parameters
    if request.method == 'GET':
        form.check_in.data = request.args.get('check_in', '')
        form.check_out.data = request.args.get('check_out', '')
        form.num_guests.data = request.args.get('guests', '1')
    
    return render_template('book_room.html',
                         form=form,
                         room=room,
                         currency=currency,
                         currency_symbol=currency_symbol,
                         currencies=CURRENCY_SYMBOLS,
                         feature_icons=feature_icons,
                         today=datetime.now().strftime('%Y-%m-%d'),
                         max_date=(datetime.now() + timedelta(days=90)).strftime('%Y-%m-%d'))


# calculate price route
@app.route('/calculate_price/<int:room_id>', methods=['GET'])
def calculate_price(room_id):
    try:
        check_in = request.args.get('check_in')
        check_out = request.args.get('check_out')
        num_guests = int(request.args.get('num_guests', 1))
        
        cursor = get_db()
        cursor.execute("""
            SELECT r.*, rt.type_name
            FROM rooms r
            JOIN room_types rt ON r.room_type_id = rt.room_type_id
            WHERE r.room_id = %s
        """, (room_id,))
        room = cursor.fetchone()
        cursor.close()
        
        if not room or not check_in or not check_out:
            return jsonify({'error': 'Invalid parameters'})
            
        # Get currency preferences
        currency = session.get('currency', 'GBP')
        exchange_rate = Decimal(str(EXCHANGE_RATES.get(currency, 1.0)))
        currency_symbol = CURRENCY_SYMBOLS.get(currency, '£')
        
        # Calculate prices
        check_in_date = datetime.strptime(check_in, '%Y-%m-%d')
        check_out_date = datetime.strptime(check_out, '%Y-%m-%d')
        stay_duration = (check_out_date - check_in_date).days
        
        base_price = calculate_room_price(
            room['base_price_peak'],
            room['type_name'],
            check_in_date,
            num_guests
        )
        
        total_base_price = base_price * Decimal(str(stay_duration))
        
        # Calculate advance booking discount
        days_ahead = (check_in_date.date() - datetime.now().date()).days
        if days_ahead >= 80:
            discount_rate = 30
        elif days_ahead >= 60:
            discount_rate = 20
        elif days_ahead >= 45:
            discount_rate = 10
        else:
            discount_rate = 0
            
        # Calculate final prices
        base_price_per_night = (base_price * exchange_rate).quantize(Decimal('0.01'))
        total_base_price_converted = (total_base_price * exchange_rate).quantize(Decimal('0.01'))
        
        if discount_rate > 0:
            discount_amount = total_base_price * (Decimal(str(discount_rate)) / Decimal('100'))
            discount_amount_converted = (discount_amount * exchange_rate).quantize(Decimal('0.01'))
            final_price = ((total_base_price - discount_amount) * exchange_rate).quantize(Decimal('0.01'))
        else:
            discount_amount_converted = Decimal('0')
            final_price = total_base_price_converted
            
        return jsonify({
            'base_price_per_night': float(base_price_per_night),
            'num_nights': stay_duration,
            'total_base_price': float(total_base_price_converted),
            'discount_rate': discount_rate,
            'discount_amount': float(discount_amount_converted),
            'final_price': float(final_price),
            'currency_symbol': currency_symbol
        })
        
    except Exception as e:
        app.logger.error(f'Price calculation error: {str(e)}')
        return jsonify({'error': 'Error calculating price'})

# booking payment route
@app.route('/booking/payment', methods=['GET', 'POST'])
@login_required
def booking_payment():
    if 'pending_booking' not in session:
        flash('No pending booking found', 'error')
        return redirect(url_for('search'))
        
    form = PaymentForm()
    booking = session['pending_booking']
    
    if form.validate_on_submit():
        try:
            cursor = get_db()
            
            # Create booking in database
            cursor.execute("""
                INSERT INTO bookings (
                    user_id, room_id, check_in_date, check_out_date,
                    num_guests, total_price, applied_discount,
                    currency, exchange_rate, status,
                    guest_name, guest_email, guest_phone,
                    special_requests
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'confirmed',
                         %s, %s, %s, %s)
            """, (
                session['user_id'], booking['room_id'],
                booking['check_in'], booking['check_out'],
                booking['num_guests'], booking['total_price'],
                booking['discount_amount'], booking['currency'],
                Decimal(str(EXCHANGE_RATES.get(booking['currency'], 1.0))),
                form.full_name.data, form.email.data,
                form.phone.data, form.special_requests.data
            ))
            
            mysql.connection.commit()
            booking_id = cursor.lastrowid
            
            # Send email notification if there's a special request
            special_request = form.special_requests.data
            if special_request:
                booking_data = {
                    'booking_id': booking_id,
                    'guest_name': form.full_name.data,
                    'guest_email': form.email.data,
                    'check_in_date': datetime.strptime(booking['check_in'], '%Y-%m-%d'),
                    'check_out_date': datetime.strptime(booking['check_out'], '%Y-%m-%d'),
                    'room_type': booking.get('room_type', 'Standard Room')
                }
                
                email_sent = send_special_request_email(booking_data, special_request)
                if email_sent:
                    app.logger.info(f"Special request email sent for booking {booking_id}")
                else:
                    app.logger.warning(f"Failed to send special request email for booking {booking_id}")
            
            # Store final booking details in session
            session['booking_details'] = booking
            session['booking_details']['booking_id'] = booking_id
            
            # Clear pending booking
            session.pop('pending_booking', None)
            
            flash('Booking confirmed successfully!', 'success')
            return redirect(url_for('booking_confirmation', booking_id=booking_id))
            
        except Exception as e:
            mysql.connection.rollback()
            app.logger.error(f'Payment error: {str(e)}')
            flash('An error occurred while processing your payment', 'error')
            return redirect(request.url)
    
    return render_template('booking_payment.html',
                         form=form,
                         booking=booking)

# booking confirmation route
@app.route('/booking/confirmation/<int:booking_id>')
@login_required
def booking_confirmation(booking_id):
    cursor = get_db()
    
    # Get currency from session or default to GBP
    currency = session.get('currency', 'GBP')
    exchange_rate = Decimal(str(EXCHANGE_RATES.get(currency, 1.0)))
    currency_symbol = CURRENCY_SYMBOLS.get(currency, '£')
    
    cursor.execute("""
        SELECT b.*, r.room_number, h.hotel_name, rt.type_name,
               b.currency as booking_currency, b.exchange_rate as booking_exchange_rate,
               b.guest_name, b.guest_email, b.guest_phone, b.special_requests
        FROM bookings b
        JOIN rooms r ON b.room_id = r.room_id
        JOIN hotels h ON r.hotel_id = h.hotel_id
        JOIN room_types rt ON r.room_type_id = rt.room_type_id
        WHERE b.booking_id = %s AND b.user_id = %s
    """, (booking_id, session['user_id']))
    booking = cursor.fetchone()
    cursor.close()
    
    if not booking:
        flash('Booking not found', 'error')
        return redirect(url_for('my_bookings'))
    
    # Convert prices if current currency is different from booking currency
    if currency != booking['booking_currency']:
        conversion_rate = exchange_rate / Decimal(str(booking['booking_exchange_rate']))
        booking['total_price'] = (Decimal(str(booking['total_price'])) * conversion_rate).quantize(Decimal('0.01'))
        booking['applied_discount'] = (Decimal(str(booking['applied_discount'])) * conversion_rate).quantize(Decimal('0.01'))
    
    return render_template('booking_confirmation.html',
                         booking=booking,
                         currency=currency,
                         currency_symbol=currency_symbol)

# cancel booking route
@app.route('/bookings/cancel/<int:booking_id>', methods=['POST'])
@login_required
def cancel_booking(booking_id):
    form = CancellationForm()
    
    if form.validate_on_submit():
        cursor = get_db()
        
        cursor.execute("""
            SELECT * FROM bookings 
            WHERE booking_id = %s AND user_id = %s
        """, (booking_id, session['user_id']))
        booking = cursor.fetchone()
        
        if not booking:
            flash('Booking not found', 'error')
            return redirect(url_for('my_bookings'))
            
        # Calculate cancellation charges
        check_in_date = booking['check_in_date']
        days_until_checkin = (check_in_date - datetime.now().date()).days
        total_price = Decimal(str(booking['total_price']))
        
        if days_until_checkin > 60:
            cancellation_charge = Decimal('0.00')
        elif days_until_checkin > 30:
            cancellation_charge = total_price * Decimal('0.5')
        else:
            cancellation_charge = total_price
            
        refund_amount = total_price - cancellation_charge
            
        cursor.execute("""
            UPDATE bookings 
            SET status = 'cancelled',
                cancellation_charge = %s,
                cancellation_date = NOW()
            WHERE booking_id = %s
        """, (cancellation_charge, booking_id))
        mysql.connection.commit()
        cursor.close()
        
        flash(f'Booking cancelled. Refund amount: £{refund_amount:.2f}', 'info')
    else:
        flash('Invalid request', 'error')
        
    return redirect(url_for('my_bookings'))

# my bookings route
@app.route('/my-bookings')
@login_required
def my_bookings():
    form = CancellationForm()
    cursor = get_db()
    
    # Get current currency preferences
    currency = session.get('currency', 'GBP')
    exchange_rate = Decimal(str(EXCHANGE_RATES.get(currency, 1.0)))
    currency_symbol = CURRENCY_SYMBOLS.get(currency, '£')
    
    cursor.execute("""
        SELECT b.*, r.room_number, h.hotel_name, rt.type_name,
               b.currency as booking_currency, b.exchange_rate as booking_exchange_rate
        FROM bookings b
        JOIN rooms r ON b.room_id = r.room_id
        JOIN hotels h ON r.hotel_id = h.hotel_id
        JOIN room_types rt ON r.room_type_id = rt.room_type_id
        WHERE b.user_id = %s
        ORDER BY b.booking_date DESC
    """, (session['user_id'],))
    bookings = cursor.fetchall()
    
    # Convert prices to current currency
    for booking in bookings:
        if currency != booking['booking_currency']:
            conversion_rate = exchange_rate / Decimal(str(booking['booking_exchange_rate']))
            booking['total_price'] = (Decimal(str(booking['total_price'])) * conversion_rate).quantize(Decimal('0.01'))
            if booking['applied_discount']:
                booking['applied_discount'] = (Decimal(str(booking['applied_discount'])) * conversion_rate).quantize(Decimal('0.01'))
    
    cursor.close()
    
    return render_template('my_bookings.html', 
                         bookings=bookings,
                         form=form,
                         currency=currency,
                         currency_symbol=currency_symbol,
                         currencies=CURRENCY_SYMBOLS,  # Add this line
                         today=datetime.now().date())

# admin bookings route
@app.route('/admin/bookings')
@admin_required
def admin_bookings():
    cursor = get_db()
    
    # Get filter parameters
    status = request.args.get('status', '')
    hotel_id = request.args.get('hotel_id', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # Base query
    query = """
        SELECT b.*, 
               h.hotel_name,
               r.room_number,
               rt.type_name as room_type,
               CONCAT(u.first_name, ' ', u.last_name) as guest_name,
               u.email as guest_email,
               COUNT(*) OVER() as total_count
        FROM bookings b
        JOIN rooms r ON b.room_id = r.room_id
        JOIN hotels h ON r.hotel_id = h.hotel_id
        JOIN room_types rt ON r.room_type_id = rt.room_type_id
        JOIN users u ON b.user_id = u.user_id
        WHERE 1=1
    """
    params = []
    
    # Add filters
    if status:
        query += " AND b.status = %s"
        params.append(status)
    if hotel_id:
        query += " AND h.hotel_id = %s"
        params.append(hotel_id)
    if date_from:
        query += " AND b.check_in_date >= %s"
        params.append(date_from)
    if date_to:
        query += " AND b.check_out_date <= %s"
        params.append(date_to)
    
    query += " ORDER BY b.booking_date DESC LIMIT %s OFFSET %s"
    params.extend([per_page, (page - 1) * per_page])
    
    cursor.execute(query, params)
    bookings = cursor.fetchall()
    
    total_count = bookings[0]['total_count'] if bookings else 0
    total_pages = (total_count + per_page - 1) // per_page
    
    # Get hotels for filter dropdown
    cursor.execute("SELECT hotel_id, hotel_name FROM hotels ORDER BY hotel_name")
    hotels = cursor.fetchall()
    
    cursor.close()
    
    return render_template('admin/manage_bookings.html',
                         bookings=bookings,
                         hotels=hotels,
                         page=page,
                         total_pages=total_pages,
                         filters={
                             'status': status,
                             'hotel_id': hotel_id,
                             'date_from': date_from,
                             'date_to': date_to
                         })

# admin booking detail route
@app.route('/admin/bookings/<int:booking_id>')
@admin_required
def admin_booking_detail(booking_id):
    cursor = get_db()
    
    try:
        # Get booking details
        cursor.execute("""
            SELECT b.*, 
                   h.hotel_id,
                   h.hotel_name, 
                   h.address as hotel_address,
                   r.room_number, 
                   r.description as room_description,
                   rt.type_name as room_type, 
                   rt.max_guests,
                   CONCAT(u.first_name, ' ', u.last_name) as guest_name,
                   u.email as guest_email,
                   u.phone as guest_phone
            FROM bookings b
            JOIN rooms r ON b.room_id = r.room_id
            JOIN hotels h ON r.hotel_id = h.hotel_id
            JOIN room_types rt ON r.room_type_id = rt.room_type_id
            JOIN users u ON b.user_id = u.user_id
            WHERE b.booking_id = %s
        """, (booking_id,))
        booking = cursor.fetchone()
        
        if not booking:
            abort(404)
        
        # Calculate booking statistics
        nights = (booking['check_out_date'] - booking['check_in_date']).days
        price_per_night = booking['total_price'] / nights if nights > 0 else 0
        
    except Exception as e:
        flash(f'Error retrieving booking details: {str(e)}', 'error')
        return redirect(url_for('admin_bookings'))
    
    finally:
        cursor.close()
    
    return render_template('admin/edit_bookings.html',
                         booking=booking,
                         nights=nights,
                         price_per_night=price_per_night)

# admin update booking status route
@app.route('/admin/bookings/<int:booking_id>/update-status', methods=['POST'])
@admin_required
def admin_update_booking_status(booking_id):
    cursor = get_db()
    try:
        new_status = request.form.get('status')
        if new_status not in ['confirmed', 'cancelled', 'completed']:
            raise ValueError('Invalid status')
        
        cursor.execute("""
            UPDATE bookings 
            SET status = %s,
                cancellation_date = CASE 
                    WHEN %s = 'cancelled' THEN CURRENT_TIMESTAMP
                    ELSE cancellation_date
                END
            WHERE booking_id = %s
        """, (new_status, new_status, booking_id))
        
        mysql.connection.commit()
        flash('Booking status updated successfully!', 'success')
        
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error updating booking status: {str(e)}', 'error')
        
    finally:
        cursor.close()
        
    return redirect(url_for('admin_booking_detail', booking_id=booking_id))

#admin export bookings route
@app.route('/admin/bookings/export')
@admin_required
def admin_export_bookings():
    cursor = get_db()
    
    # Get filter parameters (similar to admin_bookings)
    status = request.args.get('status', '')
    hotel_id = request.args.get('hotel_id', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    # Query bookings with filters
    query = """
        SELECT 
            b.booking_id,
            h.hotel_name,
            r.room_number,
            rt.type_name as room_type,
            CONCAT(u.first_name, ' ', u.last_name) as guest_name,
            u.email as guest_email,
            b.check_in_date,
            b.check_out_date,
            b.num_guests,
            b.total_price,
            b.status,
            b.booking_date
        FROM bookings b
        JOIN rooms r ON b.room_id = r.room_id
        JOIN hotels h ON r.hotel_id = h.hotel_id
        JOIN room_types rt ON r.room_type_id = rt.room_type_id
        JOIN users u ON b.user_id = u.user_id
        WHERE 1=1
    """
    params = []
    
    # Add filters (similar to admin_bookings)
    if status:
        query += " AND b.status = %s"
        params.append(status)
    if hotel_id:
        query += " AND h.hotel_id = %s"
        params.append(hotel_id)
    if date_from:
        query += " AND b.check_in_date >= %s"
        params.append(date_from)
    if date_to:
        query += " AND b.check_out_date <= %s"
        params.append(date_to)
    
    query += " ORDER BY b.booking_date DESC"
    
    cursor.execute(query, params)
    bookings = cursor.fetchall()
    
    # Create CSV response
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write headers
    writer.writerow([
        'Booking ID', 'Hotel', 'Room', 'Room Type', 'Guest', 'Email',
        'Check-in', 'Check-out', 'Guests', 'Total Price', 'Status', 'Booking Date'
    ])
    
    # Write data
    for booking in bookings:
        writer.writerow([
            booking['booking_id'],
            booking['hotel_name'],
            booking['room_number'],
            booking['room_type'],
            booking['guest_name'],
            booking['guest_email'],
            booking['check_in_date'].strftime('%Y-%m-%d'),
            booking['check_out_date'].strftime('%Y-%m-%d'),
            booking['num_guests'],
            f"£{booking['total_price']:.2f}",
            booking['status'],
            booking['booking_date'].strftime('%Y-%m-%d %H:%M:%S')
        ])
    
    cursor.close()
    
    # Create response
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={
            'Content-Disposition': 'attachment; filename=bookings_export.csv'
        }
    )
    
#admin dashboard route
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    cursor = get_db()
    
    # Get overall statistics - Fixed CROSS JOIN issue
    cursor.execute("""
        SELECT 
            (SELECT COUNT(*) FROM bookings WHERE status IN ('confirmed', 'completed')) as total_bookings,
            (SELECT COUNT(*) FROM bookings WHERE status = 'confirmed') as active_bookings,
            (SELECT COUNT(*) FROM bookings WHERE status = 'cancelled') as cancelled_bookings,
            (SELECT COALESCE(SUM(total_price), 0) FROM bookings WHERE status IN ('confirmed', 'completed')) as total_revenue,
            (SELECT COUNT(*) FROM users WHERE user_type = 'customer') as total_users,
            (SELECT COUNT(*) FROM hotels) as total_hotels,
            (SELECT COUNT(*) FROM rooms) as total_rooms
    """)
    stats = cursor.fetchone()
    
    # Get monthly revenue for the current year - Added status filter
    cursor.execute("""
        SELECT 
            MONTH(booking_date) as month,
            COALESCE(SUM(total_price), 0) as revenue
        FROM bookings
        WHERE YEAR(booking_date) = YEAR(CURRENT_DATE)
        AND status IN ('confirmed', 'completed')
        GROUP BY MONTH(booking_date)
        ORDER BY month
    """)
    monthly_revenue = cursor.fetchall()
    
    # Get top performing hotels - Fixed JOIN and added status filter
    cursor.execute("""
        SELECT 
            h.hotel_name,
            COUNT(DISTINCT b.booking_id) as booking_count,
            COALESCE(SUM(b.total_price), 0) as revenue
        FROM hotels h
        LEFT JOIN rooms r ON h.hotel_id = r.hotel_id
        LEFT JOIN bookings b ON r.room_id = b.room_id 
            AND b.status IN ('confirmed', 'completed')
            AND b.booking_date >= DATE_SUB(CURRENT_DATE, INTERVAL 30 DAY)
        GROUP BY h.hotel_id, h.hotel_name
        HAVING booking_count > 0
        ORDER BY revenue DESC
        LIMIT 5
    """)
    top_hotels = cursor.fetchall()
    
    # Get recent bookings - Added ORDER BY
    cursor.execute("""
        SELECT 
            b.booking_id,
            b.booking_date,
            b.check_in_date,
            b.check_out_date,
            b.total_price,
            b.status,
            h.hotel_name,
            CONCAT(u.first_name, ' ', u.last_name) as guest_name
        FROM bookings b
        JOIN rooms r ON b.room_id = r.room_id
        JOIN hotels h ON r.hotel_id = h.hotel_id
        JOIN users u ON b.user_id = u.user_id
        ORDER BY b.booking_date DESC
        LIMIT 10
    """)
    recent_bookings = cursor.fetchall()
    
    # Get room occupancy data - Fixed occupancy calculation
    cursor.execute("""
        SELECT 
            rt.type_name,
            COUNT(DISTINCT r.room_id) as total_rooms,
            COUNT(DISTINCT CASE 
                WHEN b.status = 'confirmed' 
                AND CURRENT_DATE BETWEEN b.check_in_date AND b.check_out_date 
                THEN r.room_id 
            END) as occupied_rooms
        FROM room_types rt
        JOIN rooms r ON rt.room_type_id = r.room_type_id
        LEFT JOIN bookings b ON r.room_id = b.room_id
        GROUP BY rt.room_type_id, rt.type_name
        ORDER BY total_rooms DESC
    """)
    room_occupancy = cursor.fetchall()
    
    cursor.close()
    
    # Prepare data for charts - Initialize all months
    months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 
              'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    revenue_data = [0] * 12
    for row in monthly_revenue:
        revenue_data[row['month']-1] = float(row['revenue'])
    
    return render_template('admin/dashboard.html',
                         stats=stats,
                         months=months,
                         revenue_data=revenue_data,
                         top_hotels=top_hotels,
                         recent_bookings=recent_bookings,
                         room_occupancy=room_occupancy)
# admin hotels route
@app.route('/admin/hotels')
@admin_required
def admin_hotels():
    cursor = get_db()
    
    # Get search parameters
    search = request.args.get('search', '')
    city_filter = request.args.get('city', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # Build query
    query = """
        SELECT h.*, c.city_name,
            COUNT(DISTINCT r.room_id) as room_count,
            COUNT(DISTINCT b.booking_id) as booking_count,
            COUNT(*) OVER() as total_count
        FROM hotels h
        JOIN cities c ON h.city_id = c.city_id
        LEFT JOIN rooms r ON h.hotel_id = r.hotel_id
        LEFT JOIN bookings b ON r.room_id = b.room_id
        WHERE 1=1
    """
    params = []
    
    if search:
        query += " AND h.hotel_name LIKE %s"
        params.append(f'%{search}%')
    
    if city_filter:
        query += " AND c.city_id = %s"
        params.append(city_filter)
    
    query += " GROUP BY h.hotel_id ORDER BY h.hotel_name LIMIT %s OFFSET %s"
    params.extend([per_page, (page - 1) * per_page])
    
    cursor.execute(query, params)
    hotels = cursor.fetchall()
    
    total_count = hotels[0]['total_count'] if hotels else 0
    total_pages = (total_count + per_page - 1) // per_page
    
    # Get cities for filter
    cursor.execute("SELECT * FROM cities ORDER BY city_name")
    cities = cursor.fetchall()
    
    cursor.close()
    
    return render_template('admin/manage_hotels.html',
                         hotels=hotels,
                         cities=cities,
                         search=search,
                         city_filter=city_filter,
                         page=page,
                         total_pages=total_pages)

# admin add hotel route
@app.route('/admin/hotels/add', methods=['GET', 'POST'])
@admin_required
def admin_add_hotel():
    cursor = get_db()
    
    if request.method == 'POST':
        try:
            # Get form data
            hotel_name = request.form['hotel_name']
            city_id = request.form['city_id']
            description = request.form['description']
            address = request.form['address']
            total_rooms = request.form['total_rooms']
            star_rating = request.form['star_rating']
            features = request.form['features']
            check_in_time = request.form['check_in_time']
            check_out_time = request.form['check_out_time']
            
            # Handle image upload
            if 'main_image' in request.files:
                file = request.files['main_image']
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    main_image = f'uploads/hotels/{filename}'
                else:
                    main_image = None
            else:
                main_image = None

            
            # Insert hotel
            cursor.execute("""
                INSERT INTO hotels (
                    city_id, hotel_name, description, address, 
                    total_rooms, star_rating, main_image, features,
                    check_in_time, check_out_time
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                city_id, hotel_name, description, address,
                total_rooms, star_rating, main_image, features,
                check_in_time, check_out_time
            ))
            
            mysql.connection.commit()
            flash('Hotel added successfully!', 'success')
            return redirect(url_for('admin_hotels'))
            
        except Exception as e:
            mysql.connection.rollback()
            flash(f'Error adding hotel: {str(e)}', 'error')
            
    # Get cities for dropdown
    cursor.execute("SELECT * FROM cities ORDER BY city_name")
    cities = cursor.fetchall()
    cursor.close()
    
    return render_template('admin/add_hotels.html', cities=cities)

# admin edit hotel route
@app.route('/admin/hotels/edit/<int:hotel_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_hotel(hotel_id):
    cursor = get_db()
    
    # Get reviews for this hotel
    cursor.execute("""
        SELECT r.*, u.first_name, u.last_name 
        FROM reviews r
        JOIN users u ON r.user_id = u.user_id
        WHERE r.hotel_id = %s
        ORDER BY r.review_date DESC
    """, (hotel_id,))
    reviews = cursor.fetchall()
    
    if request.method == 'POST':
        try:
            # Update hotel data
            cursor.execute("""
                UPDATE hotels SET
                    city_id = %s,
                    hotel_name = %s,
                    description = %s,
                    address = %s,
                    total_rooms = %s,
                    star_rating = %s,
                    features = %s,
                    check_in_time = %s,
                    check_out_time = %s
                WHERE hotel_id = %s
            """, (
                request.form['city_id'],
                request.form['hotel_name'],
                request.form['description'],
                request.form['address'],
                request.form['total_rooms'],
                request.form['star_rating'],
                request.form['features'],
                request.form['check_in_time'],
                request.form['check_out_time'],
                hotel_id
            ))
            
            # Handle image update if provided
            if 'main_image' in request.files and request.files['main_image'].filename:
                file = request.files['main_image']
                if allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    cursor.execute(
                        "UPDATE hotels SET main_image = %s WHERE hotel_id = %s",
                        (f'uploads/hotels/{filename}', hotel_id)
                    )
            
            mysql.connection.commit()
            flash('Hotel updated successfully!', 'success')
            return redirect(url_for('admin_hotels'))
            
        except Exception as e:
            mysql.connection.rollback()
            flash(f'Error updating hotel: {str(e)}', 'error')
    
    # Get hotel data
    cursor.execute("""
        SELECT h.*, c.city_name 
        FROM hotels h 
        JOIN cities c ON h.city_id = c.city_id 
        WHERE h.hotel_id = %s
    """, (hotel_id,))
    hotel = cursor.fetchone()
    
    if not hotel:
        cursor.close()
        abort(404)
    
    # Get cities for dropdown
    cursor.execute("SELECT * FROM cities ORDER BY city_name")
    cities = cursor.fetchall()
    cursor.close()
    
    return render_template('admin/edit_hotels.html',
                         hotel=hotel,
                         cities=cities,
                         reviews=reviews)

# admin delete hotel route
@app.route('/admin/hotels/delete/<int:hotel_id>', methods=['POST'])
@admin_required
def admin_delete_hotel(hotel_id):
    cursor = get_db()
    try:
        # Check for existing bookings
        cursor.execute("""
            SELECT COUNT(*) as booking_count 
            FROM bookings b 
            JOIN rooms r ON b.room_id = r.room_id 
            WHERE r.hotel_id = %s
        """, (hotel_id,))
        result = cursor.fetchone()
        
        if result['booking_count'] > 0:
            flash('Cannot delete hotel with existing bookings', 'error')
            return redirect(url_for('admin_hotels'))
        
        # Delete associated rooms first
        cursor.execute("DELETE FROM rooms WHERE hotel_id = %s", (hotel_id,))
        
        # Delete the hotel
        cursor.execute("DELETE FROM hotels WHERE hotel_id = %s", (hotel_id,))
        
        mysql.connection.commit()
        flash('Hotel deleted successfully!', 'success')
        
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error deleting hotel: {str(e)}', 'error')
        
    finally:
        cursor.close()
        
    return redirect(url_for('admin_hotels'))

# admin hotel rooms route
@app.route('/admin/hotels/<int:hotel_id>/rooms')
@admin_required
def admin_hotel_rooms(hotel_id):
    cursor = get_db()
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # Get hotel details
    cursor.execute("""
        SELECT h.*, c.city_name 
        FROM hotels h 
        JOIN cities c ON h.city_id = c.city_id 
        WHERE h.hotel_id = %s
    """, (hotel_id,))
    hotel = cursor.fetchone()
    
    if not hotel:
        cursor.close()
        abort(404)
    
    # Get rooms with pagination
    cursor.execute("""
        SELECT r.*, rt.type_name, rt.max_guests,
               COUNT(DISTINCT b.booking_id) as booking_count,
               COUNT(DISTINCT CASE 
                   WHEN b.status = 'confirmed' 
                   AND CURRENT_DATE BETWEEN b.check_in_date AND b.check_out_date 
                   THEN b.booking_id 
               END) as current_bookings,
               COUNT(*) OVER() as total_count
        FROM rooms r
        JOIN room_types rt ON r.room_type_id = rt.room_type_id
        LEFT JOIN bookings b ON r.room_id = b.room_id
        WHERE r.hotel_id = %s
        GROUP BY r.room_id
        ORDER BY r.room_number
        LIMIT %s OFFSET %s
    """, (hotel_id, per_page, (page - 1) * per_page))
    rooms = cursor.fetchall()
    
    total_count = rooms[0]['total_count'] if rooms else 0
    total_pages = (total_count + per_page - 1) // per_page
    
    cursor.close()
    
    return render_template('admin/manage_rooms.html',
                         hotel=hotel,
                         rooms=rooms,
                         page=page,
                         total_pages=total_pages)

# admin add room route
@app.route('/admin/hotels/<int:hotel_id>/rooms/add', methods=['GET', 'POST'])
@admin_required
def admin_add_room(hotel_id):
    cursor = get_db()
    
    if request.method == 'POST':
        try:

            main_image = None
            if 'main_image' in request.files:
                file = request.files['main_image']
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(ROOM_UPLOAD_FOLDER, filename))
                    main_image = f'uploads/rooms/{filename}'

            # Get form data
            room_type_id = request.form['room_type_id']
            room_number = request.form['room_number']
            floor_number = request.form['floor_number']
            base_price_peak = request.form['base_price_peak']
            base_price_offpeak = request.form['base_price_offpeak']
            description = request.form['description']
            features = request.form.get('features', '')
            
            # Handle image upload
            main_image = None
            if 'main_image' in request.files:
                file = request.files['main_image']
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    main_image = f'uploads/rooms/{filename}'
            
            # Insert room
            cursor.execute("""
                INSERT INTO rooms (
                    hotel_id, room_type_id, room_number, floor_number,
                    base_price_peak, base_price_offpeak, description,
                    features, main_image, is_active
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, TRUE)
            """, (
                hotel_id, room_type_id, room_number, floor_number,
                base_price_peak, base_price_offpeak, description,
                features, main_image
            ))
            
            mysql.connection.commit()
            flash('Room added successfully!', 'success')
            return redirect(url_for('admin_hotel_rooms', hotel_id=hotel_id))
            
        except Exception as e:
            mysql.connection.rollback()
            flash(f'Error adding room: {str(e)}', 'error')
    
    # Get hotel details
    cursor.execute("""
        SELECT h.*, c.city_name 
        FROM hotels h 
        JOIN cities c ON h.city_id = c.city_id 
        WHERE h.hotel_id = %s
    """, (hotel_id,))
    hotel = cursor.fetchone()
    
    if not hotel:
        cursor.close()
        abort(404)
    
    # Get room types
    cursor.execute("SELECT * FROM room_types ORDER BY type_name")
    room_types = cursor.fetchall()
    
    cursor.close()
    
    return render_template('admin/add_rooms.html',
                         hotel=hotel,
                         room_types=room_types)

# admin delete room route
@app.route('/admin/hotels/<int:hotel_id>/rooms/<int:room_id>/delete', methods=['POST'])
@admin_required
def admin_delete_room(hotel_id, room_id):
    cursor = get_db()
    try:
        # Check for existing bookings
        cursor.execute("""
            SELECT COUNT(*) as booking_count 
            FROM bookings 
            WHERE room_id = %s AND status = 'confirmed'
        """, (room_id,))
        result = cursor.fetchone()
        
        if result['booking_count'] > 0:
            flash('Cannot delete room with existing bookings', 'error')
            return redirect(url_for('admin_hotel_rooms', hotel_id=hotel_id))
        
        # Delete the room
        cursor.execute("DELETE FROM rooms WHERE room_id = %s", (room_id,))
        
        mysql.connection.commit()
        flash('Room deleted successfully!', 'success')
        
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error deleting room: {str(e)}', 'error')
        
    finally:
        cursor.close()
        
    return redirect(url_for('admin_hotel_rooms', hotel_id=hotel_id))

# admin edit room route
@app.route('/admin/hotels/<int:hotel_id>/rooms/<int:room_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_room(hotel_id, room_id):
    cursor = get_db()
    
    if request.method == 'POST':
        try:
            # Handle image upload first
            if 'main_image' in request.files and request.files['main_image'].filename:
                file = request.files['main_image']
                if allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(ROOM_UPLOAD_FOLDER, filename))
                    cursor.execute(
                        "UPDATE rooms SET main_image = %s WHERE room_id = %s",
                        (f'uploads/rooms/{filename}', room_id)
                    )

            # Get the current booking status
            cursor.execute("""
                SELECT COUNT(*) as active_bookings
                FROM bookings
                WHERE room_id = %s 
                AND status = 'confirmed'
                AND check_out_date > CURRENT_DATE
            """, (room_id,))
            booking_status = cursor.fetchone()
            
            # Determine if room can be marked as unavailable
            is_active = 'is_active' in request.form
            if booking_status['active_bookings'] > 0 and not is_active:
                flash('Cannot mark room as unavailable while it has active bookings', 'error')
                is_active = True  # Force room to stay active
            
            # Update room data
            cursor.execute("""
                UPDATE rooms SET
                    room_type_id = %s,
                    room_number = %s,
                    description = %s,
                    base_price_peak = %s,
                    base_price_offpeak = %s,
                    features = %s,
                    floor_number = %s,
                    is_active = %s,
                    status = %s
                WHERE room_id = %s AND hotel_id = %s
            """, (
                request.form['room_type_id'],
                request.form['room_number'],
                request.form['description'],
                request.form['base_price_peak'],
                request.form['base_price_offpeak'],
                request.form['features'],
                request.form['floor_number'],
                is_active,
                request.form.get('room_status', 'available'),  # New field
                room_id,
                hotel_id
            ))
            
            # Handle image update if provided
            if 'main_image' in request.files and request.files['main_image'].filename:
                file = request.files['main_image']
                if allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    cursor.execute(
                        "UPDATE rooms SET main_image = %s WHERE room_id = %s",
                        (f'uploads/rooms/{filename}', room_id)
                    )
            
            mysql.connection.commit()
            flash('Room updated successfully!', 'success')
            return redirect(url_for('admin_hotel_rooms', hotel_id=hotel_id))
            
        except Exception as e:
            mysql.connection.rollback()
            flash(f'Error updating room: {str(e)}', 'error')
    
    # Get room data with current booking status
    cursor.execute("""
        SELECT r.*, h.hotel_name,
               COUNT(DISTINCT b.booking_id) as booking_count,
               COUNT(DISTINCT CASE 
                   WHEN b.status = 'confirmed' AND b.check_out_date > CURRENT_DATE 
                   THEN b.booking_id 
               END) as active_bookings,
               COALESCE(r.status, 'available') as room_status
        FROM rooms r 
        JOIN hotels h ON r.hotel_id = h.hotel_id 
        LEFT JOIN bookings b ON r.room_id = b.room_id
        WHERE r.room_id = %s AND r.hotel_id = %s
        GROUP BY r.room_id, h.hotel_name
    """, (room_id, hotel_id))
    room = cursor.fetchone()
    
    if not room:
        cursor.close()
        abort(404)
    
    # Get room types
    cursor.execute("SELECT * FROM room_types ORDER BY type_name")
    room_types = cursor.fetchall()
    
    cursor.close()
    
    return render_template('admin/edit_rooms.html',
                         room=room,
                         room_types=room_types,
                         hotel_id=hotel_id)

# admin users route
@app.route('/admin/users')
@admin_required
def admin_users():
    cursor = get_db()
    
    # Get filter parameters
    user_type = request.args.get('user_type', '')
    status = request.args.get('status', '')
    search = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # Base query
    query = """
        SELECT u.*,
               u.created_at as registration_date,
               COUNT(DISTINCT b.booking_id) as booking_count,
               MAX(b.booking_date) as last_booking_date,
               COALESCE(u.is_active, TRUE) as is_active,
               COUNT(*) OVER() as total_count
        FROM users u
        LEFT JOIN bookings b ON u.user_id = b.user_id
        WHERE 1=1
    """
    params = []
    
    # Add filters
    if user_type:
        query += " AND u.user_type = %s"
        params.append(user_type)
    if status:
        query += " AND COALESCE(u.is_active, TRUE) = %s"
        params.append(status == 'active')
    if search:
        query += """ AND (
            u.email LIKE %s OR 
            u.first_name LIKE %s OR 
            u.last_name LIKE %s OR 
            u.phone LIKE %s
        )"""
        search_param = f'%{search}%'
        params.extend([search_param] * 4)
    
    query += " GROUP BY u.user_id ORDER BY u.created_at DESC LIMIT %s OFFSET %s"
    params.extend([per_page, (page - 1) * per_page])
    
    cursor.execute(query, params)
    users = cursor.fetchall()
    
    total_count = users[0]['total_count'] if users else 0
    total_pages = (total_count + per_page - 1) // per_page
    
    cursor.close()
    
    return render_template('admin/manage_users.html',
                         users=users,
                         page=page,
                         total_pages=total_pages,
                         filters={
                             'user_type': user_type,
                             'status': status,
                             'search': search
                         })

# admin user detail route
@app.route('/admin/users/<int:user_id>')
@admin_required
def admin_user_detail(user_id):
    cursor = get_db()
    
    # Get user details with corrected total_spent calculation
    cursor.execute("""
        SELECT u.*,
               u.created_at as registration_date,
               COUNT(DISTINCT b.booking_id) as total_bookings,
               COALESCE(SUM(
                   CASE 
                       WHEN b.status = 'confirmed' OR b.status = 'completed' 
                       THEN b.total_price 
                       ELSE 0 
                   END
               ), 0) as total_spent,
               MAX(b.booking_date) as last_booking_date,
               COALESCE(u.is_active, TRUE) as is_active
        FROM users u
        LEFT JOIN bookings b ON u.user_id = b.user_id
        WHERE u.user_id = %s
        GROUP BY u.user_id
    """, (user_id,))
    user = cursor.fetchone()
    
    if not user:
        cursor.close()
        abort(404)
    
    # Get user's bookings
    cursor.execute("""
        SELECT b.*, 
               h.hotel_name, 
               r.room_number,
               h.hotel_id
        FROM bookings b
        JOIN rooms r ON b.room_id = r.room_id
        JOIN hotels h ON r.hotel_id = h.hotel_id
        WHERE b.user_id = %s
        ORDER BY b.booking_date DESC
    """, (user_id,))
    bookings = cursor.fetchall()
    
    cursor.close()
    
    return render_template('admin/edit_users.html',
                         user=user,
                         bookings=bookings)

# admin update user route
@app.route('/admin/users/<int:user_id>/update', methods=['POST'])
@admin_required
def admin_update_user(user_id):
    cursor = get_db()
    try:
        action = request.form.get('action')
        
        if action == 'update_profile':
            # Get current user's role
            cursor.execute("SELECT user_type FROM users WHERE user_id = %s", (session['user_id'],))
            current_admin = cursor.fetchone()
            
            # Update user profile
            first_name = sanitize_input(request.form.get('first_name'))
            last_name = sanitize_input(request.form.get('last_name'))
            phone = sanitize_input(request.form.get('phone'))
            is_active = 'is_active' in request.form
            user_type = request.form.get('user_type')
            
            # Prevent self-role-change and last admin removal
            if user_id == session['user_id'] and user_type != 'admin':
                flash('You cannot change your own admin status.', 'error')
                return redirect(url_for('admin_user_detail', user_id=user_id))
            
            # Check if this is the last admin before role change
            if current_admin['user_type'] == 'admin':
                cursor.execute("SELECT COUNT(*) as admin_count FROM users WHERE user_type = 'admin'")
                admin_count = cursor.fetchone()['admin_count']
                
                if admin_count <= 1 and user_type != 'admin' and user_id == session['user_id']:
                    flash('Cannot remove the last admin account.', 'error')
                    return redirect(url_for('admin_user_detail', user_id=user_id))
            
            cursor.execute("""
                UPDATE users 
                SET first_name = %s,
                    last_name = %s,
                    phone = %s,
                    is_active = %s,
                    user_type = %s
                WHERE user_id = %s
            """, (first_name, last_name, phone, is_active, user_type, user_id))
            
            flash('User profile updated successfully!', 'success')
            
        elif action == 'reset_password':
            # Validate new password
            new_password = request.form.get('new_password')
            is_valid, message = validate_password(new_password)
            
            if not is_valid:
                flash(message, 'error')
                return redirect(url_for('admin_user_detail', user_id=user_id))
                
            password_hash = generate_password_hash(new_password)
            
            cursor.execute("""
                UPDATE users 
                SET password_hash = %s
                WHERE user_id = %s
            """, (password_hash, user_id))
            
            flash('User password reset successfully!', 'success')
            
        mysql.connection.commit()
        
    except Exception as e:
        mysql.connection.rollback()
        flash(f'Error updating user: {str(e)}', 'error')
        app.logger.error(f'User update error: {str(e)}')
        
    finally:
        cursor.close()
        
    return redirect(url_for('admin_user_detail', user_id=user_id))

# admin reports route
@app.route('/admin/reports')
@admin_required
def admin_reports():
    cursor = get_db()
    
    # Get date range
    end_date = datetime.now()
    start_date = end_date - timedelta(days=30)  # Default to last 30 days
    
    date_range = request.args.get('range', '30')
    if date_range == '7':
        start_date = end_date - timedelta(days=7)
    elif date_range == '90':
        start_date = end_date - timedelta(days=90)
    elif date_range == '365':
        start_date = end_date - timedelta(days=365)
    
    # Revenue statistics - Add status filter
    cursor.execute("""
        SELECT 
            DATE(booking_date) as date,
            COUNT(*) as booking_count,
            COALESCE(SUM(total_price), 0) as revenue,
            COALESCE(AVG(total_price), 0) as avg_booking_value
        FROM bookings
        WHERE booking_date BETWEEN %s AND %s
        AND status IN ('confirmed', 'completed')
        GROUP BY DATE(booking_date)
        ORDER BY date
    """, (start_date, end_date))
    daily_stats = cursor.fetchall()
    
    # Top performing hotels - Add status filter
    cursor.execute("""
        SELECT 
            h.hotel_name,
            COUNT(b.booking_id) as booking_count,
            COALESCE(SUM(b.total_price), 0) as revenue
        FROM hotels h
        JOIN rooms r ON h.hotel_id = r.hotel_id
        JOIN bookings b ON r.room_id = b.room_id
        WHERE b.booking_date BETWEEN %s AND %s
        AND b.status IN ('confirmed', 'completed')
        GROUP BY h.hotel_id, h.hotel_name
        ORDER BY revenue DESC
        LIMIT 5
    """, (start_date, end_date))
    top_hotels = cursor.fetchall()
    
    # Room type popularity - Add status filter
    cursor.execute("""
        SELECT 
            rt.type_name,
            COUNT(b.booking_id) as booking_count
        FROM room_types rt
        JOIN rooms r ON rt.room_type_id = r.room_type_id
        JOIN bookings b ON r.room_id = b.room_id
        WHERE b.booking_date BETWEEN %s AND %s
        AND b.status IN ('confirmed', 'completed')
        GROUP BY rt.room_type_id, rt.type_name
        ORDER BY booking_count DESC
    """, (start_date, end_date))
    room_type_stats = cursor.fetchall()
    
    # Prepare chart data with null handling
    dates = [stat['date'].strftime('%Y-%m-%d') for stat in daily_stats]
    revenues = [float(stat['revenue'] or 0) for stat in daily_stats]
    booking_counts = [int(stat['booking_count'] or 0) for stat in daily_stats]
    
    cursor.close()
    
    return render_template('admin/reports.html',
                         date_range=date_range,
                         daily_stats=daily_stats,
                         top_hotels=top_hotels,
                         room_type_stats=room_type_stats,
                         chart_data={
                             'dates': dates,
                             'revenues': revenues,
                             'booking_counts': booking_counts
                         })



# Profile Management
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_profile':
            # Update profile logic
            try:
                first_name = sanitize_input(request.form.get('first_name'))
                last_name = sanitize_input(request.form.get('last_name'))
                phone = sanitize_input(request.form.get('phone'))
                
                cursor = get_db()
                cursor.execute("""
                    UPDATE users 
                    SET first_name = %s, last_name = %s, phone = %s 
                    WHERE user_id = %s
                """, (first_name, last_name, phone, session['user_id']))
                mysql.connection.commit()
                
                # Flash success message
                flash('Profile updated successfully!', 'success')
                
            except Exception as e:
                app.logger.error(f'Profile update error: {str(e)}')
                flash('An error occurred while updating your profile', 'error')
                
        elif action == 'change_password':
            try:
                current_password = request.form.get('current_password')
                new_password = request.form.get('new_password')
                confirm_password = request.form.get('confirm_password')
                
                # Verify passwords match
                if new_password != confirm_password:
                    flash('New passwords do not match', 'error')
                    return redirect(url_for('profile'))
                
                # Get current user
                cursor = get_db()
                cursor.execute('SELECT password_hash FROM users WHERE user_id = %s', 
                             (session['user_id'],))
                user = cursor.fetchone()
                
                # Verify current password
                if not check_password_hash(user['password_hash'], current_password):
                    flash('Current password is incorrect', 'error')
                    return redirect(url_for('profile'))
                
                # Update password
                password_hash = generate_password_hash(new_password)
                cursor.execute('UPDATE users SET password_hash = %s WHERE user_id = %s',
                             (password_hash, session['user_id']))
                mysql.connection.commit()
                
                # Flash success message
                flash('Password changed successfully!', 'success')
                
            except Exception as e:
                app.logger.error(f'Password change error: {str(e)}')
                flash('An error occurred while changing your password', 'error')
    
    # Get user data for display
    cursor = get_db()
    cursor.execute("""
        SELECT u.*, 
               COUNT(DISTINCT b.booking_id) as total_bookings,
               COALESCE(SUM(b.total_price), 0) as total_spent
        FROM users u
        LEFT JOIN bookings b ON u.user_id = b.user_id AND b.status = 'confirmed'
        WHERE u.user_id = %s
        GROUP BY u.user_id
    """, (session['user_id'],))
    user = cursor.fetchone()
    
    return render_template('profile.html', user=user)

# hotels route
@app.route('/hotels')
def hotels():
    cursor = get_db()
    city_filter = request.args.get('city')
    sort_by = request.args.get('sort', 'name')  # Default sort by name

    
    # Base query that always includes price calculation
    query = """
        SELECT h.*, c.city_name,
               MIN(CASE 
                   WHEN MONTH(CURRENT_DATE) IN (4,5,6,7,8,11,12) 
                   THEN r.base_price_peak 
                   ELSE r.base_price_offpeak 
               END) as min_price
        FROM hotels h
        JOIN cities c ON h.city_id = c.city_id
        LEFT JOIN rooms r ON h.hotel_id = r.hotel_id
    """
    
    params = []
    if city_filter:
        query += " WHERE h.city_id = %s"
        params.append(city_filter)
    
    # Always group by hotel
    query += " GROUP BY h.hotel_id, h.hotel_name, h.city_id, h.description, h.address, h.total_rooms, h.star_rating, h.main_image, h.features, h.check_in_time, h.check_out_time, c.city_name"
    
    # Add sorting
    if sort_by == 'price_asc':
        query += " ORDER BY min_price ASC"
    elif sort_by == 'price_desc':
        query += " ORDER BY min_price DESC"
    elif sort_by == 'rating':
        query += " ORDER BY h.star_rating DESC"
    else:  # sort by name
        query += " ORDER BY h.hotel_name"
    
    
    cursor.execute(query, params)
    hotels = cursor.fetchall()
    
    
    # Get cities for filter
    cursor.execute("SELECT * FROM cities ORDER BY city_name")
    cities = cursor.fetchall()
    
    cursor.close()
    return render_template('hotels.html', 
                         hotels=hotels, 
                         cities=cities,
                         selected_city=city_filter,
                         sort_by=sort_by)
    
# hotel detail route
@app.route('/hotels/<int:hotel_id>')
def hotel_detail(hotel_id):
    cursor = get_db()
    
    # Get currency from session or default to GBP
    currency = session.get('currency', 'GBP')
    currency_symbol = CURRENCY_SYMBOLS.get(currency, '£')
    exchange_rate = Decimal(str(EXCHANGE_RATES.get(currency, 1.0)))
    
    # Get hotel details
    cursor.execute("""
        SELECT h.*, c.city_name,
               h.features AS hotel_features
        FROM hotels h
        JOIN cities c ON h.city_id = c.city_id
        WHERE h.hotel_id = %s
    """, (hotel_id,))
    
    hotel = cursor.fetchone()
    if not hotel:
        abort(404)
        
    hotel_features = hotel['hotel_features'].split(',') if hotel['hotel_features'] else []
    
    # Get search parameters
    check_in = request.args.get('check_in', '')
    check_out = request.args.get('check_out', '')
    guests = request.args.get('guests', '1')
    
    rooms = []
    if check_in and check_out:
        # Query available rooms using the same logic as search page
        cursor.execute("""
            SELECT r.*, rt.type_name, rt.max_guests,
                   r.features,
                   r.base_price_peak, r.base_price_offpeak
            FROM rooms r
            JOIN room_types rt ON r.room_type_id = rt.room_type_id
            WHERE r.hotel_id = %s
            AND r.room_id NOT IN (
                SELECT room_id 
                FROM bookings 
                WHERE status = 'confirmed'
                AND check_out_date > %s 
                AND check_in_date < %s
            )
            AND rt.max_guests >= %s
        """, (hotel_id, check_in, check_out, guests))
        
        rooms = cursor.fetchall()
        
        # Calculate prices and discounts
        for room in rooms:
            # Determine if peak season
            check_in_date = datetime.strptime(check_in, '%Y-%m-%d')
            is_peak = check_in_date.month in [4, 5, 6, 7, 8, 11, 12]
            
            # Calculate base price
            base_price = Decimal(str(room['base_price_peak'] if is_peak else room['base_price_offpeak']))
            
            # Calculate discount
            discount = calculate_advance_booking_discount(check_in, base_price)
            
            # Apply currency conversion
            original_price = base_price * exchange_rate
            final_price = (base_price - discount) * exchange_rate
            
            # Add price info to room dict
            room['original_price'] = original_price.quantize(Decimal('0.01'))
            room['final_price'] = final_price.quantize(Decimal('0.01'))
            room['discount_amount'] = (discount * exchange_rate).quantize(Decimal('0.01'))
    
    # Add this section to fetch reviews
    cursor.execute("""
        SELECT r.*, u.first_name, u.last_name
        FROM reviews r
        JOIN users u ON r.user_id = u.user_id
        WHERE r.hotel_id = %s AND r.is_verified = TRUE
        ORDER BY r.review_date DESC
    """, (hotel_id,))
    reviews = cursor.fetchall()
    
    cursor.close()
    
    return render_template('hotel_detail.html',
                         hotel=hotel,
                         features=hotel_features,
                         rooms=rooms,
                         reviews=reviews,
                         check_in=check_in,
                         check_out=check_out,
                         guests=guests,
                         currency=currency,
                         currency_symbol=currency_symbol,
                         currencies=CURRENCY_SYMBOLS,
                         feature_icons=FEATURE_ICONS, 
                         today=datetime.now().date())

# mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'khadkaridesha@gmail.com'  
app.config['MAIL_PASSWORD'] = 'bknk ktea asac pkyz' 
app.config['MAIL_DEFAULT_SENDER'] = 'khadkaridesha@gmail.com'

mail = Mail(app)
#serializer
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Helper functions for token generation and verification
def generate_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='password-reset-salt')

# verify reset token
def verify_reset_token(token):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)  # 1 hour expiry
        return email
    except:
        return None
    return serializer.dumps(email, salt=salt)

# verify token
def verify_token(token, salt='email-confirm', expiration=3600):
    try:
        email = serializer.loads(token, salt=salt, max_age=expiration)
        return email
    except (SignatureExpired, BadSignature):
        return None

# set remember token
def set_remember_token(user_id):
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(days=30)
    
    cursor = get_db()
    cursor.execute("""
        UPDATE users 
        SET remember_token = %s, remember_token_expires_at = %s 
        WHERE user_id = %s
    """, (token, expires_at, user_id))
    mysql.connection.commit()
    cursor.close()
    
    return token

# forgot password route
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if request.method == 'POST' and form.validate_on_submit():
        try:
            email = sanitize_input(form.email.data)
            app.logger.info(f"Processing reset request for: {email}")
            
            cursor = get_db()
            cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
            user = cursor.fetchone()
            
            if user:
                # Generate token and create reset URL
                token = secrets.token_urlsafe(32)
                expires_at = datetime.now() + timedelta(hours=1)
                reset_url = url_for('reset_password', token=token, _external=True)
                
                try:
                    # Store token in database
                    cursor.execute("""
                        INSERT INTO password_reset_tokens (user_id, token, expires_at)
                        VALUES (%s, %s, %s)
                    """, (user['user_id'], token, expires_at))
                    mysql.connection.commit()
                    
                    # Create and send email
                    msg = Message(
                        'Reset Your World Hotels Password',
                        recipients=[email]
                    )
                    
                    msg.html = f'''
                    <h2>Password Reset Request</h2>
                    <p>Hello,</p>
                    <p>You have requested to reset your password for your World Hotels account.</p>
                    <p>Please click the link below to reset your password:</p>
                    <p><a href="{reset_url}" style="padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;">Reset Password</a></p>
                    <p>Or copy and paste this URL into your browser:</p>
                    <p>{reset_url}</p>
                    <p>This link will expire in 1 hour.</p>
                    <p>If you did not request this password reset, please ignore this email.</p>
                    <p>Best regards,<br>World Hotels Team</p>
                    '''
                    
                    # Send email directly (not async for testing)
                    mail.send(msg)
                    app.logger.info(f"Reset email sent to: {email}")
                    
                except Exception as e:
                    app.logger.error(f"Error in reset process: {str(e)}")
                    mysql.connection.rollback()
                    raise
            
            # Always show this message
            flash('If an account exists with that email, you will receive reset instructions.', 'info')
            return redirect(url_for('login'))
            
        except Exception as e:
            app.logger.error(f"Password reset error: {str(e)}")
            flash('An error occurred. Please try again later.', 'error')
            
    return render_template('forgot_password.html', form=form)

# reset password route
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'POST':
        cursor = get_db()
        cursor.execute("""
            SELECT * FROM password_reset_tokens 
            WHERE token = %s AND used = FALSE AND expires_at > NOW()
        """, (token,))
        token_data = cursor.fetchone()
        
        if not token_data:
            flash('Invalid or expired reset token.', 'error')
            return redirect(url_for('login'))
            
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html', token=token)
            
        # Validate password strength
        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message, 'error')
            return render_template('reset_password.html', token=token)
            
        # Update password and mark token as used
        password_hash = generate_password_hash(password)
        cursor.execute('UPDATE users SET password_hash = %s WHERE user_id = %s',
                      (password_hash, token_data['user_id']))
        cursor.execute('UPDATE password_reset_tokens SET used = TRUE WHERE id = %s',
                      (token_data['id'],))
        mysql.connection.commit()
        
        flash('Your password has been updated successfully.', 'success')
        return redirect(url_for('login'))
        
    # Verify token on GET request
    cursor = get_db()
    cursor.execute("""
        SELECT * FROM password_reset_tokens 
        WHERE token = %s AND used = FALSE AND expires_at > NOW()
    """, (token,))
    token_data = cursor.fetchone()
    
    if not token_data:
        flash('Invalid or expired reset token.', 'error')
        return redirect(url_for('login'))
        
    return render_template('reset_password.html', token=token)

# about us route
@app.route('/aboutus')
def aboutus():
    return render_template('aboutus.html')

# privacy policy route
@app.route('/privacypolicy')
def privacypolicy():
    return render_template('privacypolicy.html')

@app.route('/terms-and-conditions')
def terms_and_conditions():
    return render_template('terms_and_conditions.html')

# mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'khadkaridesha@gmail.com'
app.config['MAIL_PASSWORD'] = 'bknk ktea asac pkyz'
app.config['MAIL_DEFAULT_SENDER'] = ('World Hotels', 'khadkaridesha@gmail.com')

# Initialize Flask-Mail
mail = Mail(app)

# Initialize CSRF protection
csrf = CSRFProtect(app)

def send_async_email(app, msg):
    with app.app_context():
        try:
            mail.send(msg)
            app.logger.info(f"Email sent successfully to: {msg.recipients}")
        except Exception as e:
            app.logger.error(f"Failed to send email: {str(e)}")
            raise

# send email with thread
def send_email_with_thread(msg):
    try:
        thread = Thread(target=send_async_email, args=(app, msg))
        thread.start()
        return True
    except Exception as e:
        app.logger.error(f"Failed to start email thread: {str(e)}")
        return False
    
# contact route
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    cursor = None
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("""
            SELECT * FROM faqs 
            WHERE is_active = TRUE 
            ORDER BY display_order, created_at DESC
        """)
        faqs = cursor.fetchall()
        
        if request.method == 'POST':
            try:
                name = request.form.get('name')
                email = request.form.get('email')
                subject = request.form.get('subject')
                message = request.form.get('message')
                
                if not all([name, email, subject, message]):
                    flash('All fields are required', 'danger')
                    return jsonify({
                        'status': 'error',
                        'message': 'All fields are required'
                    }), 400
                
                try:
                    # Main notification email
                    msg = Message(
                        subject=f'Contact Form: {subject}',
                        recipients=['khadkaridesha@gmail.com'],
                        body=f"""
                        Name: {name}
                        Email: {email}
                        Subject: {subject}
                        Message: {message}
                        """
                    )
                    # Send admin notification asynchronously
                    send_email_with_thread(msg)
                    
                    # Confirmation email to user
                    confirm_msg = Message(
                        subject='Thank you for contacting World Hotels',
                        recipients=[email],
                        body=f"""
                        Dear {name},
                        
                        Thank you for contacting World Hotels. We have received your message and will get back to you shortly.
                        
                        Your message details:
                        Subject: {subject}
                        Message: {message}
                        
                        Best regards,
                        World Hotels Team
                        """
                    )
                    # Send user confirmation asynchronously
                    send_email_with_thread(confirm_msg)
                    
                    # Add success flash message
                    flash('Your message has been sent successfully! We will get back to you soon.', 'success')
                    
                    return jsonify({
                        'status': 'success',
                        'message': 'Your message has been sent successfully!'
                    })
                    
                except Exception as e:
                    app.logger.error(f'Mail sending error: {str(e)}')
                    flash('Error sending email. Please try again later.', 'danger')
                    return jsonify({
                        'status': 'error',
                        'message': 'Error sending email. Please try again later.'
                    }), 500
                    
            except Exception as e:
                app.logger.error(f'Contact form error: {str(e)}')
                flash('An error occurred. Please try again.', 'danger')
                return jsonify({
                        'status': 'error',
                        'message': 'An error occurred. Please try again.'
                    }), 500
                
        return render_template('contact.html', faqs=faqs)
    
    except Exception as e:
        app.logger.error(f'Error loading contact page: {str(e)}')
        flash('Error loading page. Please try again.', 'danger')
        return render_template('contact.html', faqs=[])
    
    finally:
        if cursor:
            cursor.close()

# submit review route
@app.route('/submit-review/<int:hotel_id>', methods=['POST'])
@login_required
def submit_review(hotel_id):
    try:
        rating = int(request.form.get('rating'))
        comment = request.form.get('comment')
        
        if not rating or not comment:
            flash('Please provide both rating and comment', 'error')
            return redirect(url_for('hotel_detail', hotel_id=hotel_id))
        
        cursor = get_db()
        
        # First, get a valid booking for this user and hotel
        cursor.execute("""
            SELECT b.booking_id 
            FROM bookings b 
            JOIN rooms r ON b.room_id = r.room_id 
            WHERE r.hotel_id = %s AND b.user_id = %s
            AND b.status = 'completed'
            LIMIT 1
        """, (hotel_id, session['user_id']))
        
        booking = cursor.fetchone()
        
        if not booking:
            # If no completed booking found, create a temporary booking for the review
            cursor.execute("""
                SELECT room_id FROM rooms 
                WHERE hotel_id = %s 
                LIMIT 1
            """, (hotel_id,))
            room = cursor.fetchone()
            
            if not room:
                flash('Invalid hotel', 'error')
                return redirect(url_for('hotel_detail', hotel_id=hotel_id))
            
            # Insert a temporary booking
            cursor.execute("""
                INSERT INTO bookings (user_id, room_id, check_in_date, check_out_date, 
                                    num_guests, total_price, status)
                VALUES (%s, %s, CURDATE(), CURDATE(), 1, 0, 'completed')
            """, (session['user_id'], room['room_id']))
            mysql.connection.commit()
            booking_id = cursor.lastrowid
        else:
            booking_id = booking['booking_id']
        
        # Insert the review
        cursor.execute("""
            INSERT INTO reviews (booking_id, user_id, hotel_id, rating, comment, is_verified)
            VALUES (%s, %s, %s, %s, %s, TRUE)
        """, (booking_id, session['user_id'], hotel_id, rating, comment))
        mysql.connection.commit()
        
        flash('Thank you for your review!', 'success')
        
        # If the request is AJAX, return JSON response
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': True, 'message': 'Review submitted successfully'})
            
        return redirect(url_for('hotel_detail', hotel_id=hotel_id))
        
    except Exception as e:
        app.logger.error(f'Review submission error: {str(e)}')
        flash('An error occurred while submitting your review', 'error')
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': 'Error submitting review'})
            
        return redirect(url_for('hotel_detail', hotel_id=hotel_id))

# wkhtmltopdf configuration
import platform

if platform.system() == 'Windows':
    WKHTMLTOPDF_PATH = r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe'
else:
    # Linux path
    WKHTMLTOPDF_PATH = '/usr/bin/wkhtmltopdf'

config = pdfkit.configuration(wkhtmltopdf=WKHTMLTOPDF_PATH)

#download receipt route
@app.route('/download_receipt/<int:booking_id>')
@login_required
def download_receipt(booking_id):
    cursor = get_db()
    
    # Get currency from session or default to GBP
    currency = session.get('currency', 'GBP')
    currency_symbol = CURRENCY_SYMBOLS.get(currency, '£')
    
    # Get booking details
    cursor.execute("""
        SELECT b.*, h.hotel_name, rt.type_name
        FROM bookings b
        JOIN rooms r ON b.room_id = r.room_id
        JOIN hotels h ON r.hotel_id = h.hotel_id
        JOIN room_types rt ON r.room_type_id = rt.room_type_id
        WHERE b.booking_id = %s AND b.user_id = %s
    """, (booking_id, session['user_id']))
    
    booking = cursor.fetchone()
    cursor.close()
    
    if not booking:
        flash('Booking not found', 'error')
        return redirect(url_for('my_bookings'))

    try:
        # Create a temporary file
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as temp_file:
            pdf_path = temp_file.name

        html_content = render_template('receipt_pdf.html',
                                     booking=booking,
                                     currency_symbol=currency_symbol)

        # Configure PDF options
        options = {
            'page-size': 'A4',
            'margin-top': '0.75in',
            'margin-right': '0.75in',
            'margin-bottom': '0.75in',
            'margin-left': '0.75in',
            'encoding': "UTF-8",
            'no-outline': None,
            'enable-local-file-access': None
        }

        # Generate PDF
        pdfkit.from_string(html_content, pdf_path, options=options, configuration=config)

        try:
            return send_file(
                pdf_path,
                download_name=f'booking_receipt_{booking_id}.pdf',
                as_attachment=True,
                mimetype='application/pdf'
            )
        finally:
            # Clean up the temporary file after sending
            try:
                os.unlink(pdf_path)
            except:
                pass  # Ignore if file is still in use

    except Exception as e:
        app.logger.error(f'PDF generation error: {str(e)}')
        flash('Error generating PDF receipt. Please try again later.', 'error')
        return redirect(url_for('booking_confirmation', booking_id=booking_id))

# admin edit review route
@app.route('/admin/review/<int:review_id>/edit', methods=['POST'])
@admin_required
def admin_edit_review(review_id):
    try:
        rating = request.form.get('rating')
        comment = request.form.get('comment')
        
        if not rating or not comment:
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
            
        cursor = get_db()
        cursor.execute("""
            UPDATE reviews 
            SET rating = %s, comment = %s 
            WHERE review_id = %s
        """, (rating, comment, review_id))
        mysql.connection.commit()
        cursor.close()
        
        return jsonify({'success': True})
    except Exception as e:
        app.logger.error(f'Error editing review: {str(e)}')
        return jsonify({'success': False, 'message': str(e)}), 500

# admin verify review route
@app.route('/admin/review/<int:review_id>/verify', methods=['POST'])
@admin_required
def admin_verify_review(review_id):
    try:
        verified = request.form.get('verified') == 'true'
        
        cursor = get_db()
        cursor.execute("""
            UPDATE reviews 
            SET is_verified = %s 
            WHERE review_id = %s
        """, (verified, review_id))
        mysql.connection.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        app.logger.error(f'Error verifying review: {str(e)}')
        return jsonify({'success': False, 'error': str(e)})

# admin delete review route
@app.route('/admin/review/<int:review_id>/delete', methods=['POST'])
@admin_required
def admin_delete_review(review_id):
    try:
        cursor = get_db()
        cursor.execute('DELETE FROM reviews WHERE review_id = %s', (review_id,))
        mysql.connection.commit()
        cursor.close()
        
        return jsonify({'success': True})
    except Exception as e:
        app.logger.error(f'Error deleting review: {str(e)}')
        return jsonify({'success': False, 'message': str(e)}), 500

# admin view review route
@app.route('/admin/review/<int:review_id>/view', methods=['GET'])
@admin_required
def admin_view_review(review_id):
    try:
        cursor = get_db()
        cursor.execute("""
            SELECT r.*, u.first_name, u.last_name
            FROM reviews r
            JOIN users u ON r.user_id = u.user_id
            WHERE r.review_id = %s
        """, (review_id,))
        review = cursor.fetchone()
        cursor.close()
        
        if not review:
            return jsonify({'success': False, 'message': 'Review not found'}), 404
            
        return jsonify({
            'success': True,
            'review': {
                'guest': f"{review['first_name']} {review['last_name']}",
                'rating': review['rating'],
                'comment': review['comment'],
                'date': review['review_date'].strftime('%Y-%m-%d')
            }
        })
    except Exception as e:
        app.logger.error(f'Error viewing review: {str(e)}')
        return jsonify({'success': False, 'message': str(e)}), 500
    
#admin special request route
@app.route('/admin/special-requests')
@admin_required
def admin_special_requests():
    cursor = None
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        form = SpecialRequestForm()  # Initialize the form
        
        # Get filter parameters from request object
        status = request.args.get('status', '')
        hotel_id = request.args.get('hotel_id', '')
        
        # Base query
        query = """
            SELECT 
                b.booking_id,
                b.check_in_date,
                b.check_out_date,
                b.guest_name,
                b.guest_email,
                b.special_requests,
                COALESCE(b.special_request_status, 'pending') as special_request_status,
                b.special_request_notes,
                b.special_request_handled_at,
                h.hotel_name,
                r.room_number,
                rt.type_name
            FROM bookings b
            JOIN rooms r ON b.room_id = r.room_id
            JOIN hotels h ON r.hotel_id = h.hotel_id
            JOIN room_types rt ON r.room_type_id = rt.room_type_id
            WHERE b.special_requests IS NOT NULL 
            AND b.special_requests != ''
        """
        params = []
        
        if status:
            query += " AND b.special_request_status = %s"
            params.append(status)
        if hotel_id:
            query += " AND h.hotel_id = %s"
            params.append(hotel_id)
        
        query += " ORDER BY b.check_in_date ASC"
        
        cursor.execute(query, params)
        special_requests = cursor.fetchall()
        
        # Get hotels for filter
        cursor.execute("SELECT hotel_id, hotel_name FROM hotels ORDER BY hotel_name")
        hotels = cursor.fetchall()
        
        # Convert datetime objects to string format
        for req in special_requests:
            if req['check_in_date']:
                req['check_in_date'] = req['check_in_date'].strftime('%Y-%m-%d')
            if req['check_out_date']:
                req['check_out_date'] = req['check_out_date'].strftime('%Y-%m-%d')
            if req['special_request_handled_at']:
                req['special_request_handled_at'] = req['special_request_handled_at'].strftime('%Y-%m-%d %H:%M:%S')
        
        return render_template('admin/special_requests.html',
                             form=form,  # Pass the form to the template
                             special_requests=special_requests,
                             hotels=hotels,
                             selected_status=status,
                             selected_hotel=hotel_id,
                             date_from=request.args.get('date_from', ''),
                             date_to=request.args.get('date_to', ''))
                             
    except Exception as e:
        app.logger.error(f"Error in admin_special_requests: {str(e)}", exc_info=True)
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))
    finally:
        if cursor:
            cursor.close()
            
#admin get special request route
@app.route('/admin/special-requests/get/<int:booking_id>')
@admin_required
def get_special_request(booking_id):
    cursor = get_db()
    cursor.execute("""
        SELECT special_request_status, special_request_notes
        FROM bookings
        WHERE booking_id = %s
    """, (booking_id,))
    request_data = cursor.fetchone()
    
    return jsonify({
        'status': request_data['special_request_status'] if request_data else 'pending',
        'notes': request_data['special_request_notes'] if request_data else ''
    })

#admin handle special request route
@app.route('/admin/special-requests/<int:booking_id>', methods=['POST'])
@admin_required
def handle_special_request(booking_id):
    try:
        status = request.form.get('status')
        notes = request.form.get('notes')
        
        if not status:
            flash('Status is required', 'error')
            return redirect(url_for('admin_special_requests'))
        
        cursor = get_db()
        cursor.execute("""
            UPDATE bookings 
            SET special_request_status = %s,
                special_request_notes = %s,
                special_request_handled_at = NOW()
            WHERE booking_id = %s
        """, (status, notes, booking_id))
        mysql.connection.commit()
        
        flash('Special request updated successfully', 'success')
        return redirect(url_for('admin_special_requests'))
        
    except Exception as e:
        app.logger.error(f'Error updating special request: {str(e)}')
        flash('Error updating special request', 'error')
        return redirect(url_for('admin_special_requests'))

#admin view special request route
@app.route('/admin/special-requests/<int:booking_id>/view')
@admin_required
def view_special_request(booking_id):
    try:
        cursor = get_db()
        cursor.execute("""
            SELECT b.*, h.hotel_name, r.room_number
            FROM bookings b
            JOIN rooms r ON b.room_id = r.room_id
            JOIN hotels h ON r.hotel_id = h.hotel_id
            WHERE b.booking_id = %s
        """, (booking_id,))
        request = cursor.fetchone()
        
        if not request:
            return jsonify({'success': False, 'message': 'Request not found'})
            
        # Format dates for JSON response
        request['check_in_date'] = request['check_in_date'].strftime('%Y-%m-%d')
        request['check_out_date'] = request['check_out_date'].strftime('%Y-%m-%d')
        
        return jsonify({
            'success': True,
            'request': {
                'booking_id': request['booking_id'],
                'guest_name': request['guest_name'],
                'guest_email': request['guest_email'],
                'check_in_date': request['check_in_date'],
                'check_out_date': request['check_out_date'],
                'special_requests': request['special_requests'],
                'status': request['special_request_status'],
                'notes': request['special_request_notes'],
                'hotel_name': request['hotel_name'],
                'room_number': request['room_number']
            }
        })
    except Exception as e:
        app.logger.error(f"Error viewing special request: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})

#admin delete special request route
@app.route('/admin/special-requests/<int:booking_id>/delete', methods=['POST'])
@admin_required
def delete_special_request(booking_id):
    try:
        cursor = get_db()
        # Instead of actually deleting, maybe just mark as cancelled
        cursor.execute("""
            UPDATE bookings 
            SET special_request_status = 'cancelled',
                special_request_notes = CONCAT(COALESCE(special_request_notes, ''), '\nCancelled by admin on ', NOW())
            WHERE booking_id = %s
        """, (booking_id,))
        mysql.connection.commit()
        return jsonify({'success': True})
    except Exception as e:
        app.logger.error(f"Error deleting special request: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})

#admin pending requests count route
@app.context_processor
def utility_processor():
    def get_pending_requests_count():
        try:
            cursor = get_db()
            cursor.execute("""
                SELECT COUNT(*) as count 
                FROM bookings 
                WHERE special_requests IS NOT NULL 
                AND special_requests != '' 
                AND (special_request_status IS NULL OR special_request_status = 'pending')
            """)
            result = cursor.fetchone()
            return result['count'] if result else 0
        except Exception as e:
            app.logger.error(f'Error getting pending requests count: {str(e)}')
            return 0
            
    return dict(pending_requests_count=get_pending_requests_count())
    
# admin reports route
@app.route('/admin/reports/export-pdf')
@admin_required
def export_reports_pdf():
    try:
        date_range = request.args.get('range', '30')
        end_date = datetime.now()
        start_date = end_date - timedelta(days=int(date_range))
        
        cursor = get_db()
        
        # Fetch daily stats
        cursor.execute("""
            SELECT 
                DATE(booking_date) as date,
                COUNT(*) as booking_count,
                COALESCE(SUM(total_price), 0) as revenue
            FROM bookings
            WHERE booking_date BETWEEN %s AND %s
            AND status IN ('confirmed', 'completed')
            GROUP BY DATE(booking_date)
            ORDER BY date
        """, (start_date, end_date))
        daily_stats = cursor.fetchall()
        
        # Fetch top hotels
        cursor.execute("""
            SELECT 
                h.hotel_name,
                COUNT(b.booking_id) as booking_count,
                COALESCE(SUM(b.total_price), 0) as revenue
            FROM hotels h
            JOIN rooms r ON h.hotel_id = r.hotel_id
            JOIN bookings b ON r.room_id = b.room_id
            WHERE b.booking_date BETWEEN %s AND %s
            AND b.status IN ('confirmed', 'completed')
            GROUP BY h.hotel_id, h.hotel_name
            ORDER BY revenue DESC
            LIMIT 5
        """, (start_date, end_date))
        top_hotels = cursor.fetchall()

        # Create a temporary file
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as temp_pdf:
            temp_path = temp_pdf.name

        # Generate HTML content
        html = render_template('admin/reports_pdf.html',
                             daily_stats=daily_stats,
                             top_hotels=top_hotels,
                             start_date=start_date,
                             end_date=end_date)

        # PDF options
        options = {
            'page-size': 'A4',
            'margin-top': '20mm',
            'margin-right': '20mm',
            'margin-bottom': '20mm',
            'margin-left': '20mm',
            'encoding': "UTF-8",
            'no-outline': None,
            'enable-local-file-access': None
        }

        # Generate PDF
        pdfkit.from_string(html, temp_path, options=options, configuration=config)

        @after_this_request
        def cleanup(response):
            try:
                os.remove(temp_path)
            except Exception as e:
                app.logger.error(f"Error removing temporary file: {e}")
            return response

        return send_file(
            temp_path,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'hotel_reports_{datetime.now().strftime("%Y%m%d")}.pdf'
        )

    except Exception as e:
        app.logger.error(f'PDF export error: {str(e)}')
        return jsonify({'error': 'Failed to generate PDF report'}), 500

# admin export excel route
@app.route('/admin/reports/export-excel')
@admin_required
def export_reports_excel():
    try:
        date_range = request.args.get('range', '30')
        end_date = datetime.now()
        start_date = end_date - timedelta(days=int(date_range))
        
        cursor = get_db()
        
        # Fetch daily stats
        cursor.execute("""
            SELECT 
                DATE(booking_date) as date,
                COUNT(*) as booking_count,
                COALESCE(SUM(total_price), 0) as revenue
            FROM bookings
            WHERE booking_date BETWEEN %s AND %s
            AND status IN ('confirmed', 'completed')
            GROUP BY DATE(booking_date)
            ORDER BY date
        """, (start_date, end_date))
        daily_stats = cursor.fetchall()
        
        # Convert daily_stats to list of dicts for pandas
        daily_data = [{
            'Date': row['date'],
            'Bookings': row['booking_count'],
            'Revenue': float(row['revenue'])
        } for row in daily_stats]
        
        # Fetch top hotels
        cursor.execute("""
            SELECT 
                h.hotel_name,
                COUNT(b.booking_id) as booking_count,
                COALESCE(SUM(b.total_price), 0) as revenue
            FROM hotels h
            JOIN rooms r ON h.hotel_id = r.hotel_id
            JOIN bookings b ON r.room_id = b.room_id
            WHERE b.booking_date BETWEEN %s AND %s
            AND b.status IN ('confirmed', 'completed')
            GROUP BY h.hotel_id, h.hotel_name
            ORDER BY revenue DESC
            LIMIT 10
        """, (start_date, end_date))
        top_hotels = cursor.fetchall()
        
        # Convert top_hotels to list of dicts for pandas
        hotels_data = [{
            'Hotel': row['hotel_name'],
            'Bookings': row['booking_count'],
            'Revenue': float(row['revenue'])
        } for row in top_hotels]

        # Create DataFrames
        daily_df = pd.DataFrame(daily_data)
        hotels_df = pd.DataFrame(hotels_data)

        # Create Excel file in memory
        output = io.BytesIO()
        
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            # Write sheets
            daily_df.to_excel(writer, sheet_name='Daily Statistics', index=False)
            hotels_df.to_excel(writer, sheet_name='Top Hotels', index=False)
            
            # Get workbook and worksheet objects
            workbook = writer.book
            
            # Add formats
            currency_format = workbook.add_format({'num_format': '£#,##0.00'})
            date_format = workbook.add_format({'num_format': 'yyyy-mm-dd'})
            header_format = workbook.add_format({
                'bold': True,
                'bg_color': '#4e73df',
                'font_color': 'white'
            })
            
            # Format Daily Statistics sheet
            worksheet1 = writer.sheets['Daily Statistics']
            worksheet1.set_column('A:A', 15, date_format)
            worksheet1.set_column('B:B', 12)
            worksheet1.set_column('C:C', 15, currency_format)
            
            # Write headers with format
            for col_num, value in enumerate(['Date', 'Bookings', 'Revenue']):
                worksheet1.write(0, col_num, value, header_format)
            
            # Format Top Hotels sheet
            worksheet2 = writer.sheets['Top Hotels']
            worksheet2.set_column('A:A', 30)
            worksheet2.set_column('B:B', 12)
            worksheet2.set_column('C:C', 15, currency_format)
            
            # Write headers with format
            for col_num, value in enumerate(['Hotel', 'Bookings', 'Revenue']):
                worksheet2.write(0, col_num, value, header_format)

        # Prepare the output
        output.seek(0)
        
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=f'hotel_reports_{datetime.now().strftime("%Y%m%d")}.xlsx'
        )

    except Exception as e:
        app.logger.error(f'Excel export error: {str(e)}')
        return jsonify({'error': 'Failed to generate Excel report'}), 500

# admin delete user route
@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    cursor = get_db()
    try:
        # Check if trying to delete self
        if user_id == session['user_id']:
            flash('You cannot delete your own account.', 'error')
            return redirect(url_for('admin_user_detail', user_id=user_id))
        
        # Check if this is the last admin
        cursor.execute("""
            SELECT user_type 
            FROM users 
            WHERE user_id = %s
        """, (user_id,))
        user = cursor.fetchone()
        
        if user['user_type'] == 'admin':
            cursor.execute("SELECT COUNT(*) as admin_count FROM users WHERE user_type = 'admin'")
            admin_count = cursor.fetchone()['admin_count']
            
            if admin_count <= 1:
                flash('Cannot delete the last admin account.', 'error')
                return redirect(url_for('admin_users'))
        
        # Begin transaction
        cursor.execute("START TRANSACTION")
        
        # Delete related records first (due to foreign key constraints)
        # Delete reviews
        cursor.execute("DELETE FROM reviews WHERE user_id = %s", (user_id,))
        
        # Delete bookings
        cursor.execute("DELETE FROM bookings WHERE user_id = %s", (user_id,))
        
        # Delete password reset tokens
        cursor.execute("DELETE FROM password_reset_tokens WHERE user_id = %s", (user_id,))
        
        # Finally, delete the user
        cursor.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
        
        # Commit the transaction
        mysql.connection.commit()
        
        flash('User account has been successfully deleted.', 'success')
        return redirect(url_for('admin_users'))
        
    except Exception as e:
        mysql.connection.rollback()
        app.logger.error(f'Error deleting user: {str(e)}')
        flash(f'Error deleting user: {str(e)}', 'error')
        return redirect(url_for('admin_user_detail', user_id=user_id))
        
    finally:
        cursor.close()

# admin view user route
@app.route('/admin/users/<int:user_id>/view')
@admin_required
def admin_view_user(user_id):
    cursor = get_db()
    try:
        # Get user details
        cursor.execute("""
            SELECT u.*,
                   u.created_at as registration_date,
                   COUNT(DISTINCT b.booking_id) as total_bookings,
                   COALESCE(SUM(
                       CASE 
                           WHEN b.status = 'confirmed' OR b.status = 'completed' 
                           THEN b.total_price 
                           ELSE 0 
                       END
                   ), 0) as total_spent,
                   MAX(b.booking_date) as last_booking_date,
                   COALESCE(u.is_active, TRUE) as is_active
            FROM users u
            LEFT JOIN bookings b ON u.user_id = b.user_id
            WHERE u.user_id = %s
            GROUP BY u.user_id
        """, (user_id,))
        user = cursor.fetchone()
        
        if not user:
            flash('User not found.', 'error')
            return redirect(url_for('admin_users'))
        
        # Get user's bookings
        cursor.execute("""
            SELECT b.*, 
                   h.hotel_name, 
                   r.room_number,
                   h.hotel_id
            FROM bookings b
            JOIN rooms r ON b.room_id = r.room_id
            JOIN hotels h ON r.hotel_id = h.hotel_id
            WHERE b.user_id = %s
            ORDER BY b.booking_date DESC
        """, (user_id,))
        bookings = cursor.fetchall()
        
        return render_template('admin/view_user.html',
                             user=user,
                             bookings=bookings)
                             
    except Exception as e:
        app.logger.error(f'Error viewing user: {str(e)}')
        flash('Error viewing user details.', 'error')
        return redirect(url_for('admin_users'))
        
    finally:
        cursor.close()

# test email route
@app.route('/test-email')
def test_email():
    try:
        msg = Message(
            'Test Email from World Hotels',
            recipients=['khadkaridesha@gmail.com'],
            body='This is a test email.'
        )
        mail.send(msg)
        return 'Test email sent! Check your inbox and spam folder.'
    except Exception as e:
        return f'Error sending email: {str(e)}'

#admin faqs route
@app.route('/admin/faqs', methods=['GET'])
@admin_required
def admin_faqs():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        cursor.execute("SELECT * FROM faqs ORDER BY display_order, created_at DESC")
        faqs = cursor.fetchall()
        return render_template('admin/faqs.html', faqs=faqs)
    finally:
        cursor.close()

#admin add faq route
@app.route('/admin/faqs/add', methods=['POST'])
@admin_required
def add_faq():
    cursor = mysql.connection.cursor()
    try:
        question = request.form.get('question')
        answer = request.form.get('answer')
        display_order = request.form.get('display_order', 0)
        
        cursor.execute("""
            INSERT INTO faqs (question, answer, display_order)
            VALUES (%s, %s, %s)
        """, (question, answer, display_order))
        mysql.connection.commit()
        
        flash('FAQ added successfully!', 'success')
    except Exception as e:
        flash('Error adding FAQ.', 'error')
    finally:
        cursor.close()
    return redirect(url_for('admin_faqs'))

#admin edit faq route
@app.route('/admin/faqs/edit/<int:faq_id>', methods=['POST'])
@admin_required
def edit_faq(faq_id):
    cursor = mysql.connection.cursor()
    try:
        question = request.form.get('question')
        answer = request.form.get('answer')
        display_order = request.form.get('display_order', 0)
        
        cursor.execute("""
            UPDATE faqs 
            SET question = %s, answer = %s, display_order = %s
            WHERE id = %s
        """, (question, answer, display_order, faq_id))
        mysql.connection.commit()
        
        flash('FAQ updated successfully!', 'success')
    except Exception as e:
        flash('Error updating FAQ.', 'error')
    finally:
        cursor.close()
    return redirect(url_for('admin_faqs'))

#admin delete faq route
@app.route('/admin/faqs/delete/<int:faq_id>', methods=['POST'])
@admin_required
def delete_faq(faq_id):
    cursor = mysql.connection.cursor()
    try:
        cursor.execute("DELETE FROM faqs WHERE id = %s", (faq_id,))
        mysql.connection.commit()
        flash('FAQ deleted successfully!', 'success')
    except Exception as e:
        flash('Error deleting FAQ.', 'error')
    finally:
        cursor.close()
    return redirect(url_for('admin_faqs'))

#submit faq suggestion route
@app.route('/submit-faq-suggestion', methods=['POST'])
@login_required
def submit_faq_suggestion():
    cursor = mysql.connection.cursor()
    try:
        question = request.form.get('question')
        user_id = session.get('user_id')  # Changed from session['id'] to session.get('user_id')
        
        if not question or not user_id:
            flash('Please provide a question and ensure you are logged in.', 'error')
            return redirect(url_for('contact'))
            
        cursor.execute("""
            INSERT INTO faq_suggestions (question, user_id)
            VALUES (%s, %s)
        """, (question, user_id))
        mysql.connection.commit()
        
        flash('Thank you! Your question has been submitted for review.', 'success')
    except Exception as e:
        app.logger.error(f'Error submitting FAQ suggestion: {str(e)}')  # Add logging
        flash('Error submitting question. Please try again.', 'error')
    finally:
        cursor.close()
    return redirect(url_for('contact'))

#admin faq suggestions route
@app.route('/admin/faq-suggestions')
@admin_required
def admin_faq_suggestions():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        cursor.execute("""
            SELECT fs.*, u.first_name, u.last_name
            FROM faq_suggestions fs
            LEFT JOIN users u ON fs.user_id = u.user_id
            WHERE fs.status = 'pending'
            ORDER BY fs.created_at DESC
        """)
        suggestions = cursor.fetchall()
        
        # Add username to each suggestion
        for suggestion in suggestions:
            suggestion['username'] = f"{suggestion['first_name']} {suggestion['last_name']}"
            
        return render_template('admin/faq_suggestions.html', suggestions=suggestions)
    except Exception as e:
        app.logger.error(f'Error loading FAQ suggestions: {str(e)}')  # Add logging
        flash('Error loading FAQ suggestions.', 'error')
        return redirect(url_for('admin_dashboard'))
    finally:
        cursor.close()

#admin approve faq suggestion route
@app.route('/admin/faq-suggestions/<int:suggestion_id>/approve', methods=['POST'])
@admin_required
def approve_faq_suggestion(suggestion_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        # Get the suggestion
        cursor.execute("SELECT * FROM faq_suggestions WHERE id = %s", (suggestion_id,))
        suggestion = cursor.fetchone()
        
        if suggestion:
            # Add to FAQs
            answer = request.form.get('answer')
            cursor.execute("""
                INSERT INTO faqs (question, answer, submitted_by)
                VALUES (%s, %s, %s)
            """, (suggestion['question'], answer, suggestion['user_id']))
            
            # Update suggestion status
            cursor.execute("""
                UPDATE faq_suggestions 
                SET status = 'approved'
                WHERE id = %s
            """, (suggestion_id,))
            
            mysql.connection.commit()
            flash('FAQ suggestion approved and added to FAQs.', 'success')
        else:
            flash('Suggestion not found.', 'error')
            
    except Exception as e:
        flash('Error approving suggestion.', 'error')
    finally:
        cursor.close()
    return redirect(url_for('admin_faq_suggestions'))

#admin reject faq suggestion route
@app.route('/admin/faq-suggestions/<int:suggestion_id>/reject', methods=['POST'])
@admin_required
def reject_faq_suggestion(suggestion_id):
    cursor = mysql.connection.cursor()
    try:
        cursor.execute("""
            UPDATE faq_suggestions 
            SET status = 'rejected'
            WHERE id = %s
        """, (suggestion_id,))
        mysql.connection.commit()
        flash('FAQ suggestion rejected.', 'success')
    except Exception as e:
        flash('Error rejecting suggestion.', 'error')
    finally:
        cursor.close()
    return redirect(url_for('admin_faq_suggestions'))

#generate token
def generate_token(email):
    """Generate a secure token for email unsubscribe"""
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='unsubscribe-salt')

#verify token
def verify_token(token, max_age=604800):  # 7 days in seconds
    """Verify the unsubscribe token"""
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='unsubscribe-salt', max_age=max_age)
        return email
    except SignatureExpired:
        app.logger.warning('Expired unsubscribe token attempted')
        return None
    except BadSignature:
        app.logger.warning('Invalid unsubscribe token attempted')
        return None

#test db route
@app.route('/test-db')
def test_db():
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT 1")
        result = cursor.fetchone()
        return jsonify({"status": "success", "result": result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})
    finally:
        cursor.close()

#cookie preferences route        
@app.before_request
def check_cookie_preferences():
    if 'cookie_preferences_set' not in request.cookies:
        g.show_cookie_banner = True
    else:
        g.show_cookie_banner = False

#inject cookie preferences
@app.context_processor
def inject_cookie_preferences():
    return {
        'cookie_preferences': get_cookie_preferences(),
        'show_cookie_banner': getattr(g, 'show_cookie_banner', True)
    }

#set cookie route
def set_cookie(response, key, value, days_expire=365):
    expire_date = datetime.now() + timedelta(days=days_expire)
    response.set_cookie(
        key,
        value=value,
        expires=expire_date,
        secure=True,  # Only sent over HTTPS
        httponly=True,  # Not accessible via JavaScript
        samesite='Lax'  # Protection against CSRF
    )
    return response

#get cookie preferences
def get_cookie_preferences():
    return {
        'essential': request.cookies.get('essential_cookies', 'true'),
        'analytics': request.cookies.get('analytics_cookies', 'false'),
        'functional': request.cookies.get('functional_cookies', 'false'),
        'marketing': request.cookies.get('marketing_cookies', 'false')
    }

#cookie policy route
@app.route('/cookie-policy')
def cookie_policy():
    cookie_preferences = get_cookie_preferences()
    return render_template(
        'cookie-policy.html',
        now=datetime.now(),
        cookie_preferences=cookie_preferences
    )

#save cookie preferences route
@app.route('/save-cookie-preferences', methods=['POST'])
def save_cookie_preferences():
    try:
        preferences = request.get_json()
        response = make_response(jsonify({'status': 'success'}))
        
        # Set each cookie preference
        set_cookie(response, 'essential_cookies', str(preferences.get('essential', True)).lower())
        set_cookie(response, 'analytics_cookies', str(preferences.get('analytics', False)).lower())
        set_cookie(response, 'functional_cookies', str(preferences.get('functional', False)).lower())
        set_cookie(response, 'marketing_cookies', str(preferences.get('marketing', False)).lower())
        
        flash('Your cookie preferences have been saved.', 'success')
        return response
        
    except Exception as e:
        app.logger.error(f"Error saving cookie preferences: {str(e)}")
        flash('Failed to save preferences. Please try again.', 'error')
        return jsonify({'status': 'error', 'message': str(e)}), 500



# check cookie session
@app.route('/check-session')
def check_session():
    if 'user_id' in session:
        return jsonify({
            'logged_in': True,
            'session_permanent': session.permanent,
            'session_lifetime': str(app.permanent_session_lifetime),
            'user_id': session['user_id'],
            'first_name': session['first_name']
        })
    return jsonify({'logged_in':False})

if __name__ == '__main__':
    app.run(debug=True) 