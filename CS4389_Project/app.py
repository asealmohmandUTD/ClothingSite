import os
from flask import Flask, render_template, redirect, url_for, flash, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Email
from flask_sqlalchemy import SQLAlchemy
import bcrypt
from flask_mail import Mail, Message
from datetime import datetime, timedelta
import random
import string
from dotenv import load_dotenv
from sqlalchemy.exc import IntegrityError 
from functools import wraps  

##################################################################################################################################

# Load environment variables from a .env file
load_dotenv()

# Initialize the Flask application
app = Flask(__name__)

# Configure the secret key for the application from an environment variable
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# Set the URI for the SQLAlchemy database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

# Configure the mail server settings for sending emails (used in 2FA)
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'  # Convert string to boolean
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

# Initialize Flask-Mail extension with the app's settings
mail = Mail(app)

# Initialize SQLAlchemy extension with the app's settings
db = SQLAlchemy(app)

##################################################################################################################################

# Define a Token model for storing two-factor authentication tokens
class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Unique identifier for each token
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Link to a User
    token = db.Column(db.String(100), nullable=False)  # The 2FA token itself
    expiration = db.Column(db.DateTime, default=datetime.utcnow)  # Expiration date and time of the token
    
    # Method to check if a token has expired
    def is_expired(self):
        return datetime.utcnow() > self.expiration

# Define a User model for storing user information
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Unique identifier for each user
    username = db.Column(db.String(20), unique=True, nullable=False)  # User's username
    email = db.Column(db.String(120), unique=True, nullable=False)  # User's email
    password = db.Column(db.String(60), nullable=False)  # Hashed password
    cart_items = db.relationship('Cart', backref='user', lazy=True)  # Relationship with Cart items

# Define a ClothingItem model for storing clothing item details
class ClothingItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Unique identifier for each clothing item
    price = db.Column(db.Float, nullable=False)  # Price of the clothing item
    size = db.Column(db.String(10), nullable=False)  # Size of the clothing item
    quantity = db.Column(db.Integer, nullable=False)  # Available quantity
    cart_items = db.relationship('Cart', backref='clothing_item', lazy=True)  # Relationship with Cart items
    image_file = db.Column(db.String(120), nullable=False, default='shirt.jpeg')  # Image file path

# Define a Cart model for storing shopping cart details
class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Unique identifier for each cart item
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Link to a User
    clothing_item_id = db.Column(db.Integer, db.ForeignKey('clothing_item.id'), nullable=False)  # Link to a ClothingItem
    quantity = db.Column(db.Integer, nullable=False)  # Quantity of the clothing item in the cart

##################################################################################################################################

# Registration form class for new user sign up
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])  # Username field
    email = StringField('Email', validators=[DataRequired(), Email()])  # Email field
    password = PasswordField('Password', validators=[DataRequired(), EqualTo('confirm_password', message='Passwords must match')])  # Password field
    confirm_password = PasswordField('Confirm Password')  # Confirm Password field for verification
    submit = SubmitField('Sign Up')  # Submit button

# Login form class for user login
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])  # Username field
    password = PasswordField('Password', validators=[DataRequired()])  # Password field
    submit = SubmitField('Login')  # Submit button

# Two-factor authentication form class
class TwoFactorForm(FlaskForm):
    token = StringField('Token', validators=[DataRequired()])  # 2FA token field
    submit = SubmitField('Verify')  # Submit button

# Checkout form class for entering address and payment information
class CheckoutForm(FlaskForm):
    address = StringField('Shipping Address', validators=[DataRequired()])
    card_number = StringField('Card Number', validators=[DataRequired()])
    card_expiry = StringField('Card Expiry Date (MM/YY)', validators=[DataRequired()])
    card_cvc = StringField('Card CVC', validators=[DataRequired()])
    submit = SubmitField('Complete Purchase')


##################################################################################################################################

# Decorator for routes that require login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('Please log in to view this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# Route for the signup page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Check if the email already exists in the database
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user is not None:
            flash('Email already in use. Please choose another one.', 'danger')
            return redirect(url_for('signup'))

        # Hash the provided password
        hashed_password = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt())
        # Create a new user with the form data
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        try:
            db.session.commit()
            flash('Account created! Please log in.', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            # Handle database integrity errors (like duplicate entries)
            db.session.rollback()
            flash('Email already exists.', 'danger')
            return redirect(url_for('signup'))

    return render_template('signup.html', form=form)

# Route for the home page which redirects to the login page
@app.route('/')
def home():
    return redirect(url_for('login'))

# Route for the two-factor authentication page
@app.route('/two_factor/<int:user_id>', methods=['GET', 'POST'])
def two_factor(user_id):
    form = TwoFactorForm()
    if form.validate_on_submit():
        # Check if the submitted token is valid and not expired
        token = Token.query.filter_by(user_id=user_id, token=form.token.data).first()
        if token and not token.is_expired():
            flash('You have been logged in!', 'success')
            # Delete the token after successful login
            db.session.delete(token)
            db.session.commit()
            # Redirect to the index page, user is considered logged in here
            return redirect(url_for('index', user_id=user_id))
        else:
            flash('Invalid or expired 2FA code.', 'danger')
    return render_template('two_factor.html', form=form, user_id=user_id)

# Route for the login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Authenticate the user
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.checkpw(form.password.data.encode('utf-8'), user.password):
            # Generate a random token for 2FA
            token_string = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
            new_token = Token(user_id=user.id, token=token_string, expiration=datetime.utcnow() + timedelta(minutes=10))
            db.session.add(new_token)
            db.session.commit()

            # Send the token via email
            try:
                msg = Message('Your 2FA Code', recipients=[user.email])
                msg.body = f'Your two-factor authentication code is: {token_string}'
                mail.send(msg)
                flash('Please check your email for a 2FA code.', 'success')

                # Set user session variables
                session['logged_in'] = True
                session['user_id'] = user.id

                return redirect(url_for('two_factor', user_id=user.id))
            except Exception as e:
                flash('Failed to send 2FA code, please try again.', 'danger')
                app.logger.error('Failed to send email: %s', e)

        else:
            flash('Login unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', form=form)

# Route for logging out
@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# Route for the index page, accessible only after login
@app.route('/index/<int:user_id>', methods=['GET', 'POST'])
@login_required
def index(user_id):
    # Prevent users from accessing other user's pages
    if session.get('user_id') != user_id:
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))
    items = ClothingItem.query.all()
    return render_template('index.html', user_id=user_id, items=items)

# Route for the cart page, accessible only after login
@app.route('/cart/<int:user_id>')
@login_required
def cart(user_id):
    # Ensure the user is accessing their own cart
    if session.get('user_id') != user_id:
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))

    # Query the database for the user's cart items
    cart_items = Cart.query.filter_by(user_id=user_id).all()

    # Now, retrieve details of each clothing item in the cart
    cart_details = []
    for item in cart_items:
        clothing_item = ClothingItem.query.get(item.clothing_item_id)
        cart_details.append({
            'id': item.id,
            'quantity': item.quantity,
            'price': clothing_item.price,
            'size': clothing_item.size,
            'image_file': clothing_item.image_file,
        })

    # Pass the cart details to the template
    return render_template('cart.html', cart_details=cart_details, user_id=user_id)

# Route for adding item process, accessible only after login
@app.route('/add_to_cart/<int:user_id>/<int:item_id>')
@login_required
def add_to_cart(user_id, item_id):
    if session.get('user_id') != user_id:
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))

    # Retrieve or create a cart item
    cart_item = Cart.query.filter_by(user_id=user_id, clothing_item_id=item_id).first()
    if cart_item:
        cart_item.quantity += 1  # Increase quantity if item already in cart
    else:
        cart_item = Cart(user_id=user_id, clothing_item_id=item_id, quantity=1)  # Create new cart item
        db.session.add(cart_item)

    db.session.commit()
    flash('Item added to cart!', 'success')
    return redirect(url_for('index', user_id=user_id))

# Route for checking out, accessible only after login
@app.route('/checkout/<int:user_id>', methods=['GET', 'POST'])
@login_required
def checkout(user_id):
    if session.get('user_id') != user_id:
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))

    cart_items = Cart.query.filter_by(user_id=user_id).all()

    cart_details = []
    total_price = 0  # Initialize total price

    for item in cart_items:
        clothing_item = ClothingItem.query.get(item.clothing_item_id)
        item_total = item.quantity * clothing_item.price  # Calculate total price for this item
        total_price += item_total  # Add to the total price

        cart_details.append({
            'id': item.id,
            'quantity': item.quantity,
            'price': clothing_item.price,
            'size': clothing_item.size,
            'image_file': clothing_item.image_file,
            'total_price': item_total  # Item's total price
        })

    form = CheckoutForm()
    if form.validate_on_submit():
        user = User.query.get(user_id)
        if user:
            try:
                # Prepare the email message
                msg = Message("Order Confirmation", recipients=[user.email])
                msg.body = f"Dear {user.username},\n\nYour order has been successfully placed.\n\nOrder Details:\n"
                for item in cart_details:
                    msg.body += f"Item: {item['size']} - Price: ${item['price']} - Quantity: {item['quantity']}\n"
                msg.body += f"\nTotal Price: ${total_price}\n\nThank you for shopping with us!"

                # Send the email
                mail.send(msg)
                flash('Order confirmation has been sent to your email.', 'success')
            except Exception as e:
                app.logger.error('Failed to send email: %s', e)
                flash('Failed to send order confirmation email.', 'danger')

        # Redirect to the success page
        return redirect(url_for('success_page', user_id=user_id))

    return render_template('checkout.html', user_id=user_id, cart_details=cart_details, total_price=total_price, form=form)

# Route for success page, accessible only after login
@app.route('/success_page/<int:user_id>')
def success_page(user_id):
    return render_template('success_page.html', user_id=user_id)


##################################################################################################################################

# Main execution point of the application
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables if they don't already exist

        # List of new clothing items
        new_items = [
            ClothingItem(price=20.00, size='M', quantity=10, image_file='shirt.jpeg'),
            ClothingItem(price=25.00, size='L', quantity=5, image_file='dressShirt.jpeg'),
            ClothingItem(price=40.00, size='M', quantity=10, image_file='jacket.jpeg'),
            ClothingItem(price=100.00, size='L', quantity=5, image_file='nikeShoe.jpeg'),
            ClothingItem(price=20.00, size='L', quantity=5, image_file='pants.jpeg')
        ]

        for item in new_items:
            # Check if an item with the same attributes already exists
            exists = ClothingItem.query.filter_by(
                price=item.price,
                size=item.size,
                image_file=item.image_file
            ).first()

            # If the item does not exist, add it to the database
            if not exists:
                db.session.add(item)

        # Commit the session if new items were added
        db.session.commit()

    app.run(debug=True)

