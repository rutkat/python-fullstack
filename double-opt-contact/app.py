from flask import Flask, render_template, request, url_for, redirect, flash
from flask_mail import Mail, Message
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import secrets
import bleach
import requests


app = Flask(__name__, template_folder='templates')
# Flask configurations
secret = secrets.token_urlsafe(32)
app.secret_key = secret
app.config['SECRET_KEY'] = secret # auto-generated secret key
app.config['HCAPTCHA_SECRET_KEY'] = 'your-secret-hcaptcha-key'

# SQLAlchemy configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://admin:user@localhost/tablename'

# Email configurations
app.config['MAIL_SERVER'] = 'your.domain.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'your-email@domain.com'
app.config['MAIL_PASSWORD'] = 'email-password'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

db = SQLAlchemy(app)
mail = Mail(app)
sserializer = URLSafeTimedSerializer(app.config['SECRET_KEY']) #set secret to the serliazer

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    validated = db.Column(db.Boolean, default=False)

# Create the database table
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return '<h1>Index page</h1>'

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = bleach.clean(request.form.get('email'))
        hcaptcha_response = request.form.get('h-captcha-response')

        # Verify hCaptcha response
        payload = {
            'secret': app.config['HCAPTCHA_SECRET_KEY'],
            'response': hcaptcha_response
        }
        try:
            response = requests.post('https://hcaptcha.com/siteverify', data=payload, timeout=10)
            result = response.json()
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")

        if not result.get('success'):
            flash('CAPTCHA validation failed, please try again.', 'danger')
            return redirect('/contact')
        # Insert user into the database
        new_user = Users(email=email)
        try:
            db.session.add(new_user)
            db.session.commit()
        except Exception as e:
            print(f"Error occurred saving to db: {e}")

        # Send confirmation email
        token = sserializer.dumps(email, salt='email-confirm')
        msg = Message('Confirm your Email', sender=app.config['MAIL_USERNAME'], recipients=[email])
        link = url_for('confirm_email', token=token, _external=True)
        msg.body = f'Your link is {link}'
        print('msg: ', msg.body)
        try:
            mail.send(msg)
        except Exception as e:
            print(f"Error occurred sending message: {e}")
            flash("Error occurred sending message!")
            return render_template('signup.html')   
        flash('A confirmation email has been sent to your email address.', 'success') 
    return render_template('signup.html')  	

@app.route('/confirm_email/<token>')
def confirm_email(token):
    print(token)
    try:
        email = sserializer.loads(token, salt='email-confirm', max_age=1200)  # Token expires after 1 hour
    except SignatureExpired:
        return '<h1>Oops, the token expired!</h1>'

    # Update field in database
    user = Users.query.filter_by(email=email).first_or_404()
    user.validated = True
    try:
        db.session.commit()
    except Exception as e:
        print(f"Error occurred saving to db: {e}")

    return '<h1>Email address confirmed!</h1>'


if __name__ == '__main__':
    app.run()
