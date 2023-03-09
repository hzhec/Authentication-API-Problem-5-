from flask import Flask, render_template, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database.db"
app.config['SECRET_KEY'] = 'secretkey'

# Allow app and flask login to work together when logging in
login_manager = LoginManager() 
login_manager.init_app(app)
login_manager.login_view = "login"

# Reload user object from the user ID stored in the session
@login_manager.user_loader 
def load_user(user_id):
    return User.query.get(int(user_id))

#Create database
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    countrycode = db.Column(db.String(20), nullable=False)
    username = db.Column(db.String(20), nullable=False, unique=True) # unique to set to True so that there cannot be two or more of same usernames
    password = db.Column(db.String(80), nullable=False)

# Create Register Form for account registration
class RegisterForm(FlaskForm):
    countrycode = StringField(validators=[InputRequired(), Length(min=1, max=4)], render_kw={"placeholder": "Country Code (2 Letters)"})
    
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    
    submit = SubmitField("Register")


# Create Login Form for account login page
class LoginForm(FlaskForm):
    
    country_user = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Country Code + Username"})
    
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    
    submit = SubmitField("Login")

# Home Page
@app.route('/')
def home():
    return render_template('home.html')

# Login Page
@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Split login username input into country code and username to check in database
        countrycode_data = form.country_user.data[:2]
        username_data = form.country_user.data[2:]
        country_code = User.query.filter_by(countrycode=countrycode_data.lower()).first()
        user = User.query.filter_by(username=username_data.lower()).first()
        # Check account exists in database
        if not country_code: 
                flash("Account not exists!")
                return redirect(url_for('login'))
        else: 
            if not user:
                    flash("Account not exists!")
                    return redirect(url_for('login'))
            else: 
                # If account exists, check if password is input correctly
                if bcrypt.check_password_hash(user.password, form.password.data):
                    login_user(user)
                    return redirect(url_for('dashboard'))
                # Return error message if password is incorrect
                else: 
                    flash("Incorrect password!")
                    return redirect(url_for('login'))
            
    return render_template('login.html', form=form)

# Dashboard page after successfully logged in
@app.route('/dashboard', methods=('GET','POST'))
@login_required
def dashboard():
    return render_template('dashboard.html')

# Log out and redirect back to login page
@app.route('/logout', methods=('GET', 'POST'))
@login_required
def logout():
    logout_user()
    flash("You have logged out successfully!")
    return redirect(url_for('login'))

# Registration page
@app.route('/register', methods=['GET','POST'])
def register():
    form = RegisterForm()
    
    if form.validate_on_submit():
        # Check if country code input meet the 2 letter criteria
        if not len(form.countrycode.data) < 3:
            flash("Does not meet the 2 letter country code criteria.")
            return redirect(url_for('register'))

        # Check if account already created/existed in database
        existing_user_username = User.query.filter_by(username=form.username.data).first()
        if existing_user_username:
            flash("That user already exists! Please choose a different one.")
            return redirect(url_for('register'))
        
        # Check if password is more than 8 characters length
        if not len(form.password.data) >= 8:
            flash("Password must be at least 8 characters in length")
            return redirect(url_for('register'))
        
        # Encrypt and store password into database
        encrypt_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(countrycode=form.countrycode.data.lower(), username=form.username.data.lower(), password=encrypt_password)
        db.session.add(new_user) # Add into database
        db.session.commit() # Commit the changes 
        # Prompt account created successfully and redirect user to login page
        flash("Account created successfully!")
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)