from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from . import db
from werkzeug.security import generate_password_hash, check_password_hash

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='Success')
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect in password, try again!', category='Error' )   
        else:
            flash('Email does not exist.', category='Error')
             
    return render_template("login.html", text="Login")

@auth.route('/logout')
def logout():
    return "<h3>Logout</h3>"

@auth.route('/signup', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        firstName = request.form.get('firstName')
        password = request.form.get('password1')
        passwordConfirm = request.form.get('password2')
        
        print(f"PWD 1 >>> {password}")
        print(f"PWD 2 >>> {passwordConfirm}")
        
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists, please login', category='Error')
        if len(email) <= 4:
            flash("Email must be greater than 4 chars.", category='Error')
        elif len(firstName) < 2:
            flash("First name must be greater than 2 chars.", category='Error')
        elif password != passwordConfirm:
            flash("Passwords do not match", category='Error')
        elif len(password) <= 7:
            flash("Password must be greater than 7 chars.", category='Error')
        else:     
            new_user = User(email=email, first_name=firstName, password=generate_password_hash(password, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            flash("Account created", category='Success')
            return redirect(url_for('views.home'))
        
    return render_template("signup.html")