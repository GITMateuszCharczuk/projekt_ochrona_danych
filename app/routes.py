from flask import Blueprint,session, render_template, url_for, flash, redirect, request, jsonify
import sys
from flask_login import login_user, current_user, logout_user, login_required
from app import db, login_manager
from app.models import User, Note
from app.forms import RegistrationForm, LoginForm, NoteForm, DecryptNoteForm, VerifyTOTPForm, ChangePassword
from sqlalchemy.orm import joinedload
from flask_bcrypt import Bcrypt
from bleach import clean
import pyotp
bcrypt = Bcrypt()

routes = Blueprint('routes', __name__)

MAX_FAILED_ATTEMPTS = 10
LOCKOUT_DURATION_SECONDS = 3600

@routes.route('/')
def home():
    public_notes = (
            Note.query
            .filter_by(public=True)
            .options(joinedload(Note.user))  # This will eagerly load the associated user
            .all()
    )
    if current_user.is_authenticated:
        user_notes = Note.query.filter_by(user_id=current_user.id, public=False).all()
        #public_notes = Note.query.filter_by(public=True).all()
        return render_template('home.html', username=current_user.username, user_notes=user_notes, public_notes=public_notes)
    else:
        public_notes = Note.query.filter_by(public=True).all()
        return render_template('home.html', public_notes=public_notes)

@routes.route('/add_note', methods=['GET', 'POST'])
@login_required
def add_note():
    form = NoteForm()
    try:
        if form.validate_on_submit():
            content = secure_content_payload(form.content.data)
            note = Note(content=content, user_id=current_user.id)
            if form.encrypted.data:
                note.encrypt_content(form.password.data)
            note.public = form.public.data  
            db.session.add(note)
            db.session.commit()
            flash('Your note has been added!', 'success')
            return redirect(url_for('routes.home'))

    except Exception as e:
            db.session.rollback()
            flash(f'Error adding note: {str(e)}', 'danger')
            
    return render_template('add_note.html', title='Add Note', form=form)

@routes.route('/view_notes')
def view_notes():
    public_notes = (
            Note.query
            .filter_by(public=True)
            .options(joinedload(Note.user))  # This will eagerly load the associated user
            .all()
    )
    if current_user.is_authenticated:
        user_notes = Note.query.filter_by(user_id=current_user.id, public=False).all()
        return render_template('view_notes.html', title='View Notes', user_notes=user_notes, public_notes=public_notes)
    else:
        return render_template('view_notes.html', title='View Notes', user_notes=[], public_notes=public_notes)

@routes.route('/view_encrypted_note/<int:note_id>', methods=['GET', 'POST'])
@login_required
def view_encrypted_note(note_id):
    note = Note.query.get_or_404(note_id)

    if not note.encrypted:
        flash('This note is not encrypted.', 'warning')
        return redirect(url_for('routes.view_notes'))

    form = DecryptNoteForm()

    if form.validate_on_submit():
        password = form.password.data
        decrypted_content = note.decrypt_content(password)

        if decrypted_content is not None:
            form.decrypted_content.data = decrypted_content
        else:
            flash('Incorrect password.', 'danger')

    return render_template('view_encrypted.html', title='View Encrypted Note', form=form, note=note)

@routes.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('routes.home'))

    form = RegistrationForm()

    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()

        if existing_user:
            flash('Username is already taken. Please choose a different one.', 'danger')
            return redirect(url_for('routes.register'))

        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        user.generate_totp_secret()
        totp_uri = user.get_totp_uri()
        db.session.add(user)
        db.session.commit()

        session['email'] = user.email
        flash('Your account has been created! Set up Two-Factor Authentication.', 'success')

        return redirect(url_for('routes.totp_setup', totp_uri=totp_uri))

    return render_template('register.html', title='Register', form=form)

@routes.route('/totp-setup', methods=['GET', 'POST'])
def totp_setup():
    totp_uri = request.args.get('totp_uri', '')
    email = session.get('email', '')
    
    form = VerifyTOTPForm()  # Create an instance of the form
    
    if form.validate_on_submit():  # Check if the form is submitted and valid
        totp_code = form.totp_code.data
        user = User.query.filter_by(email=email).first()
        session.pop('email', None)
        if user.verify_totp(totp_code):
            flash('TOTP verification successful!', 'success')
            return redirect(url_for('routes.home'))
        else:
            flash('Invalid verification code. Please try again.', 'danger')

    return render_template('totp_setup.html', totp_uri=totp_uri, form=form)

@routes.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data) and user.verify_totp(form.totp_code.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('routes.home'))
        else:
            flash('Login unsuccessful.', 'danger')
    return render_template('login.html', title='Login', form=form)

@routes.route('/change_password', methods=['GET', 'POST'])
def change_password():
    form = ChangePassword()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.verify_totp(form.totp_code.data):
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user.password = hashed_password
            db.session.commit()
            flash('Password changed successfully', 'success')
            return redirect(url_for('routes.home'))
        else:
            flash('Something went wrong', 'danger')
    return render_template('change_password.html', form=form)

@routes.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('routes.home'))

def secure_content_payload(content):
    allowed_tags = ['h1', 'h2', 'h3', 'h4', 'h5', 'strong', 'a', 'img', 'i']
    allowed_attributes = {'a': ['href', 'title'],'img': ['src', 'alt']}
    
    cleaned_content = clean(content, tags=allowed_tags, attributes=allowed_attributes)
    return cleaned_content