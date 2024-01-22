# routes.py

from flask import render_template, url_for, flash, redirect, request, jsonify
from flask_login import login_user, current_user, logout_user, login_required
from app import app, db, bcrypt, login_manager
from app.models import User, Note
from app.forms import RegistrationForm, LoginForm, NoteForm

@app.route('/add_note', methods=['GET', 'POST'])
@login_required
def add_note():
    form = NoteForm()
    if form.validate_on_submit():
        note = Note(content=form.content.data, author=current_user)
        if form.encrypted.data:
            note.encrypt_content(form.password.data)
        db.session.add(note)
        db.session.commit()
        flash('Your note has been added!', 'success')
        return redirect(url_for('home'))
    return render_template('add_note.html', title='Add Note', form=form)

@app.route('/view_notes')
@login_required
def view_notes():
    notes = Note.query.filter_by(user_id=current_user.id).all()
    return render_template('view_notes.html', title='View Notes', notes=notes)

@app.route('/decrypt_note/<int:note_id>', methods=['POST'])
@login_required
def decrypt_note(note_id):
    password = request.form.get('password')
    note = Note.query.get(note_id)

    if not note or note.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Note not found or unauthorized.'})

    decrypted_content = note.decrypt_content(password)

    if decrypted_content is not None:
        return jsonify({'success': True, 'decrypted_content': decrypted_content})
    else:
        return jsonify({'success': False, 'message': 'Incorrect password or error decrypting content.'})

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('home'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))