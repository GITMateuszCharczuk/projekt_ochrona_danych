from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo, Email, ValidationError
from app.models import User

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, BooleanField
from wtforms.validators import DataRequired, Length, EqualTo, Email, ValidationError
from app.models import User

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('This email is already taken. Please choose a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class NoteForm(FlaskForm):
    content = TextAreaField('Content', validators=[DataRequired()])
    encrypted = BooleanField('Encrypt Content')
    password = PasswordField('Password (Optional)', validators=[Length(max=32)])
    public = BooleanField('Make Public')
    submit = SubmitField('Save Note')
    
class DecryptNoteForm(FlaskForm):
    password = PasswordField('Password', render_kw={'placeholder': 'Enter password'})
    decrypted_content = TextAreaField('Decrypted Content', render_kw={'readonly': True})
    submit = SubmitField('Decrypt')
