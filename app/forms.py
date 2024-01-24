from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField,BooleanField
from wtforms.validators import DataRequired, Length, EqualTo,Regexp,  Email, ValidationError
from app.models import User

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_password(self, password):
        min_length = 8
        if len(password.data) < min_length:
            raise ValidationError(f'Password must be at least {min_length} characters long')

        if not any(char.isupper() for char in password.data):
            raise ValidationError('Password must contain at least one uppercase letter')

        if not any(char.isdigit() for char in password.data):
            raise ValidationError('Password must contain at least one digit')

        special_characters = "!@#$%^&*(),.?\":{}|<>"
        if not any(char in special_characters for char in password.data):
            raise ValidationError('Password must contain at least one special character')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Something went wrong')
        
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Something went wrong')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    totp_code = StringField('Enter Verification Code', validators=[DataRequired(), Length(max=6)])
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
    
    
class ChangePassword(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', render_kw={'placeholder': 'Enter password'})
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    totp_code = StringField('Enter Verification Code', validators=[DataRequired()])
    submit = SubmitField('Submit')
    
class VerifyTOTPForm(FlaskForm):
    totp_code = StringField('Enter Verification Code', validators=[DataRequired()])
    submit = SubmitField('Verify')
