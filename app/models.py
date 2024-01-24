from datetime import datetime
from flask_login import UserMixin
from flask_bcrypt import Bcrypt
from cryptography.fernet import Fernet
from app import db, app
import hashlib
import base64
import pyotp
import re
import math
from collections import Counter

bcrypt = Bcrypt()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    totp_secret = db.Column(db.String(16), nullable=False)
    notes = db.relationship('Note', backref='author', lazy=True)

    def set_password(self, password):
        res = is_password_strong(password)
        if(res is not None):
            raise ValueError(res)
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)
    
    def generate_totp_secret(self):
        totp = pyotp.TOTP(pyotp.random_base32())
        self.totp_secret = totp.secret

    def verify_totp(self, totp_code):
        if not self.totp_secret:
            return False

        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(totp_code)
    
    def get_totp_uri(self):
        totp = pyotp.TOTP(self.totp_secret)
        issuer_name = 'Note app'
        user_name = self.email
        return totp.provisioning_uri(name=user_name, issuer_name=issuer_name)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    public = db.Column(db.Boolean, default=False)
    encrypted = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    user = db.relationship('User', back_populates='notes')
    
    def encrypt_content(self, password):
        try:
            key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
            self.content=Fernet(key).encrypt(self.content.encode('utf-8'))
            self.encrypted = True
        except Exception as e:
            print(f"Error encrypting content: {e}")


    def decrypt_content(self, password):
        try:
            key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
            decrypted_content = Fernet(key).decrypt(self.content).decode('utf-8')
            return decrypted_content
        except Exception as e:
            print(f"Error decrypting content: {e}")
            return None
        
class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.Text, nullable=False)
    timeout_date = db.Column(db.DateTime, default=datetime.utcnow)
    is_suspended = db.Column(db.Boolean, default=False)
    requests = db.relationship('Request', back_populates='client')

class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_date = db.Column(db.DateTime, default=datetime.utcnow)
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'))
    client = db.relationship('Client', back_populates='requests')
    
def is_password_strong(password):
    if len(password) < 8:
        return "Password too short, it must contain at least 8 digits"

    if not any(char.isupper() for char in password):
        return "No uppercase characters in password"

    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return "No special characters in password"

    if not any(char.isdigit() for char in password):
        return "No digits in password"

    if calculate_entropy(password) < 3:
        return "Too weak password"
    
    return None



def calculate_entropy(input_string):
    n = len(input_string)
    char_frequencies = Counter(input_string)
    probabilities = [char_count / n for char_count in char_frequencies.values()]
    entropy = -sum(p * math.log2(p) for p in probabilities if p > 0)
    
    return entropy

