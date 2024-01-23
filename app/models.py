from datetime import datetime
from flask_login import UserMixin
from flask_bcrypt import Bcrypt
from cryptography.fernet import Fernet
from app import db, app
import hashlib
import base64


bcrypt = Bcrypt()

def generate_fernet_key(secret_key):
    # Ensure the secret_key is in bytes
    key = secret_key.encode() if isinstance(secret_key, str) else secret_key
    # Take the SHA256 hash of the key
    key_hash = hashlib.sha256(key).digest()
    # Use the first 32 bytes as the Fernet key
    return base64.urlsafe_b64encode(key_hash[:32])

# Generate the Fernet key from the SECRET_KEY
fernet_key = generate_fernet_key(app.config['SECRET_KEY'])
fernet = Fernet(fernet_key)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    notes = db.relationship('Note', backref='author', lazy=True)

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

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
            self.encrypted = True
            self.content=Fernet(key).encrypt(self.content.encode('utf-8'))
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

