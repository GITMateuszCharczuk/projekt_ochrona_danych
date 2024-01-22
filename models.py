from datetime import datetime
from flask_login import UserMixin
from flask_bcrypt import Bcrypt
from cryptography.fernet import Fernet
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from app import db, app

bcrypt = Bcrypt()
fernet = Fernet(app.config['SECRET_KEY'])

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
    encrypted = db.Column(db.LargeBinary)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    def encrypt_content(self, password):
        self.encrypted_content = fernet.encrypt(bytes(self.content, 'utf-8'))

    def decrypt_content(self, password):
        try:
            decrypted_content = fernet.decrypt(self.encrypted_content).decode('utf-8')
            return decrypted_content
        except Exception as e:
            print(f"Error decrypting content: {e}")
            return None
