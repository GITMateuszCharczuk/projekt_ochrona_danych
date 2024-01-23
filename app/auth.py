from app import app, login_manager
from app.models import User

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))