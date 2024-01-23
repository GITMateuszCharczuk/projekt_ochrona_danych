from flask import Flask
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
# from flask_security import Security
# from flask_talisman import Talisman

app = Flask(__name__)

# talisman = Talisman(
#     app,
#     content_security_policy={
#         'default-src': '\'self\''
#         # Add more directives as needed
#     }
# )

app.config['SECRET_KEY'] = '10685202-838e-4733-afcf-72c141d1868f'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
# app.config['SECURITY_PASSWORD_COMPLEXITY_RULES'] = [
#     dict(type='length', min=8),
#     dict(type='uppercase', min=1),
#     dict(type='numbers', min=1),
# ]

# security = Security(app)


csrf = CSRFProtect(app)
login_manager = LoginManager()
login_manager.login_view = 'routes.login'

db = SQLAlchemy(app)
migrate = Migrate(app, db)
from app.routes import routes
app.register_blueprint(routes)

login_manager.init_app(app)
from app.auth import load_user
login_manager.user_loader(load_user)



