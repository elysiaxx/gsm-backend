# tuong tac voi bang user trong CSDL --> Flask
from datetime import datetime

from werkzeug.security import generate_password_hash, check_password_hash

from app.modules.common.model import Model
from app import db


class User(Model):
    """
    Define the model
    """
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    display_name = db.Column(db.String)  # , default='')
    title = db.Column(db.String)  # , default='')

    first_name = db.Column(db.String)  # (128), default='')
    middle_name = db.Column(db.String)  # (128), default='')
    last_name = db.Column(db.String)  # (128), default='')

    gender = db.Column(db.String)  # (10), default='')
    age = db.Column(db.String)  # (3), default='')
    email = db.Column(db.String)  # (255), unique=True)
    password_hash = db.Column(db.String)  # (128), default='')

    last_seen = db.Column(db.DateTime, default=datetime.now)
    joined_date = db.Column(db.DateTime, default=datetime.now)
    confirmed = db.Column(db.Boolean, default=False)

    profile_pic_url = db.Column(db.String)  # (255), default='')
    profile_pic_data_url = db.Column(db.String)  # (10000), default='')
    admin = db.Column(db.Boolean, default=False)
    active = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        if self.admin:
            return True
        else:
            return False