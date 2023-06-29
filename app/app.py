from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_mongoengine import MongoEngine

from settings.config import config_by_name

db = SQLAlchemy()
mongodb = MongoEngine()
flask_bcrypt = Bcrypt()


def init_app(config_name):
    app = Flask(__name__)
    app.config['JSON_AS_ASCII'] = False
    app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024
    CORS(app)
    app.config.from_object(config_by_name[config_name])
    db.init_app(app)
    mongodb.init_app(app)
    flask_bcrypt.init_app(app)
    return app
