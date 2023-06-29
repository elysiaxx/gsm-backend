from sqlalchemy.orm import backref

from app.modules.common.model import Model
from app import db

class Country(Model):
    '''
    Define the model
    '''
    __tablename__ = 'country'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String)
    code = db.Column(db.String)
