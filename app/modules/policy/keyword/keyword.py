from sqlalchemy import ForeignKey
from app.modules.common.model import Model
from app import db

class Keyword(Model):
    '''
    Define the model to interact with keyword in database
    '''
    __tablename__ = 'keyword'
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    key_word = db.Column(db.String, nullable=False)
    
    core = db.Column(db.String, nullable=False)
    description = db.Column(db.String)
    user_id = db.Column(db.Integer)
