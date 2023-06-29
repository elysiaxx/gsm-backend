from app import db

from app.modules.common.model import Model


class Automation(Model):
    '''
    Define the model
    '''
    __tablename__ = 'automation'
    email = db.Column(db.String, primary_key=True)
    password = db.Column(db.String)