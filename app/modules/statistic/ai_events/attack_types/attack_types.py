from app import db

from app.modules.common.model import Model


class AttackTypes(Model):
    '''
    Define the model
    '''
    __tablename__ = 'attack_types'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String)
    description = db.Column(db.String)