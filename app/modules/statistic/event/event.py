from sqlalchemy.orm import backref

from app.modules.common.model import Model
from app import db

class Event(Model):
    '''
    Define the model  to interact with sensor in database
    '''
    __tablename__ = 'event'
    sid = db.Column(db.Integer, db.ForeignKey('sensor.sid'), primary_key=True,nullable=False)
    cid = db.Column(db.Integer,primary_key=True,nullable=False)

    signature = db.Column(db.Integer, db.ForeignKey('signature.sig_id'), nullable=False)
    timestamp = db.Column(db.DateTime,nullable=False)
