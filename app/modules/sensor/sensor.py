from sqlalchemy.orm import backref

from app.modules.common.model import Model
from app.modules.statistic.event.event import Event
from app import db


class Sensor(Model):
    '''
    Define the model to interact with sensor in database
    '''
    __tablename__ = 'sensor'
    sid = db.Column(db.Integer,primary_key=True)
    hostname = db.Column(db.String) #, default= ''

    interface = db.Column(db.String) #, default= ''
    filter = db.Column(db.String) #, default= ''
    detail = db.Column(db.Integer)

    encoding = db.Column(db.Integer)
    last_cid = db.Column(db.Integer)
    events = db.relationship('Event',backref='sensor',lazy=True)
