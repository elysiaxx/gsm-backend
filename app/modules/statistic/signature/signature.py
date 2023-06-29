from sqlalchemy.orm import backref

from app import db

from app.modules.common.model import Model
from app.modules.statistic.sig_reference.sig_reference import SigReference
from app.modules.statistic.event.event import Event


class Signature(Model):
    '''
    Define model of Signature.
    '''
    __tablename__ = 'signature'
    sig_id = db.Column(db.Integer,primary_key=True)
    sig_name = db.Column(db.String)
    sig_class_id = db.Column(db.Integer)
    sig_priority = db.Column(db.Integer)
    sig_rev = db.Column(db.Integer)
    sig_sid = db.Column(db.Integer)
    sig_gid = db.Column(db.Integer)
    sig_references = db.relationship('SigReference', backref='signature', lazy=True)
    sig_classes = db.relationship('SigClass', backref='signature', lazy=True)
    # event = db.relationship('Event', backref='signature', lazy=True)
