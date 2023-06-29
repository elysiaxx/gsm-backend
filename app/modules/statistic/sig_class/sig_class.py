from sqlalchemy.orm import backref
from app.modules.common.model import Model
from app.modules.common.dto import Dto
from app import db

class SigClass(Model):
    '''
    Define model of SigClass.
    '''
    __tablename__ = 'sig_class'
    sig_class_id = db.Column(db.Integer, db.ForeignKey('signature.sig_class_id'), primary_key=True)
    sig_class_name = db.Column(db.String)