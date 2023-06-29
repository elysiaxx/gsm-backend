from app.modules.common.dto import Dto
from app.modules.common.model import Model
from app import db


class SigReference(Model):
    '''
    Define model of SigReference.
    '''
    __tablename__ = 'sig_reference'
    sig_id = db.Column(db.Integer, db.ForeignKey('signature.sig_id'), primary_key=True)
    ref_id = db.Column(db.Integer, db.ForeignKey('reference.ref_id'))
    ref_seq = db.Column(db.Integer, primary_key=True)