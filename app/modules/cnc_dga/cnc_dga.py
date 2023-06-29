from app import db

from app.modules.common.model import Model


class CncDga(Model):
    '''
    Define cnc server model
    '''
    __tablename__ = 'cnc_dga'
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String)
    timestamp = db.Column(db.DateTime)
