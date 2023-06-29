from app import db

from app.modules.common.model import Model


class CncServer(Model):
    '''
    Define cnc server model
    '''
    __tablename__ = 'cnc_server'
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String)
    status = db.Column(db.Boolean)
    
    description = db.Column(db.String)
    type = db.Column(db.String)
    created_by = db.Column(db.String)
    updated_by = db.Column(db.String)
    
    created_at = db.Column(db.DateTime)
    updated_at = db.Column(db.DateTime)
    deleted_at = db.Column(db.DateTime)
