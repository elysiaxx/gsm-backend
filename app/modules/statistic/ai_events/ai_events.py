from app import db

from app.modules.common.model import Model


class AIEvents(Model):
    '''
    Define the model
    '''
    __tablename__ = 'ai_events'
    flow_id = db.Column(db.Integer, primary_key=True)
    src_ip = db.Column(db.Integer)
    
    src_port = db.Column(db.Integer)
    dst_ip = db.Column(db.Integer)
    dst_port = db.Column(db.Integer)
    protocol = db.Column(db.Integer)
    
    timestamp = db.Column(db.DateTime)
    flow_duration = db.Column(db.Integer)
    attack_type = db.Column(db.Integer)
    