from app import db
from datetime import datetime

from app.modules.common.model import Model


class Action(Model):
    '''
    Define action model
    '''
    __tablename__ = 'action'
    id = db.Column(db.Integer, primary_key=True)
    action_name = db.Column(db.String)
    description = db.Column(db.String)
    
    action_filter = db.Column(db.String)
    minimum_events = db.Column(db.Integer)
    during_time = db.Column(db.Integer)
    
    email_notification = db.Column(db.String)
    created_by = db.Column(db.String)
    updated_by = db.Column(db.String)
    
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now)
    deleted_at = db.Column(db.DateTime, default=datetime.now)
