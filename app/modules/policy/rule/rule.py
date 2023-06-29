from datetime import datetime
from app import db

from app.modules.common.model import Model

class Rule(Model):
    '''
    Define the model to interact with rule in database
    '''
    __tablename__ = 'rule'
    id = db.Column(db.Integer, primary_key=True,nullable=False)
    raw_text = db.Column(db.String)
    
    rule_index = db.Column(db.Integer)
    rule_status = db.Column(db.Boolean, default=False)
    file_id = db.Column(db.Integer, db.ForeignKey('rules_file.id'))
    
    created_by = db.Column(db.String)
    updated_by = db.Column(db.String)
    
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now)
    deleted_at = db.Column(db.DateTime, default=datetime.now)
    

