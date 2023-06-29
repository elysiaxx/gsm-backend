from app import db
from datetime import datetime

from app.modules.common.model import Model


class RulesFile(db.Model):
    '''
    Define the model to interact with rules file in database
    '''
    __tablename__ = 'rules_file'
    id = db.Column(db.Integer, primary_key=True)
    
    file_name = db.Column(db.String)
    file_type = db.Column(db.String)
    file_status = db.Column(db.Boolean, default=False)
        
    last_index = db.Column(db.Integer)
    created_by = db.Column(db.String)
    updated_by = db.Column(db.String)
    
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now)
    deleted_at = db.Column(db.DateTime, default=datetime.now)
    
    # rules = db.relationship('Rule', backref='rules_file', lazy=True)
    # backups = db.relationship('Backup', backref='rules_file', lazy=True)