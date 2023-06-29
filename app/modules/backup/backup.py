from app.modules.common.model import Model
from app import db
from datetime import datetime


class Backup(Model):
    """
    Define the model
    """
    __tablename__ = 'backup'
    id = db.Column(db.Integer, primary_key=True)
    path = db.Column(db.String)
    file_id = db.Column(db.Integer)
    
    backup_type = db.Column(db.String)
    num_of_rules = db.Column(db.Integer)
    created_by = db.Column(db.String)
    created_at = db.Column(db.DateTime, default=datetime.now)