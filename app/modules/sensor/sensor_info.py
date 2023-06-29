from datetime import datetime

from app.modules.common.model import Model
from app import db


class SensorInfo(Model):
    '''
    Define the model
    '''
    __tablename__ = 'sensor_info'
    id = db.Column(db.Integer, primary_key=True)
    interface = db.Column(db.String)
    
    name = db.Column(db.String)
    description = db.Column(db.String)
    sensor_status = db.Column(db.String)
    
    address = db.Column(db.String)
    home_net = db.Column(db.String)
    log_dir = db.Column(db.String)
    config_dir = db.Column(db.String)
    
    snort_pid = db.Column(db.Integer)
    barnyard2_pid = db.Column(db.Integer)
    
    created_by = db.Column(db.String)
    updated_by = db.Column(db.String)
    
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now)
    deleted_at = db.Column(db.DateTime, default=datetime.now)