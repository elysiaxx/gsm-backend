from app.modules.common.model import Model
from app import db

class ReportEvents(Model):
    '''
    Define model of Report Events table.
    '''
    __tablename__ = 'report_events'
    sid = db.Column(db.Integer, primary_key=True, nullable=False)
    cid = db.Column(db.Integer, primary_key=True, nullable=False)
    signature = db.Column(db.Integer,nullable=False)

    sig_name = db.Column(db.String)
    sig_class_id = db.Column(db.Integer)
    sig_priority = db.Column(db.Integer)

    timestamp = db.Column(db.DateTime, nullable=False)
    ip_src = db.Column(db.Integer)
    ip_dst = db.Column(db.Integer)
    ip_proto = db.Column(db.Integer)

    layer4_sport = db.Column(db.Integer)
    layer4_dport = db.Column(db.Integer)
    cnc_server = db.Column(db.Integer)
    
    security_level = db.Column(db.Integer)
    id_country = db.Column(db.Integer)
