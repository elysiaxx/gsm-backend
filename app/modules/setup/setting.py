from app import db

from app.modules.common.model import Model

class Setting(Model):
    '''
    Define the model
    '''
    __tablename__ = 'setting'
    setting_type = db.Column(db.String, primary_key=True)
    state = db.Column(db.Integer)
        
    options_type = db.Column(db.Boolean) # auto or mannual
    setup_at = db.Column(db.DateTime)
    setup_by = db.Column(db.String)