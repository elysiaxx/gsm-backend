from flask_restx import Namespace, fields

from app.modules.common.dto import Dto


class SettingDto(Dto):
    name = 'setting'
    api = Namespace(name)
    
    model_backup_request = api.model('backup_request', {
        'state': fields.Integer(required=False),
        'options_type': fields.Boolean(required=False)
    })
    
    model_response = api.model('setting_response', {
        'setting_type': fields.String(required=False),
        'state': fields.Integer(required=False),
        
        'options_type': fields.Boolean(required=False),
        'setup_by': fields.String(required=False),
        'setup_at': fields.DateTime(required=False)
    })