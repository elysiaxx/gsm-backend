from flask_restx import Namespace, fields

from app.modules.common.dto import Dto


class BackupDto(Dto):
    name = 'backup'
    api = Namespace(name)
    model_request = api.model('model_backup_request', {
        'file_id': fields.Integer(required=False),
        'backup_type': fields.String(required=False)
    })

    model_response = api.model('model_backup_response', {
        'id': fields.Integer(required=False),
        'file_id': fields.Integer(required=False),
        'num_of_rules': fields.Integer(required=False),
        
        'backup_type': fields.String(required=False),
        'path': fields.String(required=False),
        'created_by': fields.String(required=False),
        'created_at': fields.DateTime(required=False)
    })