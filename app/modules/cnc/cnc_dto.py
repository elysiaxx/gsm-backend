from flask_restx import fields, Namespace
from datetime import datetime

from app.modules.common.dto import Dto


class CncDto(Dto):
    name = 'cnc_server'
    api = Namespace(name)
    model_request = api.model('cnc_server_request', {
        'address': fields.String(required=False),
        'status': fields.Boolean(required=False),
        'description': fields.String(required=False),
        'type': fields.String(require=False)
    })
    
    model_response = api.model('cnc_server_response', {
        'id': fields.Integer(required=False),
        'address': fields.String(required=False),
        'status': fields.Boolean(required=False),
        
        'description': fields.String(required=False),
        'type': fields.String(required=False),
        'created_by': fields.String(required=False),
        'updated_by': fields.String(required=False),
        
        'created_at': fields.DateTime(required=False, default=datetime.now),
        'updated_at': fields.DateTime(required=False, default=datetime.now),
        'deleted_at': fields.DateTime(required=False)
    })