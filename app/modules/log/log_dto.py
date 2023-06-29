from app import db
from flask_restx import Namespace, fields

from app.modules.common.dto import Dto


class LogDto(Dto):
    name = 'log'
    api = Namespace(name)
    model_request = api.model('model_request', {
        
    })
    
    model_response = api.model('model_response', {
        'time': fields.String(required=False),
        'level': fields.String(required=False),
        
        'user': fields.String(required=False),
        'message': fields.String(required=False)
    })