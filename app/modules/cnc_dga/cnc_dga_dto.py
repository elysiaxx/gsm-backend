from flask_restx import fields, Namespace
from datetime import datetime

from app.modules.common.dto import Dto


class CncDgaDto(Dto):
    name = 'cnc_dga'
    api = Namespace(name)
    model_request = api.model('cnc_dga_request', {
        'domain': fields.String(required=False),
        'timestamp': fields.DateTime(required=False)
    })
    
    model_response = api.model('cnc_dga_response', {
        'domain': fields.String(required=False),
        'timestamp': fields.DateTime(required=False)
    })