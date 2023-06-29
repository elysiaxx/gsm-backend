from flask_restx import Namespace, fields

from app.modules.common.dto import Dto


class EventDto(Dto):
    name = 'event'
    api = Namespace(name)
    model_request = api.model('event_request', {
        'sid': fields.Integer(required=True),
        'cid': fields.Integer(required=True),

        'signature': fields.Integer(required=False),
        'timestamp': fields.DateTime(required=False)
    })

    model_response = api.model('event_response', {
        'sid': fields.Integer(required=False),
        'cid': fields.Integer(required=False),
        
        'signature': fields.Integer(required=False),
        'timestamp': fields.DateTime(required=False)
    })