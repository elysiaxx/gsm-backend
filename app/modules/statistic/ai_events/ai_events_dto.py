import struct
import socket
from flask_restx import Namespace, fields

from app.modules.common.dto import Dto

from utils.protocol import PROTOCOLS


class IPItem(fields.Raw):

    def format(self, value):
        return socket.inet_ntoa(struct.pack("!L", value))

class PROTOItem(fields.Raw):

    def format(self, value):
        return PROTOCOLS[str(value)] if str(value) in PROTOCOLS else "UNKNOWN"

class DateTimeItem(fields.Raw):
    def format(self, value):
        print(str(value))
        return str(value)

class AIEventsDto(Dto):
    name = 'ai_events'
    api = Namespace(name)
    model_request = api.model('ai_events_request', {
        
    })
    
    model_response = api.model('ai_events_response', {
        'time': fields.DateTime(required=False),
        'src_ip': IPItem(required=False),
        
        'src_port': fields.Integer(required=False),
        'dst_ip': IPItem(required=False),
        'dst_port': fields.Integer(required=False),
        
        'protocol': PROTOItem(required=False),
        'flow_duration': fields.Integer(required=False),
        'attack_type': fields.String(required=False)
    })
    
    count_by_attack = api.model('count_by_attack', {
        'name': fields.String(required=False),
        'count': fields.Integer(required=False)
    })
    
    attacks = api.model('attacks_response', {
        'name': fields.String(required=False),
        'description': fields.String(required=False)
    })
    
    model_top_by_ip = api.model('top_by_ip', {
        'ip': IPItem(required=False),
        'amount': fields.Integer(required=False)
    })
    
    model_top_by_port = api.model('top_by_port', {
        'port': fields.String(required=False),
        'amount': fields.Integer(required=False)
    })
    
    model_top_by_proto = api.model('top_by_proto', {
        'protocol': PROTOItem(required=False),
        'amount': fields.Integer(required=False)
    })
    