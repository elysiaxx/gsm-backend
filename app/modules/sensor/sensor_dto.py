from xmlrpc.client import boolean
from flask_restx import Namespace, fields

from app.modules.common.dto import Dto
from app.modules.statistic.event.event_dto import EventDto


class SensorDto(Dto):
    name = 'sensor'
    api = Namespace(name)
    model_request = api.model('sensor_request', {
        'hostname': fields.String(required=False,default=''),
        'interface': fields.String(required=False,default=''),
        'filter': fields.String(required=False,default=''),

        'detail': fields.Integer(required=False),
        'encoding': fields.Integer(required=False),
        'last_cid': fields.Integer(required=False)
    })

    model_event = api.model('Event', {
        'sid': fields.Integer(required=False),
        'cid': fields.Integer(required=True),

        'signature': fields.Integer(required=False),
        'timestamp': fields.DateTime(required=False)
    })

    model_response = api.model('sensor_response',{
        'sid': fields.Integer(readonly=True),
        'hostname': fields.String(required=False),

        'interface': fields.String(required=False),
        'filter': fields.String(required=False),
        'detail': fields.Integer(required=False),

        'encoding': fields.Integer(required=False),
        'last_cid': fields.Integer(required=False),
        'events': fields.List(fields.Nested(model_event))
    })

    model_statistic_sensor = api.model('statistic_sensor', {
        'sensor': fields.Integer(required=False),
        'hostname': fields.String(required=False),

        'interface': fields.String(required=False),
        'total_events': fields.Integer(required=False),
        'unique_events': fields.Integer(required=False),
        
        'src_addr': fields.Integer(required=False),
        'dst_addr': fields.Integer(required=False),
        'first': fields.DateTime(required=False),
        'last': fields.DateTime(required=False)
    })
    
    model_sensor_request = api.model('sensor_info_request', {
        'interface': fields.String(required=False),
        'name': fields.String(required=False),
        
        'description': fields.String(required=False),
        'address': fields.String(require=True),
        'home_net': fields.String(required=False)
    })
    
    model_sensor_update = api.model('sensor_update_request', {
        'name': fields.String(required=False),
        'description': fields.String(required=False),
        'address': fields.String(required=False),
        'home_net': fields.String(required=False)
    })
    
    model_sensor_response = api.model('sensor_info_response', {
        'id': fields.Integer(required=False),
        'interface': fields.String(required=False),
        'name': fields.String(required=False),
        'description': fields.String(required=False),
        
        'sensor_status': fields.String(required=False),
        'address': fields.String(required=False),
        'home_net': fields.String(required=False),
        
        'log_dir': fields.String(required=False),
        'config_dir': fields.String(required=False),
        'created_by': fields.String(required=False),
        
        'updated_by': fields.String(required=False),
        'created_at': fields.DateTime(required=False),
        'updated_at': fields.DateTime(required=False)
    })