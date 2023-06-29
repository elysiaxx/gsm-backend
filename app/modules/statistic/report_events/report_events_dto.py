import socket
import struct
from time import timezone

from flask_restx import Namespace, fields
from sqlalchemy.sql.expression import false
from app.modules.common.dto import Dto

from utils.protocol import PROTOCOLS


class IPItem(fields.Raw):

    def format(self, value):
        return socket.inet_ntoa(struct.pack("!L", value))


class PROTOItem(fields.Raw):

    def format(self, value):
        return PROTOCOLS[str(value)] if str(value) in PROTOCOLS else "UNKNOWN"


class PriorityItem(fields.Raw):

    def format(self, value):
        if value == 0:
            return "very low"
        elif value == 1:
            return "low"
        elif value == 2:
            return "medium"
        elif value == 3:
            return "high"
        else:
            return "unknown"


class ReportEventsDto(Dto):
    name = 'report_events'
    api = Namespace(name)
    model_request = api.model('report_events_request', {
        'sid': fields.Integer(required=False),
        'cid': fields.Integer(required=False),
        'signature': fields.Integer(required=False),

        'sig_name': fields.String(required=False,default=''),
        'sig_class_id': fields.Integer(required=False),
        'sig_priority': fields.Integer(required=False),

        'timestamp': fields.DateTime(required=False),
        'ip_src': fields.Integer(required=False),
        'ip_dst': fields.Integer(required=False),
        'ip_proto': PROTOItem(required=False),

        'layer4_sport': fields.Integer(required=False),
        'layer4_dport': fields.Integer(required=False),
        'cnc_server': fields.Integer(required=False),
        'security_level': fields.Integer(required=False),
        'id_country': fields.Integer(required=False)
    })

    model_response = api.model('report_events_response', {
        'sid': fields.Integer(required=False),
        'cid': fields.Integer(required=False),
        'signature': fields.Integer(required=False),

        'sig_name': fields.String(required=False,default=''),
        'sig_class_id': fields.Integer(required=False),
        'sig_priority': fields.Integer(required=False),

        'timestamp': fields.DateTime(required=False),
        'ip_src': fields.Integer(required=False),
        'ip_dst': fields.Integer(required=False),
        'ip_proto': PROTOItem(required=False),

        'layer4_sport': fields.Integer(required=False),
        'layer4_dport': fields.Integer(required=False),
        'cnc_server': fields.Integer(required=False),
        'security_level': fields.Integer(required=False),
        'id_country': fields.Integer(required=False),
        'country': fields.String(require=False)
    })

    model_last_alert = api.model('last_alert',{
        'sig_name': fields.String(requird=False),
        'ip_src': IPItem(required=False),
        'ip_dst': IPItem(required=False),

        'layer4_sport': fields.Integer(required=False),
        'layer4_dport': fields.Integer(required=False),
        'timestamp': fields.String(required=False),
        'ip_proto': PROTOItem(required=False)
    })

    model_info_alert_response = api.model('info_alert_reponse', {
        'sid': fields.Integer(required=False),
        'cid': fields.Integer(required=False),
        
        'sig_name': fields.String(required=False),
        'timestamp': fields.DateTime(required=False),
        'ip_src': IPItem(required=False),

        'ip_dst': IPItem(required=False),
        'layer4_sport': fields.Integer(required=False),
        'layer4_dport': fields.Integer(required=False),
        'ip_proto': PROTOItem(required=False)
    })

    model_statis_ip_src = api.model('statistic_ip_src', {
        'ip_src': IPItem(required=False),
        'sensor': fields.Integer(required=False),

        'total': fields.Integer(required=False),
        'unique_alerts': fields.Integer(required=False),
        'ip_dst': fields.Integer(required=False)
    })

    model_statis_ip_dst = api.model('statistic_ip_dst', {
        'ip_dst': IPItem(required=False),
        'sensor': fields.Integer(required=False),
        
        'total': fields.Integer(required=False),
        'unique_alerts': fields.Integer(required=False),
        'ip_src': fields.Integer(required=False)
    })

    model_statis_port = api.model('statistic_port', {
        'port': fields.Integer(required=False),
        'sensor': fields.Integer(required=False),
        'occurrences': fields.Integer(required=False),
        'unique_alerts': fields.Integer(required=False),

        'src_addr': fields.Integer(required=False),
        'dst_addr': fields.Integer(required=False),
        'first': fields.DateTime(required=False),
        'last': fields.DateTime(required=False)
    })

    model_statistic_alerts = api.model('statistic_alert', {
        'sid': fields.Integer(required=False),
        'cid': fields.Integer(required=False),
        'signature_name': fields.String(required=False),
        
        'timestamp': fields.DateTime(required=False),
        'src_addr': IPItem(required=False),
        'dst_addr': IPItem(required=False),
        'layer4_protocol': PROTOItem(required=False)
    })

    model_threats_intelligent_table = api.model('threat_intelligent_table', {
        'time': fields.DateTime(required=False),
        'priority': PriorityItem(required=False),
        'threat_class': fields.String(required=False),
        'threat': fields.String(required=False),

        'ip_src': IPItem(required=False),
        'sport': fields.Integer(required=False),
        'ip_dst': IPItem(required=False),
        'dport': fields.Integer(required=False),
        "country": fields.String(required=False)
    })

    model_top_by_ip = api.model('top_by_ip', {
        'ip': IPItem(required=False),
        'amount': fields.Integer(required=False)
    })

    model_top_by_priority = api.model('top_by_priority', {
        'priority': PriorityItem(required=False),
        'amount': fields.Integer(required=False)
    })

    model_top_by_protocol = api.model('top_by_protocol', {
        'protocol': PROTOItem(required=False),
        'amount': fields.Integer(required=False)
    })
    
    get_by_ip = api.model('get_by_ip', {
        'ip': fields.String(required=True),
        'page': fields.Integer(required=False),
        
        'pageSize': fields.Integer(required=False),
        'first': fields.DateTime(required=False),
        'last': fields.DateTime(required=False),
        
        'priority': fields.String(required=False),
        'sport': fields.Integer(required=False),
        'dport': fields.Integer(required=False),
        
        'group': fields.String(required=False),
        'name': fields.String(required=False),
        'country': fields.String(required=False)
    })