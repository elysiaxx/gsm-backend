from flask_restx import fields, Namespace
from datetime import datetime
import socket
import struct

from app.modules.common.dto import Dto
from utils.protocol import PROTOCOLS


class ProtoItem(fields.Raw):
    def format(self, value):
        return PROTOCOLS[str(value)] if PROTOCOLS[str(value)] else "UNKNOWN"
    
class TimeItem(fields.Raw):
    def format(self, value):
        tmp = datetime.strptime(value, "%Y/%m/%d %H:%M:%S")
        return int(tmp.timestamp())

class MonitorDto(Dto):
    name = 'monitor'
    api = Namespace(name)
    
    model_request = api.model('monitor_request', {
        
    })
    
    model_response = api.model('monitor_response', {
        "src_ip": fields.String(required=False),
        "src_port": fields.String(required=False),
        
        "dst_ip": fields.String(required=False),
        "dst_port": fields.String(required=False),
        "protocol": ProtoItem(required=False),
        
        "timestamp": fields.String(required=False),
        "flow_duration": fields.String(required=False),
        "tot_fwd_pkts": fields.String(required=False),
        "tot_bwd_pkts": fields.String(required=False),
        
        "totlen_fwd_pkts": fields.String(required=False),
        "totlen_bwd_pkts": fields.String(required=False),
        "fwd_iat_tot": fields.String(required=False),
        
        "bwd_iat_tot": fields.String(required=False),
        "fwd_header_len": fields.String(required=False),
        "bwd_header_len": fields.String(required=False),
        "fwd_pkts_s": fields.String(required=False),
        
        "bwd_pkts_s": fields.String(required=False),
        "flow_pkts_s": fields.String(required=False),
        "flow_byts_s": fields.String(required=False),
        
        "down_up_ratio": fields.String(required=False),
        "init_fwd_win_byts": fields.String(required=False),
        "init_bwd_win_byts": fields.String(required=False)
    })
    
    packets_protocol = api.model('packets_protocol', {
        'protocol': ProtoItem(),
        'count': fields.Integer(required=False)
    })
    
    flow_duration = api.model('flow_duration', {
        'flow_duration': fields.Integer(required=False),
        "timestamp": TimeItem(),
    })
    
    packets_per_second = api.model('packets_per_second', {
        'fwd_pkts_s': fields.Float(required=False),
        'bwd_pkts_s': fields.Float(required=False),
        "timestamp": TimeItem()
    })
    
    download_upload_ratio = api.model('download_upload_ratio', {
        'down_up_ratio': fields.Float(required=False),
        "timestamp": TimeItem()
    })
    
    flow_pkts_byts = api.model('flow_pkts_byts', {
        "flow_pkts_s": fields.Float(required=False),
        "flow_byts_s": fields.Float(required=False),
        "timestamp": TimeItem()
    })
    
    total_packets = api.model('total_packets', {
        "tot_fwd_pkts": fields.Integer(required=False),
        "tot_bwd_pkts": fields.Integer(required=False),
        "timestamp": TimeItem()
    })
    
    total_size_packet = api.model('total_size_packet', {
        "totlen_fwd_pkts": fields.Float(required=False),
        "totlen_bwd_pkts": fields.Float(required=False),
        "timestamp": TimeItem()
    })