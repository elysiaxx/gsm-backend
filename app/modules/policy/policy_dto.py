from flask_restx import Namespace, fields
from datetime import datetime

from app.modules.common.dto import Dto
from .header.header import Header
from .options.general.general import General

from .options.detection.detection import Detection
from .options.non_detection.non_detection import NonDetection
from .options.post_detection.post_detection import PostDetection


class PolicyDto(Dto):
    name = 'policy'
    api = Namespace(name)
    header_request = api.model('header_request', Header.request)
    header_response = api.model('header_response', Header.response)

    general_request = api.model('general_request', General.request)
    general_response = api.model('general_response', General.response)

    detection = Detection(api)
    non_detection = NonDetection(api)
    post_detection = PostDetection(api)

    model_request = api.model('policy_request', {
        "header": fields.Nested(header_request),
        "general": fields.Nested(general_request),

        "detection": fields.Nested(detection.request),
        "non_detection": fields.Nested(non_detection.request),
        "post_detection": fields.Nested(post_detection.request)
    })

    model_response = api.model('policy_response', {
        "header": fields.Nested(header_response),
        "general": fields.Nested(general_response),

        "detection": fields.Nested(detection.response),
        "non_detection": fields.Nested(non_detection.response),
        "post_detection": fields.Nested(post_detection.response)
    })
    
    model_file_request = api.model('file_request', {
        "file_name": fields.String(required=False),
        "file_type": fields.String(required=False),
        "file_status": fields.Boolean(required=False),
    })
    
    model_file_response = api.model('file_response', {
        "id": fields.Integer(required=False),
        "file_name": fields.String(required=False),
        "file_type": fields.String(required=False),
        
        "file_status": fields.Boolean(required=False),
        "last_index": fields.Integer(required=False),
        "created_by": fields.String(required=False),
        
        "updated_by": fields.String(required=False),
        "created_at": fields.DateTime(required=False),
        "updated_at": fields.DateTime(required=False)
    })
    
    model_rule_request = api.model('rule_request', {
        "raw_text": fields.String(required=False),
        "rule_status": fields.Boolean(required=False),
        "file_id": fields.Integer(required=False)
    })

    model_rule_response = api.model('rule_response', {
        "id": fields.Integer(required=False),
        "raw_text": fields.String(required=False),
        "rule_index": fields.Integer(required=False),
        
        "rule_status": fields.Boolean(required=False),
        "file_id": fields.Integer(required=False),
        "created_by": fields.String(required=False),
        
        "updated_by": fields.String(required=False),
        "created_at": fields.DateTime(required=False),
        "updated_at": fields.DateTime(required=False)
    })
    
    recent_update = api.model('recent_update', {
        'time': fields.DateTime(required=False)
    })