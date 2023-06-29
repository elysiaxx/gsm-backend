from flask_restx import fields, Namespace

from app.modules.common.dto import Dto


class AutomationDto(Dto):
    name = 'automation'
    api = Namespace(name)
    model_action_request = api.model('action_request', {
        'action_name': fields.String(required=False),
        'description': fields.String(required=False),
        'action_filter': fields.String(required=False),
        
        'minimum_events': fields.Integer(required=False, min=1),
        'during_time': fields.Integer(required=False, min=1),
        'email_notification': fields.String(required=False),
    })
    
    model_action_response = api.model('action_response', {
        'id': fields.Integer(required=False),
        'action_name': fields.String(required=False),
        'description': fields.String(required=False),
        
        'minimum_events': fields.Integer(required=False),
        'during_time': fields.Integer(required=False),
        'email_notification': fields.String(required=False),
        
        'action_filter': fields.String(required=False),
        'created_by': fields.String(required=False),
        'updated_at': fields.String(required=False),
        
        'created_at': fields.DateTime(required=False),
        'updated_at': fields.DateTime(required=False),
        'deleted_at': fields.DateTime(required=False)
    })
    
    model_sender = api.model('model_sender', {
        'email': fields.String(required=False),
        'password': fields.String(required=False)
    })
    
    model_send_test_request = api.model('send_test_request', {
        'email': fields.String(required=False),
        'password': fields.String(required=False),
        'recipient': fields.String(required=False)
    })